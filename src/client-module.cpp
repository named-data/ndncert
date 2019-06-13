/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/**
 * Copyright (c) 2017-2019, Regents of the University of California.
 *
 * This file is part of ndncert, a certificate management system based on NDN.
 *
 * ndncert is free software: you can redistribute it and/or modify it under the terms
 * of the GNU General Public License as published by the Free Software Foundation, either
 * version 3 of the License, or (at your option) any later version.
 *
 * ndncert is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
 * PARTICULAR PURPOSE.  See the GNU General Public License for more details.
 *
 * You should have received copies of the GNU General Public License along with
 * ndncert, e.g., in COPYING.md file.  If not, see <http://www.gnu.org/licenses/>.
 *
 * See AUTHORS.md for complete list of ndncert authors and contributors.
 */

#include "client-module.hpp"
#include "logging.hpp"
#include "challenge-module.hpp"
#include "crypto-support/enc-tlv.hpp"
#include <ndn-cxx/util/io.hpp>
#include <ndn-cxx/security/signing-helpers.hpp>
#include <ndn-cxx/security/verification-helpers.hpp>
#include <ndn-cxx/util/random.hpp>
#include <ndn-cxx/security/transform/base64-encode.hpp>
#include <ndn-cxx/security/transform/buffer-source.hpp>
#include <ndn-cxx/security/transform/stream-sink.hpp>

namespace ndn {
namespace ndncert {

_LOG_INIT(ndncert.client);

ClientModule::ClientModule(security::v2::KeyChain& keyChain)
  : m_keyChain(keyChain)
{
}

ClientModule::~ClientModule() = default;

shared_ptr<Interest>
ClientModule::generateProbeInfoInterest(const Name& caName)
{
  Name interestName = caName;
  if (readString(caName.at(-1)) != "CA")
    interestName.append("CA");
  interestName.append("_PROBE").append("INFO");
  auto interest = make_shared<Interest>(interestName);
  interest->setMustBeFresh(true);
  interest->setCanBePrefix(false);
  return interest;
}

void
ClientModule::onProbeInfoResponse(const Data& reply)
{
  // parse the ca item
  auto contentJson = getJsonFromData(reply);
  auto caItem = ClientConfig::extractCaItem(contentJson);

  // update the local config
  bool findItem = false;
  for (auto& item : m_config.m_caItems) {
    if (item.m_caName == caItem.m_caName) {
      findItem = true;
      item = caItem;
    }
  }
  if (!findItem) {
    m_config.m_caItems.push_back(caItem);
  }

  // verify the probe Data's sig
  if (!security::verifySignature(reply, caItem.m_anchor)) {
    _LOG_ERROR("Cannot verify data signature from " << m_ca.m_caName.toUri());
    return;
  }
}

shared_ptr<Interest>
ClientModule::generateProbeInterest(const ClientCaItem& ca, const std::string& probeInfo)
{
  Name interestName = ca.m_caName;
  interestName.append("CA").append("_PROBE");
  auto interest = make_shared<Interest>(interestName);
  interest->setMustBeFresh(true);
  interest->setCanBePrefix(false);
  auto paramJson = genProbeRequestJson(ca, probeInfo);
  interest->setApplicationParameters(paramFromJson(paramJson));

  // update local state
  m_ca = ca;
  return interest;
}

void
ClientModule::onProbeResponse(const Data& reply)
{
  if (!security::verifySignature(reply, m_ca.m_anchor)) {
    _LOG_ERROR("Cannot verify data signature from " << m_ca.m_caName.toUri());
    return;
  }
  auto contentJson = getJsonFromData(reply);

  // read the available name and put it into the state
  auto nameUri = contentJson.get<std::string>(JSON_CA_NAME, "");
  if (nameUri != "") {
    m_identityName = Name(nameUri);
  }
}

shared_ptr<Interest>
ClientModule::generateNewInterest(const time::system_clock::TimePoint& notBefore,
                                  const time::system_clock::TimePoint& notAfter,
                                  const Name& identityName, const shared_ptr<Data>& probeToken)
{
  // Name requestedName = identityName;
  if (!identityName.empty()) { // if identityName is not empty, find the corresponding CA
    bool findCa = false;
    for (const auto& caItem : m_config.m_caItems) {
      if (caItem.m_caName.isPrefixOf(identityName)) {
        m_ca = caItem;
        findCa = true;
      }
    }
    if (!findCa) { // if cannot find, cannot proceed
      return nullptr;
    }
    m_identityName = identityName;
  }
  else { // if identityName is empty, check m_identityName or generate a random name
    if (!m_identityName.empty()) {
      // do nothing
    }
    else {
      auto id = std::to_string(random::generateSecureWord64());
      m_identityName = m_ca.m_caName;
      m_identityName.append(id);
    }
  }

  // generate a newly key pair or use an existing key
  const auto& pib = m_keyChain.getPib();
  try {
    auto identity = pib.getIdentity(m_identityName);
    m_key = m_keyChain.createKey(identity);
  }
  catch (const security::Pib::Error& e) {
    auto identity = m_keyChain.createIdentity(m_identityName);
    m_key = identity.getDefaultKey();
  }

  // generate certificate request
  security::v2::Certificate certRequest;
  certRequest.setName(Name(m_key.getName()).append("cert-request").appendVersion());
  certRequest.setContentType(tlv::ContentType_Key);
  certRequest.setFreshnessPeriod(time::hours(24));
  certRequest.setContent(m_key.getPublicKey().data(), m_key.getPublicKey().size());
  SignatureInfo signatureInfo;
  signatureInfo.setValidityPeriod(security::ValidityPeriod(notBefore, notAfter));
  m_keyChain.sign(certRequest, signingByKey(m_key.getName()).setSignatureInfo(signatureInfo));

  // generate Interest packet
  Name interestName = m_ca.m_caName;
  interestName.append("CA").append("_NEW");
  auto interest = make_shared<Interest>(interestName);
  interest->setMustBeFresh(true);
  interest->setCanBePrefix(false);
  interest->setApplicationParameters(paramFromJson(genNewRequestJson(m_ecdh.getBase64PubKey(), certRequest, probeToken)));

  // sign the Interest packet
  m_keyChain.sign(*interest, signingByKey(m_key.getName()));
  return interest;
}

std::list<std::string>
ClientModule::onNewResponse(const Data& reply)
{
  if (!security::verifySignature(reply, m_ca.m_anchor)) {
    _LOG_ERROR("Cannot verify data signature from " << m_ca.m_caName.toUri());
    return std::list<std::string>();
  }
  auto contentJson = getJsonFromData(reply);

  // ECDH
  const auto& peerKeyBase64Str = contentJson.get<std::string>(JSON_CA_ECDH, "");
  const auto& saltStr = contentJson.get<std::string>(JSON_CA_SALT, "");
  uint64_t saltInt = std::stoull(saltStr);
  uint8_t salt[sizeof(saltInt)];
  std::memcpy(salt, &saltInt, sizeof(saltInt));
  m_ecdh.deriveSecret(peerKeyBase64Str);

  // HKDF
  hkdf(m_ecdh.context->sharedSecret, m_ecdh.context->sharedSecretLen, salt, sizeof(saltInt), m_aesKey, 32);

  // update state
  m_status = contentJson.get<int>(JSON_CA_STATUS);
  m_requestId = contentJson.get<std::string>(JSON_CA_EQUEST_ID, "");

  auto challengesJson = contentJson.get_child(JSON_CA_CHALLENGES);
  m_challengeList.clear();
  for (const auto& challengeJson : challengesJson) {
    m_challengeList.push_back(challengeJson.second.get<std::string>(JSON_CA_CHALLENGE_ID, ""));
  }
  return m_challengeList;
}

shared_ptr<Interest>
ClientModule::generateChallengeInterest(const JsonSection& paramJson)
{
  m_challengeType = paramJson.get<std::string>(JSON_CLIENT_SELECTED_CHALLENGE);

  Name interestName = m_ca.m_caName;
  interestName.append("CA").append("_CHALLENGE").append(m_requestId);
  auto interest = make_shared<Interest>(interestName);
  interest->setMustBeFresh(true);
  interest->setCanBePrefix(false);

  // encrypt the Interest parameters
  std::stringstream ss;
  boost::property_tree::write_json(ss, paramJson);
  auto payload = ss.str();
  auto paramBlock = genEncBlock(tlv::ApplicationParameters, m_ecdh.context->sharedSecret, m_ecdh.context->sharedSecretLen,
                                (const uint8_t*)payload.c_str(), payload.size());
  interest->setApplicationParameters(paramBlock);

  m_keyChain.sign(*interest, signingByKey(m_key.getName()));
  return interest;
}

void
ClientModule::onChallengeResponse(const Data& reply)
{
  if (!security::verifySignature(reply, m_ca.m_anchor)) {
    _LOG_ERROR("Cannot verify data signature from " << m_ca.m_caName.toUri());
    return;
  }
  auto result = parseEncBlock(m_ecdh.context->sharedSecret, m_ecdh.context->sharedSecretLen, reply.getContent());
  std::string payload((const char*)result.data(), result.size());
  std::istringstream ss(payload);
  JsonSection contentJson;
  boost::property_tree::json_parser::read_json(ss, contentJson);

  // update state
  m_status = contentJson.get<int>(JSON_CA_STATUS);
  m_challengeStatus = contentJson.get<std::string>(JSON_CHALLENGE_STATUS);
  m_remainingTries = contentJson.get<int>(JSON_CHALLENGE_REMAINING_TRIES);
  m_freshBefore = time::system_clock::now() + time::seconds(contentJson.get<int>(JSON_CHALLENGE_REMAINING_TIME));
}

shared_ptr<Interest>
ClientModule::generateDownloadInterest()
{
  Name interestName = m_ca.m_caName;
  interestName.append("CA").append("_DOWNLOAD").append(m_requestId);
  auto interest = make_shared<Interest>(interestName);
  interest->setMustBeFresh(true);
  interest->setCanBePrefix(false);
  return interest;
}

shared_ptr<Interest>
ClientModule::generateCertFetchInterest()
{
  Name interestName = m_identityName;
  interestName.append("KEY").append(m_certId);
  auto interest = make_shared<Interest>(interestName);
  interest->setMustBeFresh(true);
  interest->setCanBePrefix(false);
  return interest;
}

void
ClientModule::onDownloadResponse(const Data& reply)
{
  try {
    security::v2::Certificate cert(reply.getContent().blockFromValue());
    m_keyChain.addCertificate(m_key, cert);
    _LOG_TRACE("Got DOWNLOAD response and installed the cert " << cert.getName());
  }
  catch (const std::exception& e) {
    _LOG_ERROR("Cannot add replied certificate into the keychain " << e.what());
    return;
  }
  m_isCertInstalled = true;
}

void
ClientModule::onCertFetchResponse(const Data& reply)
{
  onDownloadResponse(reply);
}

JsonSection
ClientModule::getJsonFromData(const Data& data)
{
  std::istringstream ss(encoding::readString(data.getContent()));
  JsonSection json;
  boost::property_tree::json_parser::read_json(ss, json);
  return json;
}

const JsonSection
ClientModule::genProbeRequestJson(const ClientCaItem& ca, const std::string& probeInfo)
{
  std::string delimiter = ":";
  size_t last = 0;
  size_t next = 0;

  JsonSection root;

  std::vector<std::string> fields;
  while ((next = ca.m_probe.find(delimiter, last)) != std::string::npos) {
    fields.push_back(ca.m_probe.substr(last, next - last));
    last = next + 1;
  }
  fields.push_back(ca.m_probe.substr(last));

  std::vector<std::string> arguments;
  last = 0;
  next = 0;
  while ((next = probeInfo.find(delimiter, last)) != std::string::npos) {
    arguments.push_back(probeInfo.substr(last, next - last));
    last = next + 1;
  }
  arguments.push_back(probeInfo.substr(last));

  if (arguments.size() != fields.size()) {
    BOOST_THROW_EXCEPTION(Error("Error in genProbeRequestJson: argument list does not match field list in the config file."));
  }

  for (size_t i = 0; i < fields.size(); ++i) {
      root.put(fields.at(i), arguments.at(i));
  }

  return root;
}

const JsonSection
ClientModule::genNewRequestJson(const std::string& ecdhPub, const security::v2::Certificate& certRequest,
                                const shared_ptr<Data>& probeToken)
{
  JsonSection root;
  std::stringstream ss;
  try {
    security::transform::bufferSource(certRequest.wireEncode().wire(), certRequest.wireEncode().size())
    >> security::transform::base64Encode(true)
    >> security::transform::streamSink(ss);
  }
  catch (const security::transform::Error& e) {
    _LOG_ERROR("Cannot convert self-signed cert into BASE64 string " << e.what());
    return root;
  }
  root.put(JSON_CLIENT_ECDH, ecdhPub);
  root.put(JSON_CLIENT_CERT_REQ, ss.str());
  if (probeToken != nullptr) {
    // clear the stringstream
    ss.str("");
    ss.clear();
    // transform the probe data into a base64 string
    try {
      security::transform::bufferSource(probeToken->wireEncode().wire(), probeToken->wireEncode().size())
      >> security::transform::base64Encode(true)
      >> security::transform::streamSink(ss);
    }
    catch (const security::transform::Error& e) {
      _LOG_ERROR("Cannot convert self-signed cert into BASE64 string " << e.what());
      return root;
    }
    // add the token into the JSON
    root.put("probe-token", ss.str());
  }
  return root;
}

Block
ClientModule::paramFromJson(const JsonSection& json)
{
  std::stringstream ss;
  boost::property_tree::write_json(ss, json);
  return makeStringBlock(ndn::tlv::ApplicationParameters, ss.str());
}

} // namespace ndncert
} // namespace ndn
