/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/**
 * Copyright (c) 2017-2020, Regents of the University of California.
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
#include "protocol-detail/info.hpp"
#include "protocol-detail/probe.hpp"
#include "protocol-detail/new.hpp"
#include "protocol-detail/challenge.hpp"
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

ClientModule::~ClientModule()
{
  endSession();
}

shared_ptr<Interest>
ClientModule::generateInfoInterest(const Name& caName)
{
  Name interestName = caName;
  if (readString(caName.at(-1)) != "CA")
    interestName.append("CA");
  interestName.append("INFO");
  auto interest = make_shared<Interest>(interestName);
  interest->setMustBeFresh(true);
  interest->setCanBePrefix(false);
  return interest;
}

bool
ClientModule::verifyInfoResponse(const Data& reply)
{
  // parse the ca item
  auto caItem = INFO::decodeClientConfigFromContent(reply.getContent());

  // verify the probe Data's sig
  if (!security::verifySignature(reply, caItem.m_anchor)) {
    _LOG_ERROR("Cannot verify data signature from " << m_ca.m_caPrefix.toUri());
    return false;
  }
  return true;
}

void
ClientModule::addCaFromInfoResponse(const Data& reply)
{
  const Block& contentBlock = reply.getContent();

  // parse the ca item
  auto caItem = INFO::decodeClientConfigFromContent(contentBlock);

  // update the local config
  bool findItem = false;
  for (auto& item : m_config.m_caItems) {
    if (item.m_caPrefix == caItem.m_caPrefix) {
      findItem = true;
      item = caItem;
    }
  }
  if (!findItem) {
    m_config.m_caItems.push_back(caItem);
  }
}

shared_ptr<Interest>
ClientModule::generateProbeInterest(const ClientCaItem& ca, const std::string& probeInfo)
{
  Name interestName = ca.m_caPrefix;
  interestName.append("CA").append("PROBE");
  auto interest = make_shared<Interest>(interestName);
  interest->setMustBeFresh(true);
  interest->setCanBePrefix(false);
  interest->setApplicationParameters(
    PROBE::encodeApplicationParametersFromProbeInfo(ca, probeInfo)
  );

  // update local state
  m_ca = ca;
  return interest;
}

void
ClientModule::onProbeResponse(const Data& reply)
{
  if (!security::verifySignature(reply, m_ca.m_anchor)) {
    _LOG_ERROR("Cannot verify data signature from " << m_ca.m_caPrefix.toUri());
    return;
  }

  auto contentTLV = reply.getContent();
  contentTLV.parse();

  // read the available name and put it into the state
  if (contentTLV.get(tlv_probe_response).hasValue()) {
    Block probeResponseBlock = contentTLV.get(tlv_probe_response);
    probeResponseBlock.parse();
    m_identityName.wireDecode(probeResponseBlock.get(tlv::Name));
  }
  else {
    NDN_LOG_TRACE("The JSON_CA_NAME is empty.");
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
      if (caItem.m_caPrefix.isPrefixOf(identityName)) {
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
      NDN_LOG_TRACE("Randomly create a new name because m_identityName is empty and the param is empty.");
      auto id = std::to_string(random::generateSecureWord64());
      m_identityName = m_ca.m_caPrefix;
      m_identityName.append(id);
    }
  }

  // generate a newly key pair or use an existing key
  const auto& pib = m_keyChain.getPib();
  security::pib::Identity identity;
  try {
    identity = pib.getIdentity(m_identityName);
  }
  catch (const security::Pib::Error& e) {
    identity = m_keyChain.createIdentity(m_identityName);
    m_isNewlyCreatedIdentity = true;
    m_isNewlyCreatedKey = true;
  }
  try {
    m_key = identity.getDefaultKey();
  }
  catch (const security::Pib::Error& e) {
    m_key = m_keyChain.createKey(identity);
    m_isNewlyCreatedKey = true;
  }

  // generate certificate request
  security::v2::Certificate certRequest;
  certRequest.setName(Name(m_key.getName()).append("cert-request").appendVersion());
  certRequest.setContentType(tlv::ContentType_Key);
  certRequest.setContent(m_key.getPublicKey().data(), m_key.getPublicKey().size());
  SignatureInfo signatureInfo;
  signatureInfo.setValidityPeriod(security::ValidityPeriod(notBefore, notAfter));
  m_keyChain.sign(certRequest, signingByKey(m_key.getName()).setSignatureInfo(signatureInfo));

  // generate Interest packet
  Name interestName = m_ca.m_caPrefix;
  interestName.append("CA").append("NEW");
  auto interest = make_shared<Interest>(interestName);
  interest->setMustBeFresh(true);
  interest->setCanBePrefix(false);
  interest->setApplicationParameters(
    NEW::encodeApplicationParameters(m_ecdh.getBase64PubKey(), certRequest, probeToken)
  );

  // sign the Interest packet
  m_keyChain.sign(*interest, signingByKey(m_key.getName()));
  return interest;
}

std::list<std::string>
ClientModule::onNewResponse(const Data& reply)
{
  if (!security::verifySignature(reply, m_ca.m_anchor)) {
    _LOG_ERROR("Cannot verify data signature from " << m_ca.m_caPrefix.toUri());
    return std::list<std::string>();
  }
  auto contentTLV = reply.getContent();
  contentTLV.parse();

  // ECDH
  const auto& peerKeyBase64Str = readString(contentTLV.get(tlv_ecdh_pub));  
  const auto& saltStr = readString(contentTLV.get(tlv_salt));
  uint64_t saltInt = std::stoull(saltStr);
  m_ecdh.deriveSecret(peerKeyBase64Str);

  // HKDF
  hkdf(m_ecdh.context->sharedSecret, m_ecdh.context->sharedSecretLen,
       (uint8_t*)&saltInt, sizeof(saltInt), m_aesKey, sizeof(m_aesKey));

  // update state
  m_status = readNonNegativeInteger(contentTLV.get(tlv_status));
  m_requestId = readString(contentTLV.get(tlv_request_id));
  m_challengeList.clear();
  for (auto const& element : contentTLV.elements()) {
    if (element.type() == tlv_challenge) {
      m_challengeList.push_back(readString(element));
    }
  }
  return m_challengeList;
}

shared_ptr<Interest>
ClientModule::generateChallengeInterest(const Block& challengeRequest)
{
  challengeRequest.parse();
  m_challengeType = readString(challengeRequest.get(tlv_selected_challenge));

  Name interestName = m_ca.m_caPrefix;
  interestName.append("CA").append("CHALLENGE").append(m_requestId);
  auto interest = make_shared<Interest>(interestName);
  interest->setMustBeFresh(true);
  interest->setCanBePrefix(false);

  // encrypt the Interest parameters
  auto paramBlock = encodeBlockWithAesGcm128(tlv::ApplicationParameters, m_aesKey,
                                             challengeRequest.value(), challengeRequest.value_size(), (const uint8_t*)"test", strlen("test"));
  interest->setApplicationParameters(paramBlock);

  m_keyChain.sign(*interest, signingByKey(m_key.getName()));
  return interest;
}

void
ClientModule::onChallengeResponse(const Data& reply)
{
  if (!security::verifySignature(reply, m_ca.m_anchor)) {
    _LOG_ERROR("Cannot verify data signature from " << m_ca.m_caPrefix.toUri());
    return;
  }
  auto result = decodeBlockWithAesGcm128(reply.getContent(), m_aesKey, (const uint8_t*)"test", strlen("test"));

  Block contentTLV = makeBinaryBlock(tlv_encrypted_payload, result.data(), result.size());
  contentTLV.parse();

  // update state
  m_status = readNonNegativeInteger(contentTLV.get(tlv_status));
  m_challengeStatus = readString(contentTLV.get(tlv_challenge_status));
  m_remainingTries = readNonNegativeInteger(contentTLV.get(tlv_remaining_tries));
  m_freshBefore = time::system_clock::now() +
                  time::seconds(readNonNegativeInteger(contentTLV.get(tlv_remaining_time)));

  if (contentTLV.find(tlv_issued_cert_name) != contentTLV.elements_end()) {
    Block issuedCertNameBlock = contentTLV.get(tlv_issued_cert_name);
    issuedCertNameBlock.parse();
    m_issuedCertName.wireDecode(issuedCertNameBlock.get(tlv::Name));
  }
}

shared_ptr<Interest>
ClientModule::generateDownloadInterest()
{
  Name interestName = m_ca.m_caPrefix;
  interestName.append("CA").append("DOWNLOAD").append(m_requestId);
  auto interest = make_shared<Interest>(interestName);
  interest->setMustBeFresh(true);
  interest->setCanBePrefix(false);
  return interest;
}

shared_ptr<Interest>
ClientModule::generateCertFetchInterest()
{
  Name interestName = m_issuedCertName;
  auto interest = make_shared<Interest>(interestName);
  interest->setMustBeFresh(true);
  interest->setCanBePrefix(false);
  return interest;
}

void
ClientModule::onCertFetchResponse(const Data& reply)
{
  try {
    security::v2::Certificate cert(reply.getContent().blockFromValue());
    m_keyChain.addCertificate(m_key, cert);
    _LOG_TRACE("Fetched and installed the cert " << cert.getName());
  }
  catch (const std::exception& e) {
    _LOG_ERROR("Cannot add replied certificate into the keychain " << e.what());
    return;
  }
}

void
ClientModule::endSession()
{
  if (getApplicationStatus() == STATUS_SUCCESS || getApplicationStatus() == STATUS_ENDED) {
    return;
  }
  if (m_isNewlyCreatedIdentity) {
    // put the identity into the if scope is because it may cause an error
    // outside since when endSession is called, identity may not have been created yet.
    auto identity = m_keyChain.getPib().getIdentity(m_identityName);
    m_keyChain.deleteIdentity(identity);
  }
  else if (m_isNewlyCreatedKey) {
    auto identity = m_keyChain.getPib().getIdentity(m_identityName);
    m_keyChain.deleteKey(identity, m_key);
  }
  m_status = STATUS_ENDED;
}


std::vector<std::string>
ClientModule::parseProbeComponents(const std::string& probe)
{
  std::vector<std::string> components;
  std::string delimiter = ":";
  size_t last = 0;
  size_t next = 0;
  while ((next = probe.find(delimiter, last)) != std::string::npos) {
    components.push_back(probe.substr(last, next - last));
    last = next + 1;
  }
  components.push_back(probe.substr(last));
  return components;
}

} // namespace ndncert
} // namespace ndn
