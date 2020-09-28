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

#include "ca-module.hpp"
#include "challenge-module.hpp"
#include "logging.hpp"
#include "crypto-support/enc-tlv.hpp"
#include "protocol-detail/info.hpp"
#include "protocol-detail/probe.hpp"
#include "protocol-detail/new.hpp"
#include "protocol-detail/challenge.hpp"
#include "protocol-detail/revoke.hpp"
#include <ndn-cxx/util/io.hpp>
#include <ndn-cxx/security/verification-helpers.hpp>
#include <ndn-cxx/security/signing-helpers.hpp>
#include <ndn-cxx/util/random.hpp>
#include <ndn-cxx/metadata-object.hpp>

namespace ndn {
namespace ndncert {

static const int IS_SUBNAME_MIN_OFFSET = 5;
static const time::seconds DEFAULT_DATA_FRESHNESS_PERIOD = 1_s;
static const time::seconds REQUEST_VALIDITY_PERIOD_NOT_BEFORE_GRACE_PERIOD = 120_s;

_LOG_INIT(ndncert.ca);

CaModule::CaModule(Face& face, security::v2::KeyChain& keyChain,
                   const std::string& configPath, const std::string& storageType)
  : m_face(face)
  , m_keyChain(keyChain)
{
  // load the config and create storage
  m_config.load(configPath);
  m_storage = CaStorage::createCaStorage(storageType);

  registerPrefix();
}

CaModule::~CaModule()
{
  for (auto handle : m_interestFilterHandles) {
    handle.cancel();
  }
  for (auto handle : m_registeredPrefixHandles) {
    handle.unregister();
  }
}

void
CaModule::registerPrefix()
{
  // register localhop discovery prefix
  Name localhopInfoPrefix("/localhop/CA/INFO");
  auto prefixId = m_face.setInterestFilter(InterestFilter(localhopInfoPrefix),
                                           bind(&CaModule::onInfo, this, _2),
                                           bind(&CaModule::onRegisterFailed, this, _2));
  m_registeredPrefixHandles.push_back(prefixId);
  _LOG_TRACE("Prefix " << localhopInfoPrefix << " got registered");

  // register prefixes
  Name prefix = m_config.m_caPrefix;
  prefix.append("CA");

  prefixId = m_face.registerPrefix(prefix,
    [&] (const Name& name) {
      // register INFO prefix
      auto filterId = m_face.setInterestFilter(Name(name).append("INFO"),
                                          bind(&CaModule::onInfo, this, _2));
      m_interestFilterHandles.push_back(filterId);

      // register PROBE prefix
      filterId = m_face.setInterestFilter(Name(name).append("PROBE"),
                                          bind(&CaModule::onProbe, this, _2));
      m_interestFilterHandles.push_back(filterId);

      // register NEW prefix
      filterId = m_face.setInterestFilter(Name(name).append("NEW"),
                                          bind(&CaModule::onNew, this, _2));
      m_interestFilterHandles.push_back(filterId);

      // register SELECT prefix
      filterId = m_face.setInterestFilter(Name(name).append("CHALLENGE"),
                                          bind(&CaModule::onChallenge, this, _2));
      m_interestFilterHandles.push_back(filterId);

      // register REVOKE prefix
      filterId = m_face.setInterestFilter(Name(name).append("REVOKE"),
                                          bind(&CaModule::onRevoke, this, _2));
      m_interestFilterHandles.push_back(filterId);
      _LOG_TRACE("Prefix " << name << " got registered");
    },
    bind(&CaModule::onRegisterFailed, this, _2));
  m_registeredPrefixHandles.push_back(prefixId);
}

void
CaModule::setNameAssignmentFunction(const NameAssignmentFunc& handler)
{
  m_config.m_nameAssignmentFunc = handler;
}

bool
CaModule::setStatusUpdateCallback(const StatusUpdateCallback& onUpdateCallback)
{
  m_config.m_statusUpdateCallback = onUpdateCallback;
  return false;
}

shared_ptr<Data>
CaModule::generateCaConfigMetaData()
{
  // @TODO
  // make metadata a class member variable m_infoMetadata
  // check whether the m_infoMetadata has the latest versioned name, if not, then generate a new one
  // otherwise, directly reply m_infoMetadata.makeData

  auto infoPacket = generateCaConfigData();
  MetadataObject metadata;
  metadata.setVersionedName(infoPacket->getName().getPrefix(-1));
  Name discoveryInterestName(infoPacket->getName().getPrefix(-2));
  name::Component metadataComponent(32, reinterpret_cast<const uint8_t*>("metadata"), std::strlen("metadata"));
  discoveryInterestName.append(metadataComponent);
  auto metadataData = metadata.makeData(discoveryInterestName, m_keyChain, signingByIdentity(m_config.m_caPrefix));
  return make_shared<Data>(metadataData);
}

shared_ptr<Data>
CaModule::generateCaConfigData()
{
  // @TODO
  // make CaInfo Data packet a class member variable m_infoData
  // check whether the m_infoData is still valid, if not, then generate a new one
  // otherwise, directly reply m_infoData

  const auto& pib = m_keyChain.getPib();
  const auto& identity = pib.getIdentity(m_config.m_caPrefix);
  const auto& cert = identity.getDefaultKey().getDefaultCertificate();
  Block contentTLV = INFO::encodeContentFromCAConfig(m_config, cert);

  Name infoPacketName(m_config.m_caPrefix);
  infoPacketName.append("CA").append("INFO").appendVersion().appendSegment(0);
  Data infoData(infoPacketName);
  infoData.setContent(contentTLV);
  infoData.setFreshnessPeriod(DEFAULT_DATA_FRESHNESS_PERIOD);
  m_keyChain.sign(infoData, signingByIdentity(m_config.m_caPrefix));
  return make_shared<Data>(infoData);
}

void
CaModule::onInfo(const Interest& request)
{
  _LOG_TRACE("Received INFO request");

  if (request.getName().get(-1).type() == 32) {
    m_face.put(*generateCaConfigMetaData());
  }
  else {
    m_face.put(*generateCaConfigData());
  }

  _LOG_TRACE("Handle INFO: send out the INFO response");
}

void
CaModule::onProbe(const Interest& request)
{
  // PROBE Naming Convention: /<CA-Prefix>/CA/PROBE/[ParametersSha256DigestComponent]
  _LOG_TRACE("Received PROBE request");

  // process PROBE requests: find an available name
  std::string availableId = "";
  const auto& parameterTLV = request.getApplicationParameters();
  parameterTLV.parse();
  if (!parameterTLV.hasValue()) {
    _LOG_ERROR("Empty TLV obtained from the Interest parameter.");
    return;
  }

  // if (m_config.m_nameAssignmentFunc) {
  //   try {
  //     availableId = m_config.m_nameAssignmentFunc(parameterTLV);
  //   }
  //   catch (const std::exception& e) {
  //     _LOG_TRACE("Cannot find PROBE input from PROBE parameters: " << e.what());
  //     return;
  //   }
  // }
  // else {
  //   // if there is no app-specified name lookup, use a random name id
  //   availableId = std::to_string(random::generateSecureWord64());
  // }
  // Name newIdentityName = m_config.m_caPrefix;
  // newIdentityName.append(availableId);
  // _LOG_TRACE("Handle PROBE: generate an identity " << newIdentityName);

  // Block contentTLV = PROBE::encodeDataContent(newIdentityName.toUri(), m_config.m_probe, parameterTLV);

  // Data result;
  // result.setName(request.getName());
  // result.setContent(contentTLV);
  // result.setFreshnessPeriod(DEFAULT_DATA_FRESHNESS_PERIOD);
  // m_keyChain.sign(result, signingByIdentity(m_config.m_caPrefix));
  // m_face.put(result);
  // _LOG_TRACE("Handle PROBE: send out the PROBE response");
}

void
CaModule::onNew(const Interest& request)
{
    // NEW Naming Convention: /<CA-prefix>/CA/NEW/[SignedInterestParameters_Digest]
    onRequestInit(request, REQUEST_TYPE_NEW);
}

void
CaModule::onRevoke(const Interest& request)
{
    // REVOKE Naming Convention: /<CA-prefix>/CA/REVOKE/[SignedInterestParameters_Digest]
    onRequestInit(request, REQUEST_TYPE_REVOKE);
}

void
CaModule::onRequestInit(const Interest& request, int requestType)
{
  // get ECDH pub key and cert request
  const auto& parameterTLV = request.getApplicationParameters();
  parameterTLV.parse();

  if (!parameterTLV.hasValue()) {
    _LOG_ERROR("Empty TLV obtained from the Interest parameter.");
    return;
  }

  std::string peerKeyBase64 = readString(parameterTLV.get(tlv_ecdh_pub));

  if (peerKeyBase64 == "") {
    _LOG_ERROR("Empty ECDH PUB obtained from the Interest parameter.");
    return;
  }

  // get server's ECDH pub key
  auto myEcdhPubKeyBase64 = m_ecdh.getBase64PubKey();
  try {
    m_ecdh.deriveSecret(peerKeyBase64);
  }
  catch (const std::exception& e) {
    _LOG_ERROR("Cannot derive a shared secret using the provided ECDH key: " << e.what());
    return;
  }
  // generate salt for HKDF
  auto saltInt = random::generateSecureWord64();
  // hkdf
  hkdf(m_ecdh.context->sharedSecret, m_ecdh.context->sharedSecretLen,
       (uint8_t*)&saltInt, sizeof(saltInt), m_aesKey, sizeof(m_aesKey));

  shared_ptr<security::v2::Certificate> clientCert = nullptr;

  if (requestType == REQUEST_TYPE_NEW) {
    // parse certificate request
    Block cert_req = parameterTLV.get(tlv_cert_request);
    cert_req.parse();

    try {
      security::v2::Certificate cert = security::v2::Certificate(cert_req.get(tlv::Data));
      clientCert = make_shared<security::v2::Certificate>(cert);
    }
    catch (const std::exception &e) {
      _LOG_ERROR("Unrecognized certificate request: " << e.what());
      return;
    }
    // check the validity period
    auto expectedPeriod = clientCert->getValidityPeriod().getPeriod();
    auto currentTime = time::system_clock::now();
    if (expectedPeriod.first < currentTime - REQUEST_VALIDITY_PERIOD_NOT_BEFORE_GRACE_PERIOD) {
      _LOG_ERROR("Client requests a too old notBefore timepoint.");
      return;
    }
    if (expectedPeriod.second > currentTime + m_config.m_maxValidityPeriod ||
      expectedPeriod.second <= expectedPeriod.first) {
      _LOG_ERROR("Client requests an invalid validity period or a notAfter timepoint beyond the allowed time period.");
      return;
    }

    // verify the self-signed certificate, the request, and the token
    if (!m_config.m_caPrefix.isPrefixOf(clientCert->getName()) // under ca prefix
        || !security::v2::Certificate::isValidName(clientCert->getName()) // is valid cert name
        || clientCert->getName().size() < m_config.m_caPrefix.size() + IS_SUBNAME_MIN_OFFSET) {
      _LOG_ERROR("Invalid self-signed certificate name " << clientCert->getName());
      return;
    }
    if (!security::verifySignature(*clientCert, *clientCert)) {
      _LOG_ERROR("Cert request with bad signature.");
      return;
    }
    if (!security::verifySignature(request, *clientCert)) {
      _LOG_ERROR("Interest with bad signature.");
      return;
    }
  } else if (requestType == REQUEST_TYPE_REVOKE) {
    // parse certificate request
    Block cert_revoke = parameterTLV.get(tlv_cert_to_revoke);
    cert_revoke.parse();

    try {
      security::v2::Certificate cert = security::v2::Certificate(cert_revoke.get(tlv::Data));
      clientCert = make_shared<security::v2::Certificate>(cert);
    }
    catch (const std::exception &e) {
      _LOG_ERROR("Unrecognized certificate: " << e.what());
      return;
    }

    // verify the certificate
    if (!m_config.m_caPrefix.isPrefixOf(clientCert->getName()) // under ca prefix
        || !security::v2::Certificate::isValidName(clientCert->getName()) // is valid cert name
        || clientCert->getName().size() < m_config.m_caPrefix.size() + IS_SUBNAME_MIN_OFFSET) {
      _LOG_ERROR("Invalid certificate name " << clientCert->getName());
      return;
    }
    const auto& cert = m_keyChain.getPib().getIdentity(m_config.m_caPrefix).getDefaultKey().getDefaultCertificate();
    if (!security::verifySignature(*clientCert, cert)) {
      _LOG_ERROR("Cert request with bad signature.");
      return;
    }
  }

  // create new request instance
  std::string requestId = std::to_string(random::generateWord64());
  CertificateRequest certRequest(m_config.m_caPrefix, requestId, requestType, Status::BEFORE_CHALLENGE, *clientCert);

  try {
    m_storage->addRequest(certRequest);
  }
  catch (const std::exception& e) {
    _LOG_ERROR("Cannot add new request instance into the storage: " << e.what());
    return;
  }

  Data result;
  result.setName(request.getName());
  result.setFreshnessPeriod(DEFAULT_DATA_FRESHNESS_PERIOD);
  if (requestType == REQUEST_TYPE_NEW) {
    result.setContent(NEW::encodeDataContent(myEcdhPubKeyBase64,
                                               std::to_string(saltInt),
                                               certRequest,
                                               m_config.m_supportedChallenges));
  } else if (requestType == REQUEST_TYPE_REVOKE) {
    result.setContent(REVOKE::encodeDataContent(myEcdhPubKeyBase64,
                                                std::to_string(saltInt),
                                                certRequest,
                                                m_config.m_supportedChallenges));
  }
  m_keyChain.sign(result, signingByIdentity(m_config.m_caPrefix));
  m_face.put(result);

  if (m_config.m_statusUpdateCallback) {
    m_config.m_statusUpdateCallback(certRequest);
  }
}

void
CaModule::onChallenge(const Interest& request)
{
  // get certificate request state
  CertificateRequest certRequest = getCertificateRequest(request);
  if (certRequest.m_requestId == "") {
    // cannot get the request state
    _LOG_ERROR("Cannot find certificate request state from CA's storage.");
    return;
  }
  // verify signature
  if (!security::verifySignature(request, certRequest.m_cert)) {
    _LOG_ERROR("Challenge Interest with bad signature.");
    return;
  }
  // decrypt the parameters
  Buffer paramTLVPayload;
  try {
    paramTLVPayload = decodeBlockWithAesGcm128(request.getApplicationParameters(), m_aesKey,
                                                (uint8_t*)"test", strlen("test"));
  }
  catch (const std::exception& e) {
    _LOG_ERROR("Cannot successfully decrypt the Interest parameters: " << e.what());
    return;
  }
  if (paramTLVPayload.size() == 0) {
    _LOG_ERROR("Got an empty buffer from content decryption.");
    return;
  }

  Block paramTLV = makeBinaryBlock(tlv_encrypted_payload, paramTLVPayload.data(), paramTLVPayload.size());
  paramTLV.parse();

  // load the corresponding challenge module
  std::string challengeType = readString(paramTLV.get(tlv_selected_challenge));
  auto challenge = ChallengeModule::createChallengeModule(challengeType);

  Block payload;

  if (challenge == nullptr) {
    _LOG_TRACE("Unrecognized challenge type " << challengeType);
    certRequest.m_status = Status::FAILURE;
    certRequest.m_challengeStatus = CHALLENGE_STATUS_UNKNOWN_CHALLENGE;
    payload = CHALLENGE::encodeDataPayload(certRequest);
  }
  else {
    _LOG_TRACE("CHALLENGE module to be load: " << challengeType);
    // let challenge module handle the request
    challenge->handleChallengeRequest(paramTLV, certRequest);
    if (certRequest.m_status == Status::FAILURE) {
      // if challenge failed
      m_storage->deleteRequest(certRequest.m_requestId);
      payload = CHALLENGE::encodeDataPayload(certRequest);
      _LOG_TRACE("Challenge failed");
    }
    else if (certRequest.m_status == Status::PENDING) {
      // if challenge succeeded
      if (certRequest.m_requestType == REQUEST_TYPE_NEW) {
        auto issuedCert = issueCertificate(certRequest);
        certRequest.m_cert = issuedCert;
        certRequest.m_status = Status::SUCCESS;
        try {
          m_storage->addCertificate(certRequest.m_requestId, issuedCert);
          m_storage->deleteRequest(certRequest.m_requestId);
          _LOG_TRACE("New Certificate Issued " << issuedCert.getName());
        }
        catch (const std::exception& e) {
          _LOG_ERROR("Cannot add issued cert and remove the request: " << e.what());
          return;
        }

        payload = CHALLENGE::encodeDataPayload(certRequest);
        payload.parse();
        payload.push_back(makeNestedBlock(tlv_issued_cert_name, issuedCert.getName()));
        payload.encode();

        //contentJson.add(JSON_CA_CERT_ID, readString(issuedCert.getName().at(-1)));
        _LOG_TRACE("Challenge succeeded. Certificate has been issued");
      }
      else if (certRequest.m_requestType == REQUEST_TYPE_REVOKE) {
        certRequest.m_status = Status::SUCCESS;
        try {
          m_storage->deleteRequest(certRequest.m_requestId);
          _LOG_TRACE("Certificate Revoked");
        }
        catch (const std::exception& e) {
          _LOG_ERROR("Cannot add issued cert and remove the request: " << e.what());
          return;
        }

        payload = CHALLENGE::encodeDataPayload(certRequest);
        payload.parse();
        _LOG_TRACE("Challenge succeeded. Certificate has been revoked");
      }
    }
    else {
      try {
        m_storage->updateRequest(certRequest);
      }
      catch (const std::exception& e) {
        _LOG_TRACE("Cannot update request instance: " << e.what());
        return;
      }
      payload = CHALLENGE::encodeDataPayload(certRequest);
      _LOG_TRACE("No failure no success. Challenge moves on");
    }
  }

  Data result;
  result.setName(request.getName());
  result.setFreshnessPeriod(DEFAULT_DATA_FRESHNESS_PERIOD);

  // encrypt the content
  auto contentBlock = encodeBlockWithAesGcm128(tlv::Content, m_aesKey, payload.value(),
                                               payload.value_size(), (uint8_t*)"test", strlen("test"));
  result.setContent(contentBlock);
  m_keyChain.sign(result, signingByIdentity(m_config.m_caPrefix));
  m_face.put(result);

  if (m_config.m_statusUpdateCallback) {
    m_config.m_statusUpdateCallback(certRequest);
  }
}

security::v2::Certificate
CaModule::issueCertificate(const CertificateRequest& certRequest)
{
  auto expectedPeriod =
    certRequest.m_cert.getValidityPeriod().getPeriod();
  security::ValidityPeriod period(expectedPeriod.first, expectedPeriod.second);
  security::v2::Certificate newCert;

  Name certName = certRequest.m_cert.getKeyName();
  certName.append("NDNCERT").append(std::to_string(random::generateSecureWord64()));
  newCert.setName(certName);
  newCert.setContent(certRequest.m_cert.getContent());
  _LOG_TRACE("cert request content " << certRequest.m_cert);
  SignatureInfo signatureInfo;
  signatureInfo.setValidityPeriod(period);
  security::SigningInfo signingInfo(security::SigningInfo::SIGNER_TYPE_ID,
                                    m_config.m_caPrefix, signatureInfo);

  m_keyChain.sign(newCert, signingInfo);
  _LOG_TRACE("new cert got signed" << newCert);
  return newCert;
}

CertificateRequest
CaModule::getCertificateRequest(const Interest& request)
{
  std::string requestId;
  CertificateRequest certRequest;
  try {
    requestId = readString(request.getName().at(m_config.m_caPrefix.size() + 2));
  }
  catch (const std::exception& e) {
    _LOG_ERROR("Cannot read the request ID out from the request: " << e.what());
  }
  try {
    _LOG_TRACE("Request Id to query the database " << requestId);
    certRequest = m_storage->getRequest(requestId);
  }
  catch (const std::exception& e) {
    _LOG_ERROR("Cannot get certificate request record from the storage: " << e.what());
  }
  return certRequest;
}

void
CaModule::onRegisterFailed(const std::string& reason)
{
  _LOG_ERROR("Failed to register prefix in local hub's daemon, REASON: " << reason);
}

Block
CaModule::dataContentFromJson(const JsonSection& jsonSection)
{
  std::stringstream ss;
  boost::property_tree::write_json(ss, jsonSection);
  return makeStringBlock(ndn::tlv::Content, ss.str());
}

JsonSection
CaModule::jsonFromBlock(const Block& block)
{
  std::string jsonString;
  try {
    jsonString = encoding::readString(block);
    std::istringstream ss(jsonString);
    JsonSection json;
    boost::property_tree::json_parser::read_json(ss, json);
    return json;
  }
  catch (const std::exception& e) {
    _LOG_ERROR("Cannot read JSON string from TLV Value: " << e.what());
    return JsonSection();
  }
}

} // namespace ndncert
} // namespace ndn
