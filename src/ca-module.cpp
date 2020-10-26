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
#include "detail/crypto-helpers.hpp"
#include "identity-challenge/challenge-module.hpp"
#include "name-assignment/assignment-func.hpp"
#include "detail/challenge-encoder.hpp"
#include "detail/error-encoder.hpp"
#include "detail/info-encoder.hpp"
#include "detail/new-renew-revoke-encoder.hpp"
#include "detail/probe-encoder.hpp"
#include <ndn-cxx/metadata-object.hpp>
#include <ndn-cxx/security/signing-helpers.hpp>
#include <ndn-cxx/security/verification-helpers.hpp>
#include <ndn-cxx/util/io.hpp>
#include <ndn-cxx/util/random.hpp>
#include <ndn-cxx/util/string-helper.hpp>

namespace ndn {
namespace ndncert {

static const time::seconds DEFAULT_DATA_FRESHNESS_PERIOD = 1_s;
static const time::seconds REQUEST_VALIDITY_PERIOD_NOT_BEFORE_GRACE_PERIOD = 120_s;
static const int AES_128_KEY_LEN = 16;

NDN_LOG_INIT(ndncert.ca);

CaModule::CaModule(Face& face, security::KeyChain& keyChain,
                   const std::string& configPath, const std::string& storageType)
    : m_face(face)
    , m_keyChain(keyChain)
{
  // load the config and create storage
  m_config.load(configPath);
  m_storage = CaStorage::createCaStorage(storageType, m_config.m_caItem.m_caPrefix, "");
  random::generateSecureBytes(m_requestIdGenKey, 32);
  if (m_config.m_nameAssignmentFuncs.size() == 0) {
    m_config.m_nameAssignmentFuncs.push_back(NameAssignmentFunc::createNameAssignmentFunc("random"));
  }
  registerPrefix();
}

CaModule::~CaModule()
{
  for (auto& handle : m_interestFilterHandles) {
    handle.cancel();
  }
  for (auto& handle : m_registeredPrefixHandles) {
    handle.unregister();
  }
}

void
CaModule::registerPrefix()
{
  // register prefixes
  Name prefix = m_config.m_caItem.m_caPrefix;
  prefix.append("CA");

  auto prefixId = m_face.registerPrefix(
      prefix,
      [&](const Name& name) {
        // register INFO RDR metadata prefix
        name::Component metaDataComp(32, reinterpret_cast<const uint8_t*>("metadata"), std::strlen("metadata"));
        auto filterId = m_face.setInterestFilter(Name(name).append("INFO").append(metaDataComp),
                                                 bind(&CaModule::onCaProfileDiscovery, this, _2));
        m_interestFilterHandles.push_back(filterId);

        // register PROBE prefix
        filterId = m_face.setInterestFilter(Name(name).append("PROBE"),
                                            bind(&CaModule::onProbe, this, _2));
        m_interestFilterHandles.push_back(filterId);

        // register NEW prefix
        filterId = m_face.setInterestFilter(Name(name).append("NEW"),
                                            bind(&CaModule::onNewRenewRevoke, this, _2, RequestType::NEW));
        m_interestFilterHandles.push_back(filterId);

        // register SELECT prefix
        filterId = m_face.setInterestFilter(Name(name).append("CHALLENGE"),
                                            bind(&CaModule::onChallenge, this, _2));
        m_interestFilterHandles.push_back(filterId);

        // register REVOKE prefix
        filterId = m_face.setInterestFilter(Name(name).append("REVOKE"),
                                            bind(&CaModule::onNewRenewRevoke, this, _2, RequestType::REVOKE));
        m_interestFilterHandles.push_back(filterId);
        NDN_LOG_TRACE("Prefix " << name << " got registered");
      },
      bind(&CaModule::onRegisterFailed, this, _2));
  m_registeredPrefixHandles.push_back(prefixId);
}

void
CaModule::setStatusUpdateCallback(const StatusUpdateCallback& onUpdateCallback)
{
  m_config.m_statusUpdateCallback = onUpdateCallback;
}

Data
CaModule::getCaProfileData()
{
  if (m_profileData == nullptr) {
    const auto& pib = m_keyChain.getPib();
    const auto& identity = pib.getIdentity(m_config.m_caItem.m_caPrefix);
    const auto& cert = identity.getDefaultKey().getDefaultCertificate();
    Block contentTLV = InfoEncoder::encodeDataContent(m_config.m_caItem, cert);

    Name infoPacketName(m_config.m_caItem.m_caPrefix);
    infoPacketName.append("CA").append("INFO").appendVersion().appendSegment(0);
    m_profileData = std::make_unique<Data>(infoPacketName);
    m_profileData->setContent(contentTLV);
    m_profileData->setFreshnessPeriod(DEFAULT_DATA_FRESHNESS_PERIOD);
    m_keyChain.sign(*m_profileData, signingByIdentity(m_config.m_caItem.m_caPrefix));
  }
  return *m_profileData;
}

void
CaModule::onCaProfileDiscovery(const Interest& request)
{
  NDN_LOG_TRACE("Received CA Profile MetaData discovery Interest");
  if (m_profileData == nullptr) {
    m_profileData = std::make_unique<Data>(getCaProfileData());
  }
  MetadataObject metadata;
  metadata.setVersionedName(m_profileData->getName().getPrefix(-1));
  Name discoveryInterestName(m_profileData->getName().getPrefix(-2));
  name::Component metadataComponent(32, reinterpret_cast<const uint8_t*>("metadata"), std::strlen("metadata"));
  discoveryInterestName.append(metadataComponent);
  m_face.put(metadata.makeData(discoveryInterestName, m_keyChain, signingByIdentity(m_config.m_caItem.m_caPrefix)));
}

void
CaModule::onProbe(const Interest& request)
{
  // PROBE Naming Convention: /<CA-Prefix>/CA/PROBE/[ParametersSha256DigestComponent]
  NDN_LOG_TRACE("Received PROBE request");

  // process PROBE requests: collect probe parameters
  auto parameters = ProbeEncoder::decodeApplicationParameters(request.getApplicationParameters());
  std::vector<PartialName> availableComponents;
  for (auto& item : m_config.m_nameAssignmentFuncs) {
    auto names = item->assignName(parameters);
    availableComponents.insert(availableComponents.end(), names.begin(), names.end());
  }
  if (availableComponents.size() == 0) {
    m_face.put(generateErrorDataPacket(request.getName(), ErrorCode::INVALID_PARAMETER,
                                       "Cannot generate available names from parameters provided."));
    return;
  }
  std::vector<Name> availableNames;
  for (const auto& component : availableComponents) {
    Name newIdentityName = m_config.m_caItem.m_caPrefix;
    newIdentityName.append(component);
    availableNames.push_back(newIdentityName);
  }

  Data result;
  result.setName(request.getName());
  result.setContent(ProbeEncoder::encodeDataContent(availableNames, m_config.m_caItem.m_maxSuffixLength, m_config.m_redirection));
  result.setFreshnessPeriod(DEFAULT_DATA_FRESHNESS_PERIOD);
  m_keyChain.sign(result, signingByIdentity(m_config.m_caItem.m_caPrefix));
  m_face.put(result);
  NDN_LOG_TRACE("Handle PROBE: send out the PROBE response");
}

void
CaModule::onNewRenewRevoke(const Interest& request, RequestType requestType)
{
  // NEW Naming Convention: /<CA-prefix>/CA/NEW/[SignedInterestParameters_Digest]
  // REVOKE Naming Convention: /<CA-prefix>/CA/REVOKE/[SignedInterestParameters_Digest]
  // get ECDH pub key and cert request
  const auto& parameterTLV = request.getApplicationParameters();
  std::vector<uint8_t> ecdhPub;
  shared_ptr<security::Certificate> clientCert;
  try {
    NewRenewRevokeEncoder::decodeApplicationParameters(parameterTLV, requestType, ecdhPub, clientCert);
  }
  catch (const std::exception& e) {
    if (!parameterTLV.hasValue()) {
      NDN_LOG_ERROR("Empty TLV obtained from the Interest parameter.");
      m_face.put(generateErrorDataPacket(request.getName(), ErrorCode::INVALID_PARAMETER,
                                         "Empty TLV obtained from the Interest parameter."));
      return;
    }

    NDN_LOG_ERROR("Unrecognized self-signed certificate: " << e.what());
    m_face.put(generateErrorDataPacket(request.getName(), ErrorCode::INVALID_PARAMETER,
                                       "Unrecognized self-signed certificate."));
    return;
  }

  if (ecdhPub.empty()) {
    NDN_LOG_ERROR("Empty ECDH PUB obtained from the Interest parameter.");
    m_face.put(generateErrorDataPacket(request.getName(), ErrorCode::INVALID_PARAMETER,
                                       "Empty ECDH PUB obtained from the Interest parameter."));
    return;
  }

  // get server's ECDH pub key
  ECDHState ecdh;
  auto myEcdhPubKeyBase64 = ecdh.getSelfPubKey();
  std::vector<uint8_t> sharedSecret;
  try {
    sharedSecret = ecdh.deriveSecret(ecdhPub);
  }
  catch (const std::exception& e) {
    NDN_LOG_ERROR("Cannot derive a shared secret using the provided ECDH key: " << e.what());
    m_face.put(generateErrorDataPacket(request.getName(), ErrorCode::INVALID_PARAMETER,
                                       "Cannot derive a shared secret using the provided ECDH key."));
    return;
  }
  // generate salt for HKDF
  std::array<uint8_t, 32> salt;
  random::generateSecureBytes(salt.data(), salt.size());
  // hkdf
  uint8_t aesKey[AES_128_KEY_LEN];
  hkdf(sharedSecret.data(), sharedSecret.size(), salt.data(), salt.size(), aesKey, sizeof(aesKey));

  // verify identity name
  if (!m_config.m_caItem.m_caPrefix.isPrefixOf(clientCert->getIdentity())
      || !security::Certificate::isValidName(clientCert->getName())
      || clientCert->getIdentity().size() <= m_config.m_caItem.m_caPrefix.size()) {
      NDN_LOG_ERROR("An invalid certificate name is being requested " << clientCert->getName());
      m_face.put(generateErrorDataPacket(request.getName(), ErrorCode::NAME_NOT_ALLOWED,
                                         "An invalid certificate name is being requested."));
      return;
  }
  if (m_config.m_caItem.m_maxSuffixLength) {
    if (clientCert->getIdentity().size() > m_config.m_caItem.m_caPrefix.size() + *m_config.m_caItem.m_maxSuffixLength) {
      NDN_LOG_ERROR("An invalid certificate name is being requested " << clientCert->getName());
      m_face.put(generateErrorDataPacket(request.getName(), ErrorCode::NAME_NOT_ALLOWED,
                                         "An invalid certificate name is being requested."));
      return;
    }
  }

  if (requestType == RequestType::NEW) {
    // check the validity period
    auto expectedPeriod = clientCert->getValidityPeriod().getPeriod();
    auto currentTime = time::system_clock::now();
    if (expectedPeriod.first < currentTime - REQUEST_VALIDITY_PERIOD_NOT_BEFORE_GRACE_PERIOD ||
        expectedPeriod.second > currentTime + m_config.m_caItem.m_maxValidityPeriod ||
        expectedPeriod.second <= expectedPeriod.first) {
      NDN_LOG_ERROR("An invalid validity period is being requested.");
      m_face.put(generateErrorDataPacket(request.getName(), ErrorCode::BAD_VALIDITY_PERIOD,
                                         "An invalid validity period is being requested."));
      return;
    }

    // verify signature
    if (!security::verifySignature(*clientCert, *clientCert)) {
      NDN_LOG_ERROR("Invalid signature in the self-signed certificate.");
      m_face.put(generateErrorDataPacket(request.getName(), ErrorCode::BAD_SIGNATURE,
                                         "Invalid signature in the self-signed certificate."));
      return;
    }
    if (!security::verifySignature(request, *clientCert)) {
      NDN_LOG_ERROR("Invalid signature in the Interest packet.");
      m_face.put(generateErrorDataPacket(request.getName(), ErrorCode::BAD_SIGNATURE,
                                         "Invalid signature in the Interest packet."));
      return;
    }
  }
  else if (requestType == RequestType::REVOKE) {
    //verify cert is from this CA
    const auto& cert = m_keyChain.getPib().getIdentity(m_config.m_caItem.m_caPrefix).getDefaultKey().getDefaultCertificate();
    if (!security::verifySignature(*clientCert, cert)) {
      NDN_LOG_ERROR("Invalid signature in the certificate to revoke.");
      m_face.put(generateErrorDataPacket(request.getName(), ErrorCode::BAD_SIGNATURE,
                                         "Invalid signature in the certificate to revoke."));
      return;
    }
  }

  // create new request instance
  uint8_t requestIdData[32];
  Block certNameTlv = clientCert->getName().wireEncode();
  try {
    hmacSha256(certNameTlv.wire(), certNameTlv.size(), m_requestIdGenKey, 32, requestIdData);
  }
  catch (const std::runtime_error& e) {
    NDN_LOG_ERROR("Error computing the request ID: " << std::string(e.what()));
    m_face.put(generateErrorDataPacket(request.getName(), ErrorCode::INVALID_PARAMETER,
                                       "Error computing the request ID."));
    return;
  }
  RequestID id;
  std::memcpy(id.data(), requestIdData, id.size());
  CaState requestState(m_config.m_caItem.m_caPrefix, id,
                       requestType, Status::BEFORE_CHALLENGE, *clientCert,
                       makeBinaryBlock(ndn::tlv::ContentType_Key, aesKey, sizeof(aesKey)));
  try {
    m_storage->addRequest(requestState);
  }
  catch (const std::runtime_error& e) {
    NDN_LOG_ERROR("Duplicate Request ID: The same request has been seen before.");
    m_face.put(generateErrorDataPacket(request.getName(), ErrorCode::INVALID_PARAMETER,
                                       "Duplicate Request ID: The same request has been seen before."));
    return;
  }
  Data result;
  result.setName(request.getName());
  result.setFreshnessPeriod(DEFAULT_DATA_FRESHNESS_PERIOD);
  result.setContent(NewRenewRevokeEncoder::encodeDataContent(myEcdhPubKeyBase64,
                                                             salt,
                                                             requestState.m_requestId, requestState.m_status,
                                                             m_config.m_caItem.m_supportedChallenges));
  m_keyChain.sign(result, signingByIdentity(m_config.m_caItem.m_caPrefix));
  m_face.put(result);
  if (m_config.m_statusUpdateCallback) {
    m_config.m_statusUpdateCallback(requestState);
  }
}

void
CaModule::onChallenge(const Interest& request)
{
  // get certificate request state
  auto requestState = getCertificateRequest(request);
  if (requestState== nullptr) {
    NDN_LOG_ERROR("No certificate request state can be found.");
    m_face.put(generateErrorDataPacket(request.getName(), ErrorCode::INVALID_PARAMETER,
                                       "No certificate request state can be found."));
    return;
  }
  // verify signature
  if (!security::verifySignature(request, requestState->m_cert)) {
    NDN_LOG_ERROR("Invalid Signature in the Interest packet.");
    m_face.put(generateErrorDataPacket(request.getName(), ErrorCode::BAD_SIGNATURE,
                                       "Invalid Signature in the Interest packet."));
    return;
  }
  // decrypt the parameters
  Buffer paramTLVPayload;
  try {
    paramTLVPayload = decodeBlockWithAesGcm128(request.getApplicationParameters(),
                                               requestState->m_encryptionKey.value(),
                                               requestState->m_requestId.data(),
                                               requestState->m_requestId.size());
  }
  catch (const std::exception& e) {
    NDN_LOG_ERROR("Interest paramaters decryption failed: " << e.what());
    m_storage->deleteRequest(requestState->m_requestId);
    m_face.put(generateErrorDataPacket(request.getName(), ErrorCode::INVALID_PARAMETER,
                                       "Interest paramaters decryption failed."));
    return;
  }
  if (paramTLVPayload.size() == 0) {
    NDN_LOG_ERROR("No parameters are found after decryption.");
    m_storage->deleteRequest(requestState->m_requestId);
    m_face.put(generateErrorDataPacket(request.getName(), ErrorCode::INVALID_PARAMETER,
                                       "No parameters are found after decryption."));
    return;
  }
  Block paramTLV = makeBinaryBlock(tlv::EncryptedPayload, paramTLVPayload.data(), paramTLVPayload.size());
  paramTLV.parse();

  // load the corresponding challenge module
  std::string challengeType = readString(paramTLV.get(tlv::SelectedChallenge));
  auto challenge = ChallengeModule::createChallengeModule(challengeType);
  if (challenge == nullptr) {
    NDN_LOG_TRACE("Unrecognized challenge type: " << challengeType);
    m_storage->deleteRequest(requestState->m_requestId);
    m_face.put(generateErrorDataPacket(request.getName(), ErrorCode::INVALID_PARAMETER, "Unrecognized challenge type."));
    return;
  }

  NDN_LOG_TRACE("CHALLENGE module to be load: " << challengeType);
  auto errorInfo = challenge->handleChallengeRequest(paramTLV, *requestState);
  if (std::get<0>(errorInfo) != ErrorCode::NO_ERROR) {
    m_storage->deleteRequest(requestState->m_requestId);
    m_face.put(generateErrorDataPacket(request.getName(), std::get<0>(errorInfo), std::get<1>(errorInfo)));
    return;
  }

  Block payload;
  if (requestState->m_status == Status::PENDING) {
    // if challenge succeeded
    if (requestState->m_requestType == RequestType::NEW) {
      auto issuedCert = issueCertificate(*requestState);
      requestState->m_cert = issuedCert;
      requestState->m_status = Status::SUCCESS;
      m_storage->deleteRequest(requestState->m_requestId);

      payload = ChallengeEncoder::encodeDataContent(*requestState);
      payload.parse();
      payload.push_back(makeNestedBlock(tlv::IssuedCertName, issuedCert.getName()));
      payload.encode();
      NDN_LOG_TRACE("Challenge succeeded. Certificate has been issued: " << issuedCert.getName());
    }
    else if (requestState->m_requestType == RequestType::REVOKE) {
      requestState->m_status = Status::SUCCESS;
      m_storage->deleteRequest(requestState->m_requestId);

      payload = ChallengeEncoder::encodeDataContent(*requestState);
      NDN_LOG_TRACE("Challenge succeeded. Certificate has been revoked");
    }
  }
  else {
    m_storage->updateRequest(*requestState);
    payload = ChallengeEncoder::encodeDataContent(*requestState);
    NDN_LOG_TRACE("No failure no success. Challenge moves on");
  }

  Data result;
  result.setName(request.getName());
  result.setFreshnessPeriod(DEFAULT_DATA_FRESHNESS_PERIOD);
  auto contentBlock = encodeBlockWithAesGcm128(ndn::tlv::Content, requestState->m_encryptionKey.value(),
                                               payload.value(), payload.value_size(),
                                               requestState->m_requestId.data(),
                                               requestState->m_requestId.size(),
                                               requestState->m_aesBlockCounter);
  result.setContent(contentBlock);
  m_keyChain.sign(result, signingByIdentity(m_config.m_caItem.m_caPrefix));
  m_face.put(result);
  if (m_config.m_statusUpdateCallback) {
    m_config.m_statusUpdateCallback(*requestState);
  }
}

security::Certificate
CaModule::issueCertificate(const CaState& requestState)
{
  auto expectedPeriod = requestState.m_cert.getValidityPeriod().getPeriod();
  security::ValidityPeriod period(expectedPeriod.first, expectedPeriod.second);
  security::Certificate newCert;

  Name certName = requestState.m_cert.getKeyName();
  certName.append("NDNCERT").append(std::to_string(random::generateSecureWord64()));
  newCert.setName(certName);
  newCert.setContent(requestState.m_cert.getContent());
  NDN_LOG_TRACE("cert request content " << requestState.m_cert);
  SignatureInfo signatureInfo;
  signatureInfo.setValidityPeriod(period);
  security::SigningInfo signingInfo(security::SigningInfo::SIGNER_TYPE_ID,
                                    m_config.m_caItem.m_caPrefix, signatureInfo);

  m_keyChain.sign(newCert, signingInfo);
  NDN_LOG_TRACE("new cert got signed" << newCert);
  return newCert;
}

std::unique_ptr<CaState>
CaModule::getCertificateRequest(const Interest& request)
{
  RequestID requestId;
  try {
    auto& component = request.getName().at(m_config.m_caItem.m_caPrefix.size() + 2);
    std::memcpy(requestId.data(), component.value(), component.value_size());
  }
  catch (const std::exception& e) {
    NDN_LOG_ERROR("Cannot read the request ID out from the request: " << e.what());
    return nullptr;
  }
  try {
    NDN_LOG_TRACE("Request Id to query the database " << toHex(requestId.data(), requestId.size()));
    return std::make_unique<CaState>(m_storage->getRequest(requestId));
  }
  catch (const std::exception& e) {
    NDN_LOG_ERROR("Cannot get certificate request record from the storage: " << e.what());
    return nullptr;
  }
}

void
CaModule::onRegisterFailed(const std::string& reason)
{
  NDN_LOG_ERROR("Failed to register prefix in local hub's daemon, REASON: " << reason);
}

Data
CaModule::generateErrorDataPacket(const Name& name, ErrorCode error, const std::string& errorInfo)
{
  Data result;
  result.setName(name);
  result.setFreshnessPeriod(DEFAULT_DATA_FRESHNESS_PERIOD);
  result.setContent(ErrorEncoder::encodeDataContent(error, errorInfo));
  m_keyChain.sign(result, signingByIdentity(m_config.m_caItem.m_caPrefix));
  return result;
}

} // namespace ndncert
} // namespace ndn
