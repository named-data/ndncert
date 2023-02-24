/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2017-2023, Regents of the University of California.
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
#include "challenge/challenge-module.hpp"
#include "name-assignment/assignment-func.hpp"
#include "detail/challenge-encoder.hpp"
#include "detail/error-encoder.hpp"
#include "detail/info-encoder.hpp"
#include "detail/request-encoder.hpp"
#include "detail/probe-encoder.hpp"

#include <ndn-cxx/metadata-object.hpp>
#include <ndn-cxx/security/signing-helpers.hpp>
#include <ndn-cxx/security/verification-helpers.hpp>
#include <ndn-cxx/util/io.hpp>
#include <ndn-cxx/util/random.hpp>
#include <ndn-cxx/util/string-helper.hpp>

namespace ndncert::ca {

const time::seconds DEFAULT_DATA_FRESHNESS_PERIOD = 1_s;
const time::seconds REQUEST_VALIDITY_PERIOD_NOT_BEFORE_GRACE_PERIOD = 120_s;

NDN_LOG_INIT(ndncert.ca);

CaModule::CaModule(ndn::Face& face, ndn::KeyChain& keyChain,
                   const std::string& configPath, const std::string& storageType)
  : m_face(face)
  , m_keyChain(keyChain)
{
  // load the config and create storage
  m_config.load(configPath);
  m_storage = CaStorage::createCaStorage(storageType, m_config.caProfile.caPrefix, "");

  ndn::random::generateSecureBytes(m_requestIdGenKey);

  if (m_config.nameAssignmentFuncs.empty()) {
    m_config.nameAssignmentFuncs.push_back(NameAssignmentFunc::createNameAssignmentFunc("random"));
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
  Name prefix = m_config.caProfile.caPrefix;
  prefix.append("CA");

  auto prefixId = m_face.registerPrefix(prefix,
    [&] (const Name& name) {
      // register INFO RDR metadata prefix
      const auto& metaDataComp = ndn::MetadataObject::getKeywordComponent();
      auto filterId = m_face.setInterestFilter(Name(name).append("INFO").append(metaDataComp),
                                               [this] (auto&&, const auto& i) { onCaProfileDiscovery(i); });
      m_interestFilterHandles.push_back(filterId);

      // register PROBE prefix
      filterId = m_face.setInterestFilter(Name(name).append("PROBE"),
                                          [this] (auto&&, const auto& i) { onProbe(i); });
      m_interestFilterHandles.push_back(filterId);

      // register NEW prefix
      filterId = m_face.setInterestFilter(Name(name).append("NEW"),
                                          [this] (auto&&, const auto& i) { onNewRenewRevoke(i, RequestType::NEW); });
      m_interestFilterHandles.push_back(filterId);

      // register SELECT prefix
      filterId = m_face.setInterestFilter(Name(name).append("CHALLENGE"),
                                          [this] (auto&&, const auto& i) { onChallenge(i); });
      m_interestFilterHandles.push_back(filterId);

      // register REVOKE prefix
      filterId = m_face.setInterestFilter(Name(name).append("REVOKE"),
                                          [this] (auto&&, const auto& i) { onNewRenewRevoke(i, RequestType::REVOKE); });
      m_interestFilterHandles.push_back(filterId);

      NDN_LOG_TRACE("Prefix " << name << " got registered");
    },
    [this] (auto&&, const auto& reason) { onRegisterFailed(reason); });
  m_registeredPrefixHandles.push_back(prefixId);
}

void
CaModule::setStatusUpdateCallback(const StatusUpdateCallback& onUpdateCallback)
{
  m_statusUpdateCallback = onUpdateCallback;
}

Data
CaModule::getCaProfileData()
{
  if (m_profileData == nullptr) {
    auto key = m_keyChain.getPib().getIdentity(m_config.caProfile.caPrefix).getDefaultKey();
    Block contentTLV = infotlv::encodeDataContent(m_config.caProfile, key.getDefaultCertificate());

    Name infoPacketName(m_config.caProfile.caPrefix);
    auto segmentComp = ndn::name::Component::fromSegment(0);
    infoPacketName.append("CA").append("INFO").appendVersion().append(segmentComp);
    m_profileData = std::make_unique<Data>(infoPacketName);
    m_profileData->setFinalBlock(segmentComp);
    m_profileData->setContent(contentTLV);
    m_profileData->setFreshnessPeriod(DEFAULT_DATA_FRESHNESS_PERIOD);
    m_keyChain.sign(*m_profileData, signingByIdentity(m_config.caProfile.caPrefix));
  }
  return *m_profileData;
}

void
CaModule::onCaProfileDiscovery(const Interest&)
{
  NDN_LOG_TRACE("Received CA Profile MetaData discovery Interest");
  if (m_profileData == nullptr) {
    m_profileData = std::make_unique<Data>(getCaProfileData());
  }
  ndn::MetadataObject metadata;
  metadata.setVersionedName(m_profileData->getName().getPrefix(-1));
  Name discoveryInterestName(m_profileData->getName().getPrefix(-2));
  discoveryInterestName.append(ndn::MetadataObject::getKeywordComponent());
  m_face.put(metadata.makeData(discoveryInterestName, m_keyChain, signingByIdentity(m_config.caProfile.caPrefix)));
}

void
CaModule::onProbe(const Interest& request)
{
  // PROBE Naming Convention: /<CA-Prefix>/CA/PROBE/[ParametersSha256DigestComponent]
  NDN_LOG_TRACE("Received PROBE request");

  // process PROBE requests: collect probe parameters
  std::vector<ndn::Name> redirectionNames;
  std::vector<ndn::PartialName> availableComponents;
  try {
    auto parameters = probetlv::decodeApplicationParameters(request.getApplicationParameters());

    // collect redirections
    for (auto &item : m_config.redirection) {
      if (item.second->isRedirecting(parameters)) {
        redirectionNames.push_back(item.first->getFullName());
      }
    }

    // collect name assignments
    for (auto &item : m_config.nameAssignmentFuncs) {
      auto names = item->assignName(parameters);
      availableComponents.insert(availableComponents.end(), names.begin(), names.end());
    }
  }
  catch (const std::exception& e) {
    NDN_LOG_ERROR("[CaModule::onProbe]Error in decoding TLV: " << e.what());
    return;
  }

  if (availableComponents.empty() && redirectionNames.empty()) {
    m_face.put(generateErrorDataPacket(request.getName(), ErrorCode::INVALID_PARAMETER,
                                       "Cannot generate available names from parameters provided."));
    return;
  }

  std::vector<Name> availableNames;
  for (const auto &component : availableComponents) {
    Name newIdentityName = m_config.caProfile.caPrefix;
    newIdentityName.append(component);
    availableNames.push_back(newIdentityName);
  }

  Data result;
  result.setName(request.getName());
  result.setContent(probetlv::encodeDataContent(availableNames, m_config.caProfile.maxSuffixLength,
                                                redirectionNames));
  result.setFreshnessPeriod(DEFAULT_DATA_FRESHNESS_PERIOD);
  m_keyChain.sign(result, signingByIdentity(m_config.caProfile.caPrefix));
  m_face.put(result);
  NDN_LOG_TRACE("Handle PROBE: send out the PROBE response");
}

void
CaModule::onNewRenewRevoke(const Interest& request, RequestType requestType)
{
  // verify ca cert validity
  auto caCert = m_keyChain.getPib()
                          .getIdentity(m_config.caProfile.caPrefix)
                          .getDefaultKey()
                          .getDefaultCertificate();
  if (!caCert.isValid()) {
    NDN_LOG_ERROR("Server certificate invalid/expired");
    m_face.put(generateErrorDataPacket(request.getName(), ErrorCode::BAD_VALIDITY_PERIOD,
                                       "Server certificate invalid/expired"));
    return;
  }

  // NEW Naming Convention: /<CA-prefix>/CA/NEW/[SignedInterestParameters_Digest]
  // REVOKE Naming Convention: /<CA-prefix>/CA/REVOKE/[SignedInterestParameters_Digest]
  // get ECDH pub key and cert request
  const auto& parameterTLV = request.getApplicationParameters();
  std::vector <uint8_t> ecdhPub;
  std::shared_ptr<Certificate> clientCert;
  try {
    requesttlv::decodeApplicationParameters(parameterTLV, requestType, ecdhPub, clientCert);
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
  std::vector <uint8_t> sharedSecret;
  try {
    sharedSecret = ecdh.deriveSecret(ecdhPub);
  }
  catch (const std::exception& e) {
    NDN_LOG_ERROR("Cannot derive a shared secret using the provided ECDH key: " << e.what());
    m_face.put(generateErrorDataPacket(request.getName(), ErrorCode::INVALID_PARAMETER,
                                       "Cannot derive a shared secret using the provided ECDH key."));
    return;
  }

  // verify identity name
  if (!m_config.caProfile.caPrefix.isPrefixOf(clientCert->getIdentity())
      || !Certificate::isValidName(clientCert->getName())
      || clientCert->getIdentity().size() <= m_config.caProfile.caPrefix.size()) {
    NDN_LOG_ERROR("An invalid certificate name is being requested " << clientCert->getName());
    m_face.put(generateErrorDataPacket(request.getName(), ErrorCode::NAME_NOT_ALLOWED,
                                       "An invalid certificate name is being requested."));
    return;
  }
  if (m_config.caProfile.maxSuffixLength) {
    if (clientCert->getIdentity().size() > m_config.caProfile.caPrefix.size() + *m_config.caProfile.maxSuffixLength) {
      NDN_LOG_ERROR("An invalid certificate name is being requested " << clientCert->getName());
      m_face.put(generateErrorDataPacket(request.getName(), ErrorCode::NAME_NOT_ALLOWED,
                                         "An invalid certificate name is being requested."));
      return;
    }
  }

  if (requestType == RequestType::NEW) {
    // check the validity period
    auto [notBefore, notAfter] = clientCert->getValidityPeriod().getPeriod();
    auto currentTime = time::system_clock::now();
    if (notBefore < currentTime - REQUEST_VALIDITY_PERIOD_NOT_BEFORE_GRACE_PERIOD ||
        notAfter > currentTime + m_config.caProfile.maxValidityPeriod ||
        notAfter <= notBefore) {
      NDN_LOG_ERROR("An invalid validity period is being requested.");
      m_face.put(generateErrorDataPacket(request.getName(), ErrorCode::BAD_VALIDITY_PERIOD,
                                         "An invalid validity period is being requested."));
      return;
    }

    // verify signature
    if (!ndn::security::verifySignature(*clientCert, *clientCert)) {
      NDN_LOG_ERROR("Invalid signature in the self-signed certificate.");
      m_face.put(generateErrorDataPacket(request.getName(), ErrorCode::BAD_SIGNATURE,
                                         "Invalid signature in the self-signed certificate."));
      return;
    }
    if (!ndn::security::verifySignature(request, *clientCert)) {
      NDN_LOG_ERROR("Invalid signature in the Interest packet.");
      m_face.put(generateErrorDataPacket(request.getName(), ErrorCode::BAD_SIGNATURE,
                                         "Invalid signature in the Interest packet."));
      return;
    }
  }
  else if (requestType == RequestType::REVOKE) {
    //verify cert is from this CA
    if (!ndn::security::verifySignature(*clientCert, caCert)) {
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
  RequestId id;
  std::memcpy(id.data(), requestIdData, id.size());
  // initialize request state
  RequestState requestState;
  requestState.caPrefix = m_config.caProfile.caPrefix;
  requestState.requestId = id;
  requestState.requestType = requestType;
  requestState.cert = *clientCert;
  // generate salt for HKDF
  std::array<uint8_t, 32> salt;
  ndn::random::generateSecureBytes(salt);
  // hkdf
  std::array<uint8_t, 16> aesKey;
  hkdf(sharedSecret.data(), sharedSecret.size(), salt.data(), salt.size(),
       aesKey.data(), aesKey.size(), id.data(), id.size());
  requestState.encryptionKey = aesKey;
  try {
    m_storage->addRequest(requestState);
  }
  catch (const std::runtime_error&) {
    NDN_LOG_ERROR("Duplicate Request ID: The same request has been seen before.");
    m_face.put(generateErrorDataPacket(request.getName(), ErrorCode::INVALID_PARAMETER,
                                       "Duplicate Request ID: The same request has been seen before."));
    return;
  }

  Data result;
  result.setName(request.getName());
  result.setFreshnessPeriod(DEFAULT_DATA_FRESHNESS_PERIOD);
  result.setContent(requesttlv::encodeDataContent(ecdh.getSelfPubKey(),
                                                  salt, requestState.requestId,
                                                  m_config.caProfile.supportedChallenges));
  m_keyChain.sign(result, signingByIdentity(m_config.caProfile.caPrefix));
  m_face.put(result);
  if (m_statusUpdateCallback) {
    m_statusUpdateCallback(requestState);
  }
}

void
CaModule::onChallenge(const Interest& request)
{
  // get certificate request state
  auto requestState = getCertificateRequest(request);
  if (requestState == nullptr) {
    NDN_LOG_ERROR("No certificate request state can be found.");
    m_face.put(generateErrorDataPacket(request.getName(), ErrorCode::INVALID_PARAMETER,
                                       "No certificate request state can be found."));
    return;
  }

  // verify signature
  if (!ndn::security::verifySignature(request, requestState->cert)) {
    NDN_LOG_ERROR("Invalid Signature in the Interest packet.");
    m_face.put(generateErrorDataPacket(request.getName(), ErrorCode::BAD_SIGNATURE,
                                       "Invalid Signature in the Interest packet."));
    return;
  }

  // decrypt the parameters
  ndn::Buffer paramTLVPayload;
  try {
    paramTLVPayload = decodeBlockWithAesGcm128(request.getApplicationParameters(), requestState->encryptionKey.data(),
                                               requestState->requestId.data(), requestState->requestId.size(),
                                               requestState->decryptionIv, requestState->encryptionIv);
  }
  catch (const std::exception& e) {
    NDN_LOG_ERROR("Interest paramaters decryption failed: " << e.what());
    m_storage->deleteRequest(requestState->requestId);
    m_face.put(generateErrorDataPacket(request.getName(), ErrorCode::INVALID_PARAMETER,
                                       "Interest paramaters decryption failed."));
    return;
  }
  if (paramTLVPayload.empty()) {
    NDN_LOG_ERROR("No parameters are found after decryption.");
    m_storage->deleteRequest(requestState->requestId);
    m_face.put(generateErrorDataPacket(request.getName(), ErrorCode::INVALID_PARAMETER,
                                       "No parameters are found after decryption."));
    return;
  }

  auto paramTLV = ndn::makeBinaryBlock(tlv::EncryptedPayload, paramTLVPayload);
  paramTLV.parse();

  // load the corresponding challenge module
  std::string challengeType = readString(paramTLV.get(tlv::SelectedChallenge));
  auto challenge = ChallengeModule::createChallengeModule(challengeType);
  if (challenge == nullptr) {
    NDN_LOG_TRACE("Unrecognized challenge type: " << challengeType);
    m_storage->deleteRequest(requestState->requestId);
    m_face.put(
      generateErrorDataPacket(request.getName(), ErrorCode::INVALID_PARAMETER, "Unrecognized challenge type."));
    return;
  }

  NDN_LOG_TRACE("CHALLENGE module to be load: " << challengeType);
  auto errorInfo = challenge->handleChallengeRequest(paramTLV, *requestState);
  if (std::get<0>(errorInfo) != ErrorCode::NO_ERROR) {
    m_storage->deleteRequest(requestState->requestId);
    m_face.put(generateErrorDataPacket(request.getName(), std::get<0>(errorInfo), std::get<1>(errorInfo)));
    return;
  }

  Block payload;
  if (requestState->status == Status::PENDING) {
    // if challenge succeeded
    if (requestState->requestType == RequestType::NEW || requestState->requestType == RequestType::RENEW) {
      auto issuedCert = issueCertificate(*requestState);
      requestState->cert = issuedCert;
      requestState->status = Status::SUCCESS;
      m_storage->deleteRequest(requestState->requestId);

      payload = challengetlv::encodeDataContent(*requestState, issuedCert.getName());
      NDN_LOG_TRACE("Challenge succeeded. Certificate has been issued: " << issuedCert.getName());
    }
    else if (requestState->requestType == RequestType::REVOKE) {
      requestState->status = Status::SUCCESS;
      m_storage->deleteRequest(requestState->requestId);
      // TODO: where is the code to revoke?
      payload = challengetlv::encodeDataContent(*requestState);
      NDN_LOG_TRACE("Challenge succeeded. Certificate has been revoked");
    }
  }
  else {
    payload = challengetlv::encodeDataContent(*requestState);
    m_storage->updateRequest(*requestState);
    NDN_LOG_TRACE("No failure no success. Challenge moves on");
  }

  Data result;
  result.setName(request.getName());
  result.setFreshnessPeriod(DEFAULT_DATA_FRESHNESS_PERIOD);
  result.setContent(payload);
  m_keyChain.sign(result, signingByIdentity(m_config.caProfile.caPrefix));
  m_face.put(result);
  if (m_statusUpdateCallback) {
    m_statusUpdateCallback(*requestState);
  }
}

Certificate
CaModule::issueCertificate(const RequestState& requestState)
{
  auto period = requestState.cert.getValidityPeriod();
  Certificate newCert;

  Name certName = requestState.cert.getKeyName();
  certName.append("NDNCERT").appendVersion();
  newCert.setName(certName);
  newCert.setContent(requestState.cert.getContent());
  newCert.setFreshnessPeriod(1_h);
  NDN_LOG_TRACE("cert request content " << requestState.cert);
  SignatureInfo signatureInfo;
  signatureInfo.setValidityPeriod(period);
  ndn::security::SigningInfo signingInfo(ndn::security::SigningInfo::SIGNER_TYPE_ID,
                                         m_config.caProfile.caPrefix, signatureInfo);
  // Note: we should use KeyChain::makeCertificate() in future.
  m_keyChain.sign(newCert, signingInfo);
  NDN_LOG_TRACE("new cert got signed" << newCert);
  return newCert;
}

std::unique_ptr <RequestState>
CaModule::getCertificateRequest(const Interest& request)
{
  RequestId requestId;
  try {
    auto& component = request.getName().at(m_config.caProfile.caPrefix.size() + 2);
    std::memcpy(requestId.data(), component.value(), component.value_size());
  }
  catch (const std::exception& e) {
    NDN_LOG_ERROR("Cannot read the request ID out from the request: " << e.what());
    return nullptr;
  }
  try {
    NDN_LOG_TRACE("Request Id to query the database " << ndn::toHex(requestId));
    return std::make_unique<RequestState>(m_storage->getRequest(requestId));
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
  result.setContent(errortlv::encodeDataContent(error, errorInfo));
  m_keyChain.sign(result, signingByIdentity(m_config.caProfile.caPrefix));
  return result;
}

} // namespace ndncert::ca
