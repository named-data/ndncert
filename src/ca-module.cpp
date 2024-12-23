/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2017-2024, Regents of the University of California.
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
#include "challenge/challenge-module.hpp"
#include "name-assignment/assignment-func.hpp"
#include "detail/challenge-encoder.hpp"
#include "detail/crypto-helpers.hpp"
#include "detail/error-encoder.hpp"
#include "detail/info-encoder.hpp"
#include "detail/probe-encoder.hpp"
#include "detail/request-encoder.hpp"

#include <ndn-cxx/metadata-object.hpp>
#include <ndn-cxx/security/signing-helpers.hpp>
#include <ndn-cxx/security/verification-helpers.hpp>
#include <ndn-cxx/util/logger.hpp>
#include <ndn-cxx/util/random.hpp>
#include <ndn-cxx/util/string-helper.hpp>

namespace ndncert::ca {

constexpr time::milliseconds DEFAULT_DATA_FRESHNESS_PERIOD = 1_s;
constexpr time::seconds REQUEST_VALIDITY_PERIOD_NOT_BEFORE_GRACE_PERIOD = 120_s;

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

void
CaModule::registerPrefix()
{
  Name prefix = m_config.caProfile.caPrefix;
  prefix.append("CA");

  ndn::security::pib::Identity identity;
  try {
    identity = m_keyChain.getPib().getDefaultIdentity();
  }
  catch (const ndn::security::Pib::Error&) {
    identity = m_keyChain.getPib().getIdentity(m_config.caProfile.caPrefix);
  }

  m_registeredPrefixes.emplace_back(m_face.registerPrefix(prefix,
    [&] (const Name& name) {
      // register INFO RDR metadata prefix
      const auto& metaDataComp = ndn::MetadataObject::getKeywordComponent();
      auto filterId = m_face.setInterestFilter(Name(name).append("INFO").append(metaDataComp),
                                               [this] (auto&&, const auto& i) { onCaProfileDiscovery(i); });
      m_interestFilters.emplace_back(std::move(filterId));

      // register PROBE prefix
      filterId = m_face.setInterestFilter(Name(name).append("PROBE"),
                                          [this] (auto&&, const auto& i) { onProbe(i); });
      m_interestFilters.emplace_back(std::move(filterId));

      // register NEW prefix
      filterId = m_face.setInterestFilter(Name(name).append("NEW"),
                                          [this] (auto&&, const auto& i) { onNewRenewRevoke(i, RequestType::NEW); });
      m_interestFilters.emplace_back(std::move(filterId));

      // register CHALLENGE prefix
      filterId = m_face.setInterestFilter(Name(name).append("CHALLENGE"),
                                          [this] (auto&&, const auto& i) { onChallenge(i); });
      m_interestFilters.emplace_back(std::move(filterId));

      // register REVOKE prefix
      filterId = m_face.setInterestFilter(Name(name).append("REVOKE"),
                                          [this] (auto&&, const auto& i) { onNewRenewRevoke(i, RequestType::REVOKE); });
      m_interestFilters.emplace_back(std::move(filterId));

      NDN_LOG_TRACE("Prefix " << name << " registered successfully");
    },
    [] (auto&&, const auto& reason) {
      NDN_THROW(std::runtime_error("Failed to register prefix: " + reason));
    },
    ndn::signingByIdentity(identity)));
}

const Data&
CaModule::getCaProfileData()
{
  if (m_profileData == nullptr) {
    auto key = m_keyChain.getPib().getIdentity(m_config.caProfile.caPrefix).getDefaultKey();
    Block content = infotlv::encodeDataContent(m_config.caProfile, key.getDefaultCertificate());

    Name infoPacketName(m_config.caProfile.caPrefix);
    auto segmentComp = Name::Component::fromSegment(0);
    infoPacketName.append("CA").append("INFO").appendVersion().append(segmentComp);
    m_profileData = std::make_unique<Data>(infoPacketName);
    m_profileData->setFreshnessPeriod(DEFAULT_DATA_FRESHNESS_PERIOD);
    m_profileData->setFinalBlock(segmentComp);
    m_profileData->setContent(content);

    m_keyChain.sign(*m_profileData, signingByIdentity(m_config.caProfile.caPrefix));
  }
  return *m_profileData;
}

void
CaModule::onCaProfileDiscovery(const Interest&)
{
  NDN_LOG_TRACE("Received CA profile metadata discovery Interest");

  const auto& profileDataName = getCaProfileData().getName();
  ndn::MetadataObject metadata;
  metadata.setVersionedName(profileDataName.getPrefix(-1));
  Name discoveryInterestName(profileDataName.getPrefix(-2));
  discoveryInterestName.append(ndn::MetadataObject::getKeywordComponent());
  m_face.put(metadata.makeData(discoveryInterestName, m_keyChain, signingByIdentity(m_config.caProfile.caPrefix)));

  NDN_LOG_TRACE("Sent CA profile metadata");
}

void
CaModule::onProbe(const Interest& request)
{
  // PROBE naming convention: /<CA-Prefix>/CA/PROBE/<ParametersSha256Digest>
  NDN_LOG_TRACE("Received PROBE request");

  // process PROBE request: collect probe parameters
  std::multimap<std::string, std::string> parameters;
  try {
    parameters = probetlv::decodeApplicationParameters(request.getApplicationParameters());
  }
  catch (const std::exception& e) {
    NDN_LOG_ERROR("Cannot decode PROBE parameters: " << e.what());
    return;
  }

  // collect redirections
  std::vector<ndn::Name> redirectionNames;
  for (const auto& item : m_config.redirection) {
    if (item.second->isRedirecting(parameters)) {
      redirectionNames.push_back(item.first->getFullName());
    }
  }

  // collect name assignments
  std::vector<ndn::PartialName> availableComponents;
  for (const auto& item : m_config.nameAssignmentFuncs) {
    auto names = item->assignName(parameters);
    availableComponents.insert(availableComponents.end(), names.begin(), names.end());
  }

  if (availableComponents.empty() && redirectionNames.empty()) {
    NDN_LOG_TRACE("Cannot generate available names");
    m_face.put(makeErrorPacket(request.getName(), ErrorCode::INVALID_PARAMETER,
                               "Cannot generate available names from parameters provided."));
    return;
  }

  std::vector<Name> availableNames;
  availableNames.reserve(availableComponents.size());
  for (const auto& component : availableComponents) {
    availableNames.push_back(Name(m_config.caProfile.caPrefix).append(component));
  }

  Data result(request.getName());
  result.setFreshnessPeriod(DEFAULT_DATA_FRESHNESS_PERIOD);
  result.setContent(probetlv::encodeDataContent(availableNames, m_config.caProfile.maxSuffixLength,
                                                redirectionNames));
  m_keyChain.sign(result, signingByIdentity(m_config.caProfile.caPrefix));
  m_face.put(result);
  NDN_LOG_TRACE("Sent PROBE response");
}

void
CaModule::onNewRenewRevoke(const Interest& request, RequestType requestType)
{
  // NEW naming convention: /<CA-Prefix>/CA/NEW/<ParametersSha256Digest>
  // REVOKE naming convention: /<CA-Prefix>/CA/REVOKE/<ParametersSha256Digest>
  NDN_LOG_TRACE("Received " << requestType << " request");

  // verify ca cert validity
  auto caCert = m_keyChain.getPib()
                          .getIdentity(m_config.caProfile.caPrefix)
                          .getDefaultKey()
                          .getDefaultCertificate();
  if (!caCert.isValid()) {
    NDN_LOG_ERROR("Server certificate invalid/expired");
    m_face.put(makeErrorPacket(request.getName(), ErrorCode::BAD_VALIDITY_PERIOD,
                               "Server certificate invalid/expired"));
    return;
  }

  // get ECDH pub key and cert request
  const auto& paramsBlock = request.getApplicationParameters();
  std::vector<uint8_t> ecdhPub;
  std::shared_ptr<Certificate> clientCert;
  try {
    requesttlv::decodeApplicationParameters(paramsBlock, requestType, ecdhPub, clientCert);
  }
  catch (const std::exception& e) {
    if (!paramsBlock.hasValue()) {
      NDN_LOG_ERROR("Empty parameters in request");
      m_face.put(makeErrorPacket(request.getName(), ErrorCode::INVALID_PARAMETER,
                                 "Malformed request parameters."));
    }
    else {
      NDN_LOG_ERROR("Cannot decode request parameters: " << e.what());
      m_face.put(makeErrorPacket(request.getName(), ErrorCode::INVALID_PARAMETER,
                                 "Malformed request parameters."));
    }
    return;
  }

  if (ecdhPub.empty()) {
    NDN_LOG_ERROR("Empty ECDH public key in request parameters");
    m_face.put(makeErrorPacket(request.getName(), ErrorCode::INVALID_PARAMETER,
                               "Malformed request parameters."));
    return;
  }

  // verify identity name
  if (!Certificate::isValidName(clientCert->getName()) ||
      !m_config.caProfile.caPrefix.isPrefixOf(clientCert->getIdentity()) ||
      clientCert->getIdentity().size() <= m_config.caProfile.caPrefix.size()) {
    NDN_LOG_ERROR("Invalid certificate name requested: " << clientCert->getName());
    m_face.put(makeErrorPacket(request.getName(), ErrorCode::NAME_NOT_ALLOWED,
                               "Invalid certificate name requested."));
    return;
  }
  if (m_config.caProfile.maxSuffixLength) {
    if (clientCert->getIdentity().size() > m_config.caProfile.caPrefix.size() + *m_config.caProfile.maxSuffixLength) {
      NDN_LOG_ERROR("Invalid certificate name requested: " << clientCert->getName());
      m_face.put(makeErrorPacket(request.getName(), ErrorCode::NAME_NOT_ALLOWED,
                                 "Invalid certificate name requested."));
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
      NDN_LOG_ERROR("Invalid validity period requested");
      m_face.put(makeErrorPacket(request.getName(), ErrorCode::BAD_VALIDITY_PERIOD,
                                 "Invalid validity period requested."));
      return;
    }

    // verify signatures
    if (!ndn::security::verifySignature(*clientCert, *clientCert)) {
      NDN_LOG_ERROR("Invalid signature in the self-signed certificate");
      m_face.put(makeErrorPacket(request.getName(), ErrorCode::BAD_SIGNATURE,
                                 "Invalid signature in the self-signed certificate."));
      return;
    }
    if (!ndn::security::verifySignature(request, *clientCert)) {
      NDN_LOG_ERROR("Invalid signature in the Interest packet");
      m_face.put(makeErrorPacket(request.getName(), ErrorCode::BAD_SIGNATURE,
                                 "Invalid signature in the Interest packet."));
      return;
    }
  }
  else if (requestType == RequestType::REVOKE) {
    // verify cert is from this CA
    if (!ndn::security::verifySignature(*clientCert, caCert)) {
      NDN_LOG_ERROR("Invalid signature in the certificate to revoke");
      m_face.put(makeErrorPacket(request.getName(), ErrorCode::BAD_SIGNATURE,
                                 "Invalid signature in the certificate to revoke."));
      return;
    }
  }

  // derive server's ECDH pub key
  ECDHState ecdh;
  std::vector<uint8_t> sharedSecret;
  try {
    sharedSecret = ecdh.deriveSecret(ecdhPub);
  }
  catch (const std::exception& e) {
    NDN_LOG_ERROR("Cannot derive a shared secret using the provided ECDH public key: " << e.what());
    m_face.put(makeErrorPacket(request.getName(), ErrorCode::INVALID_PARAMETER,
                               "Cannot derive a shared secret using the provided ECDH public key."));
    return;
  }

  // create new request instance
  uint8_t requestIdData[32];
  Block certNameTlv = clientCert->getName().wireEncode();
  try {
    hmacSha256(certNameTlv.data(), certNameTlv.size(), m_requestIdGenKey, 32, requestIdData);
  }
  catch (const std::runtime_error& e) {
    NDN_LOG_ERROR("Error computing the request ID: " << e.what());
    m_face.put(makeErrorPacket(request.getName(), ErrorCode::INVALID_PARAMETER,
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
    NDN_LOG_ERROR("Duplicate request ID " << ndn::toHex(id));
    m_face.put(makeErrorPacket(request.getName(), ErrorCode::INVALID_PARAMETER, "Duplicate request ID."));
    return;
  }

  Data result(request.getName());
  result.setFreshnessPeriod(DEFAULT_DATA_FRESHNESS_PERIOD);
  result.setContent(requesttlv::encodeDataContent(ecdh.getSelfPubKey(),
                                                  salt, requestState.requestId,
                                                  m_config.caProfile.supportedChallenges));
  m_keyChain.sign(result, signingByIdentity(m_config.caProfile.caPrefix));
  m_face.put(result);
  NDN_LOG_TRACE("Sent " << requestType << " response");

  if (m_statusUpdateCallback) {
    m_statusUpdateCallback(requestState);
  }
}

void
CaModule::onChallenge(const Interest& request)
{
  NDN_LOG_TRACE("Received CHALLENGE request");

  // get certificate request state
  auto requestState = getCertificateRequest(request);
  if (requestState == nullptr) {
    NDN_LOG_ERROR("No pending certificate request found");
    m_face.put(makeErrorPacket(request.getName(), ErrorCode::INVALID_PARAMETER,
                               "No pending certificate request found."));
    return;
  }

  // verify signature
  if (!ndn::security::verifySignature(request, requestState->cert)) {
    NDN_LOG_ERROR("Invalid signature in the Interest packet");
    m_face.put(makeErrorPacket(request.getName(), ErrorCode::BAD_SIGNATURE,
                               "Invalid signature in the Interest packet."));
    return;
  }

  // decrypt the parameters
  ndn::Buffer plaintext;
  try {
    plaintext = decodeBlockWithAesGcm128(request.getApplicationParameters(), requestState->encryptionKey.data(),
                                         requestState->requestId.data(), requestState->requestId.size(),
                                         requestState->decryptionIv, requestState->encryptionIv);
  }
  catch (const std::exception& e) {
    NDN_LOG_ERROR("Cannot decrypt challenge parameters: " << e.what());
    m_storage->deleteRequest(requestState->requestId);
    m_face.put(makeErrorPacket(request.getName(), ErrorCode::INVALID_PARAMETER,
                               "Malformed challenge parameters."));
    return;
  }
  if (plaintext.empty()) {
    NDN_LOG_ERROR("Empty parameters after decryption");
    m_storage->deleteRequest(requestState->requestId);
    m_face.put(makeErrorPacket(request.getName(), ErrorCode::INVALID_PARAMETER,
                               "Malformed challenge parameters."));
    return;
  }

  auto paramTLV = ndn::makeBinaryBlock(tlv::EncryptedPayload, plaintext);
  paramTLV.parse();

  // load the corresponding challenge module
  std::string challengeType = readString(paramTLV.get(tlv::SelectedChallenge));
  auto challenge = ChallengeModule::createChallengeModule(challengeType);
  if (challenge == nullptr) {
    NDN_LOG_TRACE("Unsupported challenge type: " << challengeType);
    m_storage->deleteRequest(requestState->requestId);
    m_face.put(makeErrorPacket(request.getName(), ErrorCode::INVALID_PARAMETER,
                               "Unsupported challenge type."));
    return;
  }

  NDN_LOG_TRACE("Using challenge: " << challengeType);
  auto [errCode, errMsg] = challenge->handleChallengeRequest(paramTLV, *requestState);
  if (errCode != ErrorCode::NO_ERROR) {
    m_storage->deleteRequest(requestState->requestId);
    m_face.put(makeErrorPacket(request.getName(), errCode, errMsg));
    return;
  }

  Block payload;
  if (requestState->status == Status::PENDING) {
    NDN_LOG_TRACE("Challenge succeeded");
    if (requestState->requestType == RequestType::NEW ||
        requestState->requestType == RequestType::RENEW) {
      auto issuedCert = issueCertificate(*requestState);
      requestState->cert = issuedCert;
      requestState->status = Status::SUCCESS;
      m_storage->deleteRequest(requestState->requestId);
      payload = challengetlv::encodeDataContent(*requestState, issuedCert.getName(),
                                                m_config.caProfile.forwardingHint);
    }
    else if (requestState->requestType == RequestType::REVOKE) {
      // TODO: where is the code to revoke?
      requestState->status = Status::SUCCESS;
      m_storage->deleteRequest(requestState->requestId);
      payload = challengetlv::encodeDataContent(*requestState);
    }
  }
  else {
    payload = challengetlv::encodeDataContent(*requestState);
    m_storage->updateRequest(*requestState);
    NDN_LOG_TRACE("Challenge continues");
  }

  Data result(request.getName());
  result.setFreshnessPeriod(DEFAULT_DATA_FRESHNESS_PERIOD);
  result.setContent(payload);
  m_keyChain.sign(result, signingByIdentity(m_config.caProfile.caPrefix));
  m_face.put(result);
  NDN_LOG_TRACE("Sent CHALLENGE response");

  if (m_statusUpdateCallback) {
    m_statusUpdateCallback(*requestState);
  }
}

std::unique_ptr<RequestState>
CaModule::getCertificateRequest(const Interest& request)
{
  Name::Component component;
  try {
    component = request.getName().at(m_config.caProfile.caPrefix.size() + 2);
  }
  catch (const std::exception& e) {
    NDN_LOG_ERROR("Cannot extract request ID from Interest name: " << e.what());
    return nullptr;
  }

  RequestId requestId;
  if (component.value_size() != requestId.size()) {
    NDN_LOG_ERROR("Invalid request ID of length " << component.value_size());
    return nullptr;
  }
  std::memcpy(requestId.data(), component.value(), requestId.size());

  try {
    NDN_LOG_TRACE("Retrieving request with ID " << ndn::toHex(requestId));
    return std::make_unique<RequestState>(m_storage->getRequest(requestId));
  }
  catch (const std::exception& e) {
    NDN_LOG_ERROR("Cannot fetch certificate request record from storage: " << e.what());
    return nullptr;
  }
}

Certificate
CaModule::issueCertificate(const RequestState& requestState)
{
  ndn::security::MakeCertificateOptions opts;
  opts.issuerId = Name::Component("NDNCERT");
  opts.validity = requestState.cert.getValidityPeriod();
  auto newCert = m_keyChain.makeCertificate(requestState.cert,
                                            signingByIdentity(m_config.caProfile.caPrefix), opts);
  NDN_LOG_TRACE("Certificate issued: " << newCert);
  return newCert;
}

Data
CaModule::makeErrorPacket(const Name& name, ErrorCode errorCode, std::string_view errorInfo)
{
  Data result(name);
  result.setFreshnessPeriod(DEFAULT_DATA_FRESHNESS_PERIOD);
  result.setContent(errortlv::encodeDataContent(errorCode, errorInfo));
  m_keyChain.sign(result, signingByIdentity(m_config.caProfile.caPrefix));
  return result;
}

} // namespace ndncert::ca
