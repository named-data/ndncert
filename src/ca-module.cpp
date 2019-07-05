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

#include "ca-module.hpp"
#include "challenge-module.hpp"
#include "logging.hpp"
#include "crypto-support/enc-tlv.hpp"
#include <ndn-cxx/util/io.hpp>
#include <ndn-cxx/security/verification-helpers.hpp>
#include <ndn-cxx/security/signing-helpers.hpp>
#include <ndn-cxx/util/random.hpp>

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
  Name localhopProbePrefix("/localhop/CA/PROBE/INFO");
  auto prefixId = m_face.setInterestFilter(InterestFilter(localhopProbePrefix),
                                           bind(&CaModule::onProbe, this, _2),
                                           bind(&CaModule::onRegisterFailed, this, _2));
  m_registeredPrefixHandles.push_back(prefixId);
  _LOG_TRACE("Prefix " << localhopProbePrefix << " got registered");

  // register prefixes
  Name prefix = m_config.m_caName;
  prefix.append("CA");

  prefixId = m_face.registerPrefix(prefix,
    [&] (const Name& name) {
      // register PROBE prefix
      auto filterId = m_face.setInterestFilter(Name(name).append("_PROBE"),
                                               bind(&CaModule::onProbe, this, _2));
      m_interestFilterHandles.push_back(filterId);

      // register NEW prefix
      filterId = m_face.setInterestFilter(Name(name).append("_NEW"),
                                          bind(&CaModule::onNew, this, _2));
      m_interestFilterHandles.push_back(filterId);

      // register SELECT prefix
      filterId = m_face.setInterestFilter(Name(name).append("_CHALLENGE"),
                                          bind(&CaModule::onChallenge, this, _2));
      m_interestFilterHandles.push_back(filterId);

      // register DOWNLOAD prefix
      filterId = m_face.setInterestFilter(Name(name).append("_DOWNLOAD"),
                                          bind(&CaModule::onDownload, this, _2));
      m_interestFilterHandles.push_back(filterId);
      _LOG_TRACE("Prefix " << name << " got registered");
    },
    bind(&CaModule::onRegisterFailed, this, _2));
  m_registeredPrefixHandles.push_back(prefixId);
}

bool
CaModule::setProbeHandler(const ProbeHandler& handler)
{
  m_config.m_probeHandler = handler;
  return false;
}

bool
CaModule::setStatusUpdateCallback(const StatusUpdateCallback& onUpdateCallback)
{
  m_config.m_statusUpdateCallback = onUpdateCallback;
  return false;
}

void
CaModule::onProbe(const Interest& request)
{
  // PROBE Naming Convention: /<CA-Prefix>/CA/PROBE/[ParametersSha256DigestComponent|INFO]
  _LOG_TRACE("Receive PROBE request");
  JsonSection contentJson;

  // process PROBE INFO requests
  if (readString(request.getName().at(-1)) == "INFO") {
    contentJson = genProbeResponseJson();
  }
  else {
    // if not a PROBE INFO, find an available name
    std::string availableId = "";
    const auto& parameterJson = jsonFromBlock(request.getApplicationParameters());
    if (parameterJson.empty()) {
      _LOG_ERROR("Empty JSON obtained from the Interest parameter.");
      return;
    }
    //std::string probeInfoStr = parameterJson.get(JSON_CLIENT_PROBE_INFO, "");
    if (m_config.m_probeHandler) {
      try {
        availableId = m_config.m_probeHandler(parameterJson);
      }
      catch (const std::exception& e) {
        _LOG_TRACE("Cannot find PROBE input from PROBE parameters: " << e.what());
        return;
      }
    }
    else {
      // if there is no app-specified name lookup, use a random name id
      availableId = std::to_string(random::generateSecureWord64());
    }
    Name newIdentityName = m_config.m_caName;
    newIdentityName.append(availableId);
    _LOG_TRACE("Handle PROBE: generate an identity " << newIdentityName);
    contentJson = genProbeResponseJson(newIdentityName.toUri(), m_config.m_probe, parameterJson);
  }

  Data result;
  result.setName(request.getName());
  result.setContent(dataContentFromJson(contentJson));
  result.setFreshnessPeriod(DEFAULT_DATA_FRESHNESS_PERIOD);
  m_keyChain.sign(result, signingByIdentity(m_config.m_caName));
  m_face.put(result);
  _LOG_TRACE("Handle PROBE: send out the PROBE response");
}

void
CaModule::onNew(const Interest& request)
{
  // NEW Naming Convention: /<CA-prefix>/CA/NEW/[SignedInterestParameters_Digest]
  // get ECDH pub key and cert request
  const auto& parameterJson = jsonFromBlock(request.getApplicationParameters());
  if (parameterJson.empty()) {
    _LOG_ERROR("Empty JSON obtained from the Interest parameter.");
    return;
  }
  std::string peerKeyBase64 = parameterJson.get(JSON_CLIENT_ECDH, "");
  if (peerKeyBase64 == "") {
    _LOG_ERROR("Empty JSON_CLIENT_ECDH obtained from the Interest parameter.");
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

  // parse certificate request
  std::string certRequestStr = parameterJson.get(JSON_CLIENT_CERT_REQ, "");
  shared_ptr<security::v2::Certificate> clientCert = nullptr;
  try {
    std::stringstream ss(certRequestStr);
    clientCert = io::load<security::v2::Certificate>(ss);
  }
  catch (const std::exception& e) {
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
  if (expectedPeriod.second > currentTime + m_config.m_validityPeriod ||
      expectedPeriod.second <= expectedPeriod.first) {
    _LOG_ERROR("Client requests an invalid validity period or a notAfter timepoint beyond the allowed time period.");
    return;
  }

  // parse probe token if any
  std::string probeTokenStr = parameterJson.get("probe-token", "");
  shared_ptr<Data> probeToken = nullptr;
  if (probeTokenStr != "") {
    try {
      std::stringstream ss(probeTokenStr);
      probeToken = io::load<Data>(ss);
    }
    catch (const std::exception& e) {
      _LOG_ERROR("Unrecognized probe token: " << e.what());
      return;
    }
  }
  if (probeToken == nullptr && m_config.m_probe != "") {
    // the CA requires PROBE before NEW
    _LOG_ERROR("CA requires PROBE but no PROBE token is found in NEW Interest.");
    return;
  }
  else if (probeToken != nullptr) {
    // check whether the carried probe token is a PROBE Data packet
    Name prefix = m_config.m_caName;
    prefix.append("CA").append("_PROBE");
    if (!prefix.isPrefixOf(probeToken->getName())) {
      _LOG_ERROR("Carried PROBE token is not a valid PROBE Data packet.");
      return;
    }
  }

  // verify the self-signed certificate, the request, and the token
  if (!m_config.m_caName.isPrefixOf(clientCert->getName()) // under ca prefix
      || !security::v2::Certificate::isValidName(clientCert->getName()) // is valid cert name
      || clientCert->getName().size() != m_config.m_caName.size() + IS_SUBNAME_MIN_OFFSET) {
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
  if (probeToken != nullptr) {
    const auto& pib = m_keyChain.getPib();
    const auto& key = pib.getIdentity(m_config.m_caName).getDefaultKey();
    const auto& caCert = key.getDefaultCertificate();
    if (!security::verifySignature(*probeToken, caCert)) {
      _LOG_ERROR("PROBE Token with bad signature.");
      return;
    }
  }

  // create new request instance
  std::string requestId = std::to_string(random::generateWord64());
  CertificateRequest certRequest(m_config.m_caName, requestId, STATUS_BEFORE_CHALLENGE, *clientCert);
  if (probeToken != nullptr) {
    certRequest.setProbeToken(probeToken);
  }
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
  result.setContent(dataContentFromJson(genNewResponseJson(myEcdhPubKeyBase64,
                                                           std::to_string(saltInt),
                                                           certRequest,
                                                           m_config.m_supportedChallenges)));
  m_keyChain.sign(result, signingByIdentity(m_config.m_caName));
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
  Buffer paramJsonPayload;
  try {
    paramJsonPayload = parseEncBlock(m_aesKey, sizeof(m_aesKey),
                                     request.getApplicationParameters());
  }
  catch (const std::exception& e) {
    _LOG_ERROR("Cannot successfully decrypt the Interest parameters: " << e.what());
    return;
  }
  if (paramJsonPayload.size() == 0) {
    _LOG_ERROR("Got an empty buffer from content decryption.");
    return;
  }
  std::string paramJsonStr((const char*)paramJsonPayload.data(), paramJsonPayload.size());
  std::istringstream ss(paramJsonStr);
  JsonSection paramJson;
  try {
    boost::property_tree::json_parser::read_json(ss, paramJson);
  }
  catch (const std::exception& e) {
    _LOG_ERROR("Cannot read JSON from decrypted content: " << e.what());
    return;
  }

  // load the corresponding challenge module
  std::string challengeType = paramJson.get<std::string>(JSON_CLIENT_SELECTED_CHALLENGE);
  auto challenge = ChallengeModule::createChallengeModule(challengeType);
  JsonSection contentJson;
  if (challenge == nullptr) {
    _LOG_TRACE("Unrecognized challenge type " << challengeType);
    certRequest.m_status = STATUS_FAILURE;
    certRequest.m_challengeStatus = CHALLENGE_STATUS_UNKNOWN_CHALLENGE;
    contentJson = genChallengeResponseJson(certRequest);
  }
  else {
    _LOG_TRACE("CHALLENGE module to be load: " << challengeType);
    // let challenge module handle the request
    challenge->handleChallengeRequest(paramJson, certRequest);
    if (certRequest.m_status == STATUS_FAILURE) {
      // if challenge failed
      m_storage->deleteRequest(certRequest.m_requestId);
      contentJson = genChallengeResponseJson(certRequest);
      _LOG_TRACE("Challenge failed");
    }
    else if (certRequest.m_status == STATUS_PENDING) {
      // if challenge succeeded
      auto issuedCert = issueCertificate(certRequest);
      certRequest.m_cert = issuedCert;
      certRequest.m_status = STATUS_SUCCESS;
      try {
        m_storage->addCertificate(certRequest.m_requestId, issuedCert);
        m_storage->deleteRequest(certRequest.m_requestId);
        _LOG_TRACE("New Certificate Issued " << issuedCert.getName());
      }
      catch (const std::exception& e) {
        _LOG_ERROR("Cannot add issued cert and remove the request: " << e.what());
        return;
      }
      if (m_config.m_statusUpdateCallback) {
        m_config.m_statusUpdateCallback(certRequest);
      }
      contentJson = genChallengeResponseJson(certRequest);
      contentJson.add(JSON_CA_CERT_ID, readString(issuedCert.getName().at(-1)));
      _LOG_TRACE("Challenge succeeded. Certificate has been issued");
    }
    else {
      try {
        m_storage->updateRequest(certRequest);
      }
      catch (const std::exception& e) {
        _LOG_TRACE("Cannot update request instance: " << e.what());
        return;
      }
      contentJson = genChallengeResponseJson(certRequest);
      _LOG_TRACE("No failure no success. Challenge moves on");
    }
  }

  Data result;
  result.setName(request.getName());
  result.setFreshnessPeriod(DEFAULT_DATA_FRESHNESS_PERIOD);

  // encrypt the content
  std::stringstream ss2;
  boost::property_tree::write_json(ss2, contentJson);
  auto payload = ss2.str();
  auto contentBlock = genEncBlock(tlv::Content, m_aesKey, sizeof(m_aesKey),
                                  (const uint8_t*)payload.c_str(), payload.size());
  result.setContent(contentBlock);
  m_keyChain.sign(result, signingByIdentity(m_config.m_caName));
  m_face.put(result);

  if (m_config.m_statusUpdateCallback) {
    m_config.m_statusUpdateCallback(certRequest);
  }
}

void
CaModule::onDownload(const Interest& request)
{
  auto requestId = readString(request.getName().at(-1));
  security::v2::Certificate signedCert;
  try {
    signedCert = m_storage->getCertificate(requestId);
  }
  catch (const std::exception& e) {
    _LOG_ERROR("Cannot read signed cert " << requestId << " from CA's storage: " << e.what());
    return;
  }
  Data result;
  result.setName(request.getName());
  result.setFreshnessPeriod(DEFAULT_DATA_FRESHNESS_PERIOD);
  result.setContent(signedCert.wireEncode());
  m_keyChain.sign(result, signingByIdentity(m_config.m_caName));
  m_face.put(result);
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
                                    m_config.m_caName, signatureInfo);
  newCert.setFreshnessPeriod(m_config.m_freshnessPeriod);

  m_keyChain.sign(newCert, signingInfo);
  _LOG_TRACE("new cert got signed" << newCert);
  return newCert;
}

CertificateRequest
CaModule::getCertificateRequest(const Interest& request)
{
  std::string requestId = "";
  CertificateRequest certRequest;
  try {
    requestId = readString(request.getName().at(m_config.m_caName.size() + 2));
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

/**
 * @brief Generate JSON file to response PROBE insterest
 *
 * PROBE response JSON format:
 * {
 *   "name": "@p identifier"
 * }
 */
const JsonSection
CaModule::genProbeResponseJson(const Name& identifier, const std::string& m_probe, const JsonSection& parameterJson)
{
  std::vector<std::string> fields;
  std::string delimiter = ":";
  size_t last = 0;
  size_t next = 0;
  while ((next = m_probe.find(delimiter, last)) != std::string::npos) {
    fields.push_back(m_probe.substr(last, next - last));
    last = next + 1;
  }
  fields.push_back(m_probe.substr(last));
  JsonSection root;

  for (size_t i = 0; i < fields.size(); ++i) {
    root.put(fields.at(i), parameterJson.get(fields.at(i), ""));
  }

  root.put(JSON_CA_NAME, identifier.toUri());
  return root;
}

/**
 * @brief Generate JSON file to response NEW interest
 *
 * Target JSON format:
 * {
 *   "ecdh-pub": "@p echdPub",
 *   "salt": "@p salt"
 *   "request-id": "@p requestId",
 *   "status": "@p status",
 *   "challenges": [
 *     {
 *       "challenge-id": ""
 *     },
 *     {
 *       "challenge-id": ""
 *     },
 *     ...
 *   ]
 * }
 */
const JsonSection
CaModule::genProbeResponseJson()
{
  JsonSection root;
  // ca-prefix
  Name caName = m_config.m_caName;
  root.put("ca-prefix", caName.toUri());

  // ca-info
  const auto& pib = m_keyChain.getPib();
  const auto& identity = pib.getIdentity(m_config.m_caName);
  const auto& cert = identity.getDefaultKey().getDefaultCertificate();
  std::string caInfo = "";
  if (m_config.m_caInfo == "") {
    caInfo = "Issued by " + cert.getSignature().getKeyLocator().getName().toUri();
  }
  else {
    caInfo = m_config.m_caInfo;
  }
  root.put("ca-info", caInfo);

  // probe
  root.put("probe", m_config.m_probe);

  // certificate
  std::stringstream ss;
  io::save(cert, ss);
  root.put("certificate", ss.str());
  return root;
}

const JsonSection
CaModule::genNewResponseJson(const std::string& ecdhKey, const std::string& salt,
                             const CertificateRequest& request,
                             const std::list<std::string>& challenges)
{
  JsonSection root;
  JsonSection challengesSection;
  root.put(JSON_CA_ECDH, ecdhKey);
  root.put(JSON_CA_SALT, salt);
  root.put(JSON_CA_REQUEST_ID, request.m_requestId);
  root.put(JSON_CA_STATUS, std::to_string(request.m_status));

  for (const auto& entry : challenges) {
    JsonSection challenge;
    challenge.put(JSON_CA_CHALLENGE_ID, entry);
    challengesSection.push_back(std::make_pair("", challenge));
  }
  root.add_child(JSON_CA_CHALLENGES, challengesSection);
  return root;
}

const JsonSection
CaModule::genChallengeResponseJson(const CertificateRequest& request)
{
  JsonSection root;
  JsonSection challengesSection;
  root.put(JSON_CA_STATUS, request.m_status);
  root.put(JSON_CHALLENGE_STATUS, request.m_challengeStatus);
  root.put(JSON_CHALLENGE_REMAINING_TRIES, std::to_string(request.m_remainingTries));
  root.put(JSON_CHALLENGE_REMAINING_TIME, std::to_string(request.m_remainingTime));
  return root;
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
