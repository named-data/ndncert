/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/**
 * Copyright (c) 2017, Regents of the University of California.
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
#include <ndn-cxx/face.hpp>
#include <ndn-cxx/security/verification-helpers.hpp>
#include <ndn-cxx/security/signing-helpers.hpp>

namespace ndn {
namespace ndncert {

_LOG_INIT(ndncert.ca);

CaModule::CaModule(Face& face, security::v2::KeyChain& keyChain,
                   const std::string& configPath, const std::string& storageType)
  : m_face(face)
  , m_keyChain(keyChain)
{
  // load the config and create storage
  m_config.load(configPath);
  m_storage = CaStorage::createCaStorage(storageType);

  // set default handler and callback
  m_probeHandler = [&] (const std::string& probeInfo) {
    return probeInfo;
  };
  m_requestUpdateCallback = [&] (const CertificateRequest& CertRequest) {
    // do nothing
  };

  // register prefix
  for (const auto& item : m_config.m_caItems) {
    Name prefix = item.m_caName;
    prefix.append("CA");
    try {
      const RegisteredPrefixId* prefixId = m_face.registerPrefix(prefix,
        [&] (const Name& name) {
          const InterestFilterId* filterId = m_face.setInterestFilter(Name(name).append("_PROBE"),
                                                                      bind(&CaModule::handleProbe, this, _2, item));
          m_interestFilterIds.push_back(filterId);

          filterId = m_face.setInterestFilter(Name(name).append("_NEW"),
                                              bind(&CaModule::handleNew, this, _2, item));
          m_interestFilterIds.push_back(filterId);

          filterId = m_face.setInterestFilter(Name(name).append("_SELECT"),
                                              bind(&CaModule::handleSelect, this, _2, item));
          m_interestFilterIds.push_back(filterId);

          filterId = m_face.setInterestFilter(Name(name).append("_VALIDATE"),
                                              bind(&CaModule::handleValidate, this, _2, item));
          m_interestFilterIds.push_back(filterId);

          filterId = m_face.setInterestFilter(Name(name).append("_STATUS"),
                                              bind(&CaModule::handleStatus, this, _2, item));
          m_interestFilterIds.push_back(filterId);

          filterId = m_face.setInterestFilter(Name(name).append("_DOWNLOAD"),
                                              bind(&CaModule::handleDownload, this, _2, item));
          m_interestFilterIds.push_back(filterId);

          _LOG_TRACE("Prefix " << name << " got registered");
        },
        bind(&CaModule::onRegisterFailed, this, _2));
      m_registeredPrefixIds.push_back(prefixId);
    }
    catch (const std::exception& e) {
      _LOG_TRACE("Error: " << e.what());
    }
  }
}

CaModule::~CaModule()
{
  for (auto prefixId : m_interestFilterIds) {
    m_face.unsetInterestFilter(prefixId);
  }
  for (auto prefixId : m_registeredPrefixIds) {
    m_face.unregisterPrefix(prefixId, nullptr, nullptr);
  }
}

void
CaModule::handleProbe(const Interest& request, const CaItem& caItem)
{
  // PROBE Naming Convention: /CA-prefix/CA/_PROBE/<Probe Information>
  _LOG_TRACE("Handle PROBE request");

  std::string identifier;
  try {
    identifier = m_probeHandler(readString(request.getName().at(caItem.m_caName.size() + 2)));
  }
  catch (const std::exception& e) {
    _LOG_TRACE("Cannot generate identifier for PROBE request " << e.what());
    return;
  }
  Name identityName = caItem.m_caName;
  identityName.append(identifier);

  Data result;
  result.setName(request.getName());
  result.setContent(dataContentFromJson(genResponseProbeJson(identityName, "")));
  m_keyChain.sign(result, signingByCertificate(caItem.m_anchor));
  m_face.put(result);

  _LOG_TRACE("Handle PROBE: generate identity " << identityName);
}

void
CaModule::handleNew(const Interest& request, const CaItem& caItem)
{
  // NEW Naming Convention: /CA-prefix/CA/_NEW/<certificate-request>/[signature]
  _LOG_TRACE("Handle NEW request");

  security::v2::Certificate clientCert;
  try {
    clientCert.wireDecode(request.getName().at(caItem.m_caName.size() + 2).blockFromValue());
  }
  catch (const std::exception& e) {
    _LOG_TRACE("Unrecognized certificate request " << e.what());
    return;
  }
  std::string requestId = std::to_string(random::generateWord64());
  CertificateRequest certRequest(caItem.m_caName, requestId, clientCert);
  certRequest.setStatus(ChallengeModule::WAIT_SELECTION);
  try {
    m_storage->addRequest(certRequest);
  }
  catch (const std::exception& e) {
    _LOG_TRACE("Cannot add new request instance " << e.what());
    return;
  }

  Data result;
  result.setName(request.getName());
  result.setContent(dataContentFromJson(genResponseNewJson(requestId, certRequest.getStatus(),
                                                           caItem.m_supportedChallenges)));
  m_keyChain.sign(result, signingByCertificate(caItem.m_anchor));
  m_face.put(result);

  m_requestUpdateCallback(certRequest);
}

void
CaModule::handleSelect(const Interest& request, const CaItem& caItem)
{
  // SELECT Naming Convention: /CA-prefix/CA/_SELECT/{Request-ID JSON}/<ChallengeID>/
  // {Param JSON}/[Signature components]
  _LOG_TRACE("Handle SELECT request");

  CertificateRequest certRequest = getCertificateRequest(request, caItem.m_caName);
  if (certRequest.getRequestId().empty()) {
    return;
  }

  if (!security::verifySignature(request, certRequest.getCert())) {
    _LOG_TRACE("Error: Interest with bad signature.");
    return;
  }

  std::string challengeType;
  try {
    challengeType = readString(request.getName().at(caItem.m_caName.size() + 3));
  }
  catch (const std::exception& e) {
    _LOG_TRACE(e.what());
    return;
  }
  _LOG_TRACE("SELECT request choosing challenge " << challengeType);
  auto challenge = ChallengeModule::createChallengeModule(challengeType);
  if (challenge == nullptr) {
    _LOG_TRACE("Unrecognized challenge type " << challengeType);
    return;
  }
  JsonSection contentJson = challenge->handleChallengeRequest(request, certRequest);
  if (certRequest.getStatus() == ChallengeModule::FAILURE) {
    m_storage->deleteRequest(certRequest.getRequestId());
  }
  else {
    try {
      m_storage->updateRequest(certRequest);
    }
    catch (const std::exception& e) {
      _LOG_TRACE("Cannot update request instance " << e.what());
      return;
    }
  }

  Data result;
  result.setName(request.getName());
  result.setContent(dataContentFromJson(contentJson));
  m_keyChain.sign(result, signingByCertificate(caItem.m_anchor));
  m_face.put(result);

  m_requestUpdateCallback(certRequest);
}

void
CaModule::handleValidate(const Interest& request, const CaItem& caItem)
{
  // VALIDATE Naming Convention: /CA-prefix/CA/_VALIDATE/{Request-ID JSON}/<ChallengeID>/
  // {Param JSON}/[Signature components]
  _LOG_TRACE("Handle VALIDATE request");

  CertificateRequest certRequest = getCertificateRequest(request, caItem.m_caName);
  if (certRequest.getRequestId().empty()) {
    return;
  }

  if (!security::verifySignature(request, certRequest.getCert())) {
    _LOG_TRACE("Error: Interest with bad signature.");
    return;
  }

  std::string challengeType = certRequest.getChallengeType();
  auto challenge = ChallengeModule::createChallengeModule(challengeType);
  if (challenge == nullptr) {
    _LOG_TRACE("Unrecognized challenge type " << challengeType);
    return;
  }
  JsonSection contentJson = challenge->handleChallengeRequest(request, certRequest);
  if (certRequest.getStatus() == ChallengeModule::FAILURE) {
    m_storage->deleteRequest(certRequest.getRequestId());
  }
  else {
    try {
      m_storage->updateRequest(certRequest);
    }
    catch (const std::exception& e) {
      _LOG_TRACE("Cannot update request instance " << e.what());
      return;
    }
  }
  Data result;
  result.setName(request.getName());
  result.setContent(dataContentFromJson(contentJson));
  m_keyChain.sign(result, signingByCertificate(caItem.m_anchor));
  m_face.put(result);

  m_requestUpdateCallback(certRequest);

  if (certRequest.getStatus() == ChallengeModule::SUCCESS) {
    issueCertificate(certRequest, caItem);
  }
}

void
CaModule::handleStatus(const Interest& request, const CaItem& caItem)
{
  // STATUS Naming Convention: /CA-prefix/CA/_STATUS/{Request-ID JSON}/[Signature components]
  _LOG_TRACE("Handle STATUS request");

  CertificateRequest certRequest = getCertificateRequest(request, caItem.m_caName);
  if (certRequest.getRequestId().empty()) {
    return;
  }

  if (!security::verifySignature(request, certRequest.getCert())) {
    _LOG_TRACE("Error: Interest with bad signature.");
    return;
  }

  std::string challengeType = certRequest.getChallengeType();
  auto challenge = ChallengeModule::createChallengeModule(challengeType);
  if (challenge == nullptr) {
    _LOG_TRACE("Unrecognized challenge type " << challengeType);
    return;
  }
  JsonSection contentJson = challenge->handleChallengeRequest(request, certRequest);

  Data result;
  result.setName(request.getName());
  result.setContent(dataContentFromJson(contentJson));
  m_keyChain.sign(result, signingByCertificate(caItem.m_anchor));
  m_face.put(result);
}

void
CaModule::handleDownload(const Interest& request, const CaItem& caItem)
{
  // DOWNLOAD Naming Convention: /CA-prefix/CA/_DOWNLOAD/{Request-ID JSON}
  _LOG_TRACE("Handle DOWNLOAD request");

  JsonSection requestIdJson = jsonFromNameComponent(request.getName(), caItem.m_caName.size() + 2);
  std::string requestId = requestIdJson.get(JSON_REQUEST_ID, "");
  security::v2::Certificate signedCert;
  try {
    signedCert = m_storage->getCertificate(requestId);
  }
  catch (const std::exception& e) {
    _LOG_TRACE("Error: " << e.what());
    return;
  }

  Data result;
  result.setName(request.getName());
  result.setContent(signedCert.wireEncode());
  m_keyChain.sign(result, signingByCertificate(caItem.m_anchor));
  m_face.put(result);
}

void
CaModule::issueCertificate(const CertificateRequest& certRequest, const CaItem& caItem)
{
  Name certName = certRequest.getCert().getKeyName();
  certName.append("NDNCERT").appendVersion();
  security::v2::Certificate newCert;
  newCert.setName(certName);
  newCert.setContent(certRequest.getCert().getContent());
  SignatureInfo signatureInfo;
  security::ValidityPeriod period(time::system_clock::now(),
                                  time::system_clock::now() + caItem.m_validityPeriod);
  signatureInfo.setValidityPeriod(period);
  security::SigningInfo signingInfo(security::SigningInfo::SIGNER_TYPE_CERT,
                                    caItem.m_anchor, signatureInfo);
  newCert.setFreshnessPeriod(caItem.m_freshnessPeriod);

  m_keyChain.sign(newCert, signingInfo);
  try {
    m_storage->addCertificate(certRequest.getRequestId(), newCert);
    m_storage->deleteRequest(certRequest.getRequestId());
    _LOG_TRACE("New Certificate Issued " << certName);
  }
  catch (const std::exception& e) {
    _LOG_TRACE("Error: Cannot add issued cert and remove the request " << e.what());
    return;
  }
}

CertificateRequest
CaModule::getCertificateRequest(const Interest& request, const Name& caName)
{
  JsonSection requestIdJson = jsonFromNameComponent(request.getName(), caName.size() + 2);
  std::string requestId = requestIdJson.get(JSON_REQUEST_ID, "");
  CertificateRequest certRequest;
  try {
    certRequest = m_storage->getRequest(requestId);
  }
  catch (const std::exception& e) {
    _LOG_TRACE("Error: " << e.what());
  }
  return certRequest;
}

void
CaModule::onRegisterFailed(const std::string& reason)
{
  _LOG_TRACE("Error: failed to register prefix in local hub's daemon, REASON: " << reason);
}

Block
CaModule::dataContentFromJson(const JsonSection& jsonSection)
{
  std::stringstream ss;
  boost::property_tree::write_json(ss, jsonSection);
  return makeStringBlock(ndn::tlv::Content, ss.str());
}

JsonSection
CaModule::jsonFromNameComponent(const Name& name, int pos)
{
  std::string jsonString;
  try {
    jsonString = encoding::readString(name.at(pos));
  }
  catch (const std::exception& e) {
    _LOG_TRACE(e.what());
    return JsonSection();
  }
  std::istringstream ss(jsonString);
  JsonSection json;
  boost::property_tree::json_parser::read_json(ss, json);
  return json;
}

} // namespace ndncert
} // namespace ndn
