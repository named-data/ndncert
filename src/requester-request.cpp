/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2017-2022, Regents of the University of California.
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

#include "requester-request.hpp"

#include "challenge/challenge-module.hpp"
#include "detail/crypto-helpers.hpp"
#include "detail/challenge-encoder.hpp"
#include "detail/error-encoder.hpp"
#include "detail/info-encoder.hpp"
#include "detail/request-encoder.hpp"
#include "detail/probe-encoder.hpp"

#include <ndn-cxx/metadata-object.hpp>
#include <ndn-cxx/security/signing-helpers.hpp>
#include <ndn-cxx/security/transform/base64-encode.hpp>
#include <ndn-cxx/security/transform/buffer-source.hpp>
#include <ndn-cxx/security/transform/stream-sink.hpp>
#include <ndn-cxx/security/verification-helpers.hpp>
#include <ndn-cxx/util/io.hpp>
#include <ndn-cxx/util/random.hpp>

#include <boost/lexical_cast.hpp>

namespace ndncert {
namespace requester {

NDN_LOG_INIT(ndncert.client);

std::shared_ptr<Interest>
Request::genCaProfileDiscoveryInterest(const Name& caName)
{
  Name contentName = caName;
  if (readString(caName.at(-1)) != "CA")
    contentName.append("CA");
  contentName.append("INFO");
  return std::make_shared<Interest>(ndn::MetadataObject::makeDiscoveryInterest(contentName));
}

std::shared_ptr<Interest>
Request::genCaProfileInterestFromDiscoveryResponse(const Data& reply)
{
  auto metaData = ndn::MetadataObject(reply);
  auto interestName = metaData.getVersionedName();
  interestName.appendSegment(0);
  return std::make_shared<Interest>(interestName);
}

optional<CaProfile>
Request::onCaProfileResponse(const Data& reply)
{
  auto caItem = infotlv::decodeDataContent(reply.getContent());
  if (!ndn::security::verifySignature(reply, *caItem.cert)) {
    NDN_LOG_ERROR("Cannot verify replied Data packet signature.");
    NDN_THROW(std::runtime_error("Cannot verify replied Data packet signature."));
  }
  return caItem;
}

optional<CaProfile>
Request::onCaProfileResponseAfterRedirection(const Data& reply, const Name& caCertFullName)
{
  auto caItem = infotlv::decodeDataContent(reply.getContent());
  auto certBlock = caItem.cert->wireEncode();
  caItem.cert = std::make_shared<Certificate>(certBlock);
  if (caItem.cert->getFullName() != caCertFullName) {
    NDN_LOG_ERROR("Ca profile does not match the certificate information offered by the original CA.");
    NDN_THROW(std::runtime_error("Cannot verify replied Data packet signature."));
  }
  return onCaProfileResponse(reply);
}

std::shared_ptr<Interest>
Request::genProbeInterest(const CaProfile& ca, std::multimap<std::string, std::string>&& probeInfo)
{
  Name interestName = ca.caPrefix;
  interestName.append("CA").append("PROBE");
  auto interest = std::make_shared<Interest>(interestName);
  interest->setMustBeFresh(true);
  interest->setApplicationParameters(probetlv::encodeApplicationParameters(std::move(probeInfo)));
  return interest;
}

void
Request::onProbeResponse(const Data& reply, const CaProfile& ca,
                         std::vector<std::pair<Name, int>>& identityNames, std::vector<Name>& otherCas)
{
  if (!ndn::security::verifySignature(reply, *ca.cert)) {
    NDN_LOG_ERROR("Cannot verify replied Data packet signature.");
    NDN_THROW(std::runtime_error("Cannot verify replied Data packet signature."));
  }
  processIfError(reply);
  probetlv::decodeDataContent(reply.getContent(), identityNames, otherCas);
}

Request::Request(ndn::KeyChain& keyChain, const CaProfile& profile, RequestType requestType)
  : m_caProfile(profile)
  , m_type(requestType)
  , m_keyChain(keyChain)
{
}

std::shared_ptr<Interest>
Request::genNewInterest(const Name& keyName,
                        const time::system_clock::TimePoint& notBefore,
                        const time::system_clock::TimePoint& notAfter)
{
  if (!m_caProfile.caPrefix.isPrefixOf(keyName)) {
    return nullptr;
  }
  if (keyName.empty()) {
    return nullptr;
  }
  else {
    const auto& pib = m_keyChain.getPib();
    ndn::security::pib::Identity identity;
    m_identityName = ndn::security::extractIdentityFromKeyName(keyName);
    identity = pib.getIdentity(m_identityName);
    m_keyPair = identity.getKey(keyName);
  }

  // generate certificate request
  Certificate certRequest;
  certRequest.setName(Name(keyName).append("cert-request").appendVersion());
  certRequest.setContentType(ndn::tlv::ContentType_Key);
  certRequest.setContent(m_keyPair.getPublicKey());
  SignatureInfo signatureInfo;
  signatureInfo.setValidityPeriod(ndn::security::ValidityPeriod(notBefore, notAfter));
  m_keyChain.sign(certRequest, signingByKey(keyName).setSignatureInfo(signatureInfo));

  // generate Interest packet
  Name interestName = m_caProfile.caPrefix;
  interestName.append("CA").append("NEW");
  auto interest = std::make_shared<Interest>(interestName);
  interest->setMustBeFresh(true);
  interest->setApplicationParameters(
    requesttlv::encodeApplicationParameters(RequestType::NEW, m_ecdh.getSelfPubKey(), certRequest));

  // sign the Interest packet
  m_keyChain.sign(*interest, signingByKey(keyName));
  return interest;
}

std::shared_ptr<Interest>
Request::genRevokeInterest(const Certificate& certificate)
{
  if (!m_caProfile.caPrefix.isPrefixOf(certificate.getName())) {
    return nullptr;
  }

  // generate Interest packet
  Name interestName = m_caProfile.caPrefix;
  interestName.append("CA").append("REVOKE");
  auto interest = std::make_shared<Interest>(interestName);
  interest->setMustBeFresh(true);
  interest->setApplicationParameters(
    requesttlv::encodeApplicationParameters(RequestType::REVOKE, m_ecdh.getSelfPubKey(), certificate));
  return interest;
}

std::list<std::string>
Request::onNewRenewRevokeResponse(const Data& reply)
{
  if (!ndn::security::verifySignature(reply, *m_caProfile.cert)) {
    NDN_LOG_ERROR("Cannot verify replied Data packet signature.");
    NDN_THROW(std::runtime_error("Cannot verify replied Data packet signature."));
  }
  processIfError(reply);

  const auto& contentTLV = reply.getContent();
  std::vector<uint8_t> ecdhKey;
  std::array<uint8_t, 32> salt;
  auto challenges = requesttlv::decodeDataContent(contentTLV, ecdhKey, salt, m_requestId);

  // ECDH and HKDF
  auto sharedSecret = m_ecdh.deriveSecret(ecdhKey);
  hkdf(sharedSecret.data(), sharedSecret.size(),
       salt.data(), salt.size(), m_aesKey.data(), m_aesKey.size(),
       m_requestId.data(), m_requestId.size());

  // update state
  return challenges;
}

std::multimap<std::string, std::string>
Request::selectOrContinueChallenge(const std::string& challengeSelected)
{
  auto challenge = ChallengeModule::createChallengeModule(challengeSelected);
  if (challenge == nullptr) {
    NDN_THROW(std::runtime_error("The challenge selected is not supported by your current version of NDNCERT."));
  }
  m_challengeType = challengeSelected;
  return challenge->getRequestedParameterList(m_status, m_challengeStatus);
}

std::shared_ptr<Interest>
Request::genChallengeInterest(std::multimap<std::string, std::string>&& parameters)
{
  if (m_challengeType.empty()) {
    NDN_THROW(std::runtime_error("The challenge has not been selected."));
  }
  auto challenge = ChallengeModule::createChallengeModule(m_challengeType);
  if (challenge == nullptr) {
    NDN_THROW(std::runtime_error("The challenge selected is not supported by your current version of NDNCERT."));
  }
  auto challengeParams = challenge->genChallengeRequestTLV(m_status, m_challengeStatus, std::move(parameters));

  Name interestName = m_caProfile.caPrefix;
  interestName.append("CA").append("CHALLENGE").append(Name::Component(m_requestId));
  auto interest = std::make_shared<Interest>(interestName);
  interest->setMustBeFresh(true);

  // encrypt the Interest parameters
  auto paramBlock = encodeBlockWithAesGcm128(ndn::tlv::ApplicationParameters, m_aesKey.data(),
                                             challengeParams.value(), challengeParams.value_size(),
                                             m_requestId.data(), m_requestId.size(),
                                             m_encryptionIv);
  interest->setApplicationParameters(paramBlock);
  m_keyChain.sign(*interest, signingByKey(m_keyPair.getName()));
  return interest;
}

void
Request::onChallengeResponse(const Data& reply)
{
  if (!ndn::security::verifySignature(reply, *m_caProfile.cert)) {
    NDN_LOG_ERROR("Cannot verify replied Data packet signature.");
    NDN_THROW(std::runtime_error("Cannot verify replied Data packet signature."));
  }
  processIfError(reply);
  challengetlv::decodeDataContent(reply.getContent(), *this);
}

std::shared_ptr<Interest>
Request::genCertFetchInterest() const
{
  auto interest = std::make_shared<Interest>(m_issuedCertName);
  if (!m_forwardingHint.empty()) {
    interest->setForwardingHint({m_forwardingHint});
  }
  return interest;
}

std::shared_ptr<Certificate>
Request::onCertFetchResponse(const Data& reply)
{
  try {
    return std::make_shared<Certificate>(reply);
  }
  catch (const std::exception&) {
    NDN_LOG_ERROR("Cannot parse replied certificate");
    NDN_THROW(std::runtime_error("Cannot parse replied certificate"));
  }
}

void
Request::processIfError(const Data& data)
{
  auto errorInfo = errortlv::decodefromDataContent(data.getContent());
  if (std::get<0>(errorInfo) == ErrorCode::NO_ERROR) {
    return;
  }
  NDN_LOG_ERROR("Error info replied from the CA with Error code: " << std::get<0>(errorInfo) <<
                " and Error Info: " << std::get<1>(errorInfo));
  NDN_THROW(std::runtime_error("Error info replied from the CA with Error code: " +
                               boost::lexical_cast<std::string>(std::get<0>(errorInfo)) +
                               " and Error Info: " + std::get<1>(errorInfo)));
}

} // namespace requester
} // namespace ndncert
