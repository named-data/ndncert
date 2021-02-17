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

#include "requester-request.hpp"
#include "challenge/challenge-module.hpp"
#include "detail/crypto-helpers.hpp"
#include "detail/challenge-encoder.hpp"
#include "detail/error-encoder.hpp"
#include "detail/info-encoder.hpp"
#include "detail/request-encoder.hpp"
#include "detail/probe-encoder.hpp"
#include <ndn-cxx/security/signing-helpers.hpp>
#include <ndn-cxx/security/transform/base64-encode.hpp>
#include <ndn-cxx/security/transform/buffer-source.hpp>
#include <ndn-cxx/security/transform/stream-sink.hpp>
#include <ndn-cxx/security/verification-helpers.hpp>
#include <ndn-cxx/util/io.hpp>
#include <ndn-cxx/util/random.hpp>
#include <ndn-cxx/metadata-object.hpp>
#include <boost/lexical_cast.hpp>

namespace ndn {
namespace ndncert {
namespace requester {

NDN_LOG_INIT(ndncert.client);

shared_ptr<Interest>
Request::genCaProfileDiscoveryInterest(const Name& caName)
{
  Name contentName = caName;
  if (readString(caName.at(-1)) != "CA")
    contentName.append("CA");
  contentName.append("INFO");
  return std::make_shared<Interest>(MetadataObject::makeDiscoveryInterest(contentName));
}

shared_ptr<Interest>
Request::genCaProfileInterestFromDiscoveryResponse(const Data& reply)
{
  // set naming convention to be typed
  auto convention = name::getConventionEncoding();
  name::setConventionEncoding(name::Convention::TYPED);

  auto metaData = MetadataObject(reply);
  auto interestName= metaData.getVersionedName();
  interestName.appendSegment(0);
  auto interest = std::make_shared<Interest>(interestName);
  interest->setCanBePrefix(false);

  // set back the convention
  name::setConventionEncoding(convention);

  return interest;
}

optional<CaProfile>
Request::onCaProfileResponse(const Data& reply)
{
  auto caItem = infotlv::decodeDataContent(reply.getContent());
  if (!security::verifySignature(reply, *caItem.cert)) {
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
  caItem.cert = std::make_shared<security::Certificate>(certBlock);
  if (caItem.cert->getFullName() != caCertFullName) {
    NDN_LOG_ERROR("Ca profile does not match the certificate information offered by the original CA.");
    NDN_THROW(std::runtime_error("Cannot verify replied Data packet signature."));
  }
  return onCaProfileResponse(reply);
}

shared_ptr<Interest>
Request::genProbeInterest(const CaProfile& ca, std::multimap<std::string, std::string>&& probeInfo)
{
  Name interestName = ca.caPrefix;
  interestName.append("CA").append("PROBE");
  auto interest =std::make_shared<Interest>(interestName);
  interest->setMustBeFresh(true);
  interest->setCanBePrefix(false);
  interest->setApplicationParameters(probetlv::encodeApplicationParameters(std::move(probeInfo)));
  return interest;
}

void
Request::onProbeResponse(const Data& reply, const CaProfile& ca,
                         std::vector<std::pair<Name, int>>& identityNames, std::vector<Name>& otherCas)
{
  if (!security::verifySignature(reply, *ca.cert)) {
    NDN_LOG_ERROR("Cannot verify replied Data packet signature.");
    NDN_THROW(std::runtime_error("Cannot verify replied Data packet signature."));
    return;
  }
  processIfError(reply);
  probetlv::decodeDataContent(reply.getContent(), identityNames, otherCas);
}

Request::Request(security::KeyChain& keyChain, const CaProfile& profile, RequestType requestType)
    : caProfile(profile)
    , type(requestType)
    , m_keyChain(keyChain)
{}

shared_ptr<Interest>
Request::genNewInterest(const Name& newIdentityName,
                        const time::system_clock::TimePoint& notBefore,
                        const time::system_clock::TimePoint& notAfter)
{
  if (!caProfile.caPrefix.isPrefixOf(newIdentityName)) {
    return nullptr;
  }
  if (newIdentityName.empty()) {
    NDN_LOG_TRACE("Randomly create a new name because newIdentityName is empty and the param is empty.");
    identityName = caProfile.caPrefix;
    identityName.append(std::to_string(random::generateSecureWord64()));
  }
  else {
    identityName = newIdentityName;
  }

  // generate a newly key pair or use an existing key
  const auto& pib = m_keyChain.getPib();
  security::pib::Identity identity;
  try {
    identity = pib.getIdentity(identityName);
  }
  catch (const security::Pib::Error& e) {
    identity = m_keyChain.createIdentity(identityName);
    m_isNewlyCreatedIdentity = true;
    m_isNewlyCreatedKey = true;
  }
  try {
    m_keyPair = identity.getDefaultKey();
  }
  catch (const security::Pib::Error& e) {
    m_keyPair = m_keyChain.createKey(identity);
    m_isNewlyCreatedKey = true;
  }
  auto& keyName = m_keyPair.getName();

  // generate certificate request
  security::Certificate certRequest;
  certRequest.setName(Name(keyName).append("cert-request").appendVersion());
  certRequest.setContentType(ndn::tlv::ContentType_Key);
  certRequest.setContent(m_keyPair.getPublicKey().data(), m_keyPair.getPublicKey().size());
  SignatureInfo signatureInfo;
  signatureInfo.setValidityPeriod(security::ValidityPeriod(notBefore, notAfter));
  m_keyChain.sign(certRequest, signingByKey(keyName).setSignatureInfo(signatureInfo));

  // generate Interest packet
  Name interestName = caProfile.caPrefix;
  interestName.append("CA").append("NEW");
  auto interest =std::make_shared<Interest>(interestName);
  interest->setMustBeFresh(true);
  interest->setCanBePrefix(false);
  interest->setApplicationParameters(
          requesttlv::encodeApplicationParameters(RequestType::NEW, ecdh.getSelfPubKey(), certRequest));

  // sign the Interest packet
  m_keyChain.sign(*interest, signingByKey(keyName));
  return interest;
}

shared_ptr<Interest>
Request::genRevokeInterest(const security::Certificate& certificate)
{
  if (!caProfile.caPrefix.isPrefixOf(certificate.getName())) {
    return nullptr;
  }
  // generate Interest packet
  Name interestName = caProfile.caPrefix;
  interestName.append("CA").append("REVOKE");
  auto interest =std::make_shared<Interest>(interestName);
  interest->setMustBeFresh(true);
  interest->setCanBePrefix(false);
  interest->setApplicationParameters(
          requesttlv::encodeApplicationParameters(RequestType::REVOKE, ecdh.getSelfPubKey(), certificate));
  return interest;
}

std::list<std::string>
Request::onNewRenewRevokeResponse(const Data& reply)
{
  if (!security::verifySignature(reply, *caProfile.cert)) {
    NDN_LOG_ERROR("Cannot verify replied Data packet signature.");
    NDN_THROW(std::runtime_error("Cannot verify replied Data packet signature."));
  }
  processIfError(reply);

  const auto& contentTLV = reply.getContent();
  std::vector<uint8_t> ecdhKey;
  std::array<uint8_t, 32> salt;
  auto challenges = requesttlv::decodeDataContent(contentTLV, ecdhKey, salt, requestId);

  // ECDH and HKDF
  auto sharedSecret = ecdh.deriveSecret(ecdhKey);
  hkdf(sharedSecret.data(), sharedSecret.size(),
       salt.data(), salt.size(), aesKey.data(), aesKey.size());

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
  challengeType = challengeSelected;
  return challenge->getRequestedParameterList(status, challengeStatus);
}

shared_ptr<Interest>
Request::genChallengeInterest(std::multimap<std::string, std::string>&& parameters)
{
  if (challengeType == "") {
    NDN_THROW(std::runtime_error("The challenge has not been selected."));
  }
  auto challenge = ChallengeModule::createChallengeModule(challengeType);
  if (challenge == nullptr) {
    NDN_THROW(std::runtime_error("The challenge selected is not supported by your current version of NDNCERT."));
  }
  auto challengeParams = challenge->genChallengeRequestTLV(status, challengeStatus, std::move(parameters));

  Name interestName = caProfile.caPrefix;
  interestName.append("CA").append("CHALLENGE").append(requestId.data(), requestId.size());
  auto interest =std::make_shared<Interest>(interestName);
  interest->setMustBeFresh(true);
  interest->setCanBePrefix(false);

  // encrypt the Interest parameters
  auto paramBlock = encodeBlockWithAesGcm128(ndn::tlv::ApplicationParameters, aesKey.data(),
                                             challengeParams.value(), challengeParams.value_size(),
                                             requestId.data(), requestId.size(),
                                             encryptionIv);
  interest->setApplicationParameters(paramBlock);
  m_keyChain.sign(*interest, signingByKey(m_keyPair.getName()));
  return interest;
}

void
Request::onChallengeResponse(const Data& reply)
{
  if (!security::verifySignature(reply, *caProfile.cert)) {
    NDN_LOG_ERROR("Cannot verify replied Data packet signature.");
    NDN_THROW(std::runtime_error("Cannot verify replied Data packet signature."));
  }
  processIfError(reply);
  challengetlv::decodeDataContent(reply.getContent(), *this);
}

shared_ptr<Interest>
Request::genCertFetchInterest() const
{
  Name interestName = issuedCertName;
  auto interest =std::make_shared<Interest>(interestName);
  interest->setMustBeFresh(false);
  interest->setCanBePrefix(false);
  return interest;
}

shared_ptr<security::Certificate>
Request::onCertFetchResponse(const Data& reply)
{
  try {
    return std::make_shared<security::Certificate>(reply);
  }
  catch (const std::exception& e) {
    NDN_LOG_ERROR("Cannot parse replied certificate ");
    NDN_THROW(std::runtime_error("Cannot parse replied certificate "));
    return nullptr;
  }
}

void
Request::endSession()
{
  if (status == Status::SUCCESS) {
    return;
  }
  if (m_isNewlyCreatedIdentity) {
    // put the identity into the if scope is because it may cause an error
    // outside since when endSession is called, identity may not have been created yet.
    auto identity = m_keyChain.getPib().getIdentity(identityName);
    m_keyChain.deleteIdentity(identity);
  }
  else if (m_isNewlyCreatedKey) {
    auto identity = m_keyChain.getPib().getIdentity(identityName);
    m_keyChain.deleteKey(identity, m_keyPair);
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
} // namespace ndn
