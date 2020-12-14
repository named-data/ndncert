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

#include "requester.hpp"
#include "challenge/challenge-module.hpp"
#include "detail/crypto-helpers.hpp"
#include "detail/challenge-encoder.hpp"
#include "detail/error-encoder.hpp"
#include "detail/info-encoder.hpp"
#include "detail/new-renew-revoke-encoder.hpp"
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
Requester::genCaProfileDiscoveryInterest(const Name& caName)
{
  Name contentName = caName;
  if (readString(caName.at(-1)) != "CA")
    contentName.append("CA");
  contentName.append("INFO");
  return std::make_shared<Interest>(MetadataObject::makeDiscoveryInterest(contentName));
}

shared_ptr<Interest>
Requester::genCaProfileInterestFromDiscoveryResponse(const Data& reply)
{
  auto metaData = MetadataObject(reply);
  auto interestName= metaData.getVersionedName();
  interestName.appendSegment(0);
  auto interest = std::make_shared<Interest>(interestName);
  interest->setCanBePrefix(false);
  return interest;
}

optional<CaProfile>
Requester::onCaProfileResponse(const Data& reply)
{
  auto caItem = infotlv::decodeDataContent(reply.getContent());
  if (!security::verifySignature(reply, *caItem.cert)) {
    NDN_LOG_ERROR("Cannot verify replied Data packet signature.");
    NDN_THROW(std::runtime_error("Cannot verify replied Data packet signature."));
  }
  return caItem;
}

optional<CaProfile>
Requester::onCaProfileResponseAfterRedirection(const Data& reply, const Name& caCertFullName)
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
Requester::genProbeInterest(const CaProfile& ca, std::multimap<std::string, std::string>&& probeInfo)
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
Requester::onProbeResponse(const Data& reply, const CaProfile& ca,
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

shared_ptr<Interest>
Requester::genNewInterest(RequestState& state, const Name& identityName,
                          const time::system_clock::TimePoint& notBefore,
                          const time::system_clock::TimePoint& notAfter)
{
  if (!state.caProfile.caPrefix.isPrefixOf(identityName)) {
    return nullptr;
  }
  if (identityName.empty()) {
    NDN_LOG_TRACE("Randomly create a new name because identityName is empty and the param is empty.");
    state.identityName = state.caProfile.caPrefix;
    state.identityName.append(std::to_string(random::generateSecureWord64()));
  }
  else {
    state.identityName = identityName;
  }

  // generate a newly key pair or use an existing key
  const auto& pib = state.keyChain.getPib();
  security::pib::Identity identity;
  try {
    identity = pib.getIdentity(state.identityName);
  }
  catch (const security::Pib::Error& e) {
    identity = state.keyChain.createIdentity(state.identityName);
    state.isNewlyCreatedIdentity = true;
    state.isNewlyCreatedKey = true;
  }
  try {
    state.keyPair = identity.getDefaultKey();
  }
  catch (const security::Pib::Error& e) {
    state.keyPair = state.keyChain.createKey(identity);
    state.isNewlyCreatedKey = true;
  }
  auto& keyName = state.keyPair.getName();

  // generate certificate request
  security::Certificate certRequest;
  certRequest.setName(Name(keyName).append("cert-request").appendVersion());
  certRequest.setContentType(ndn::tlv::ContentType_Key);
  certRequest.setContent(state.keyPair.getPublicKey().data(), state.keyPair.getPublicKey().size());
  SignatureInfo signatureInfo;
  signatureInfo.setValidityPeriod(security::ValidityPeriod(notBefore, notAfter));
  state.keyChain.sign(certRequest, signingByKey(keyName).setSignatureInfo(signatureInfo));

  // generate Interest packet
  Name interestName = state.caProfile.caPrefix;
  interestName.append("CA").append("NEW");
  auto interest =std::make_shared<Interest>(interestName);
  interest->setMustBeFresh(true);
  interest->setCanBePrefix(false);
  interest->setApplicationParameters(
          requesttlv::encodeApplicationParameters(RequestType::NEW, state.ecdh.getSelfPubKey(), certRequest));

  // sign the Interest packet
  state.keyChain.sign(*interest, signingByKey(keyName));
  return interest;
}

shared_ptr<Interest>
Requester::genRevokeInterest(RequestState& state, const security::Certificate& certificate)
{
  if (!state.caProfile.caPrefix.isPrefixOf(certificate.getName())) {
    return nullptr;
  }
  // generate Interest packet
  Name interestName = state.caProfile.caPrefix;
  interestName.append("CA").append("REVOKE");
  auto interest =std::make_shared<Interest>(interestName);
  interest->setMustBeFresh(true);
  interest->setCanBePrefix(false);
  interest->setApplicationParameters(
          requesttlv::encodeApplicationParameters(RequestType::REVOKE, state.ecdh.getSelfPubKey(), certificate));
  return interest;
}

std::list<std::string>
Requester::onNewRenewRevokeResponse(RequestState& state, const Data& reply)
{
  if (!security::verifySignature(reply, *state.caProfile.cert)) {
    NDN_LOG_ERROR("Cannot verify replied Data packet signature.");
    NDN_THROW(std::runtime_error("Cannot verify replied Data packet signature."));
  }
  processIfError(reply);

  auto contentTLV = reply.getContent();
  std::vector<uint8_t> ecdhKey;
  std::array<uint8_t, 32> salt;
  auto challenges = requesttlv::decodeDataContent(contentTLV, ecdhKey, salt, state.requestId, state.status);

  // ECDH and HKDF
  auto sharedSecret = state.ecdh.deriveSecret(ecdhKey);
  hkdf(sharedSecret.data(), sharedSecret.size(),
       salt.data(), salt.size(), state.aesKey.data(), state.aesKey.size());

  // update state
  return challenges;
}

std::multimap<std::string, std::string>
Requester::selectOrContinueChallenge(RequestState& state, const std::string& challengeSelected)
{
  auto challenge = ChallengeModule::createChallengeModule(challengeSelected);
  if (challenge == nullptr) {
    NDN_THROW(std::runtime_error("The challenge selected is not supported by your current version of NDNCERT."));
  }
  state.challengeType = challengeSelected;
  return challenge->getRequestedParameterList(state.status, state.challengeStatus);
}

shared_ptr<Interest>
Requester::genChallengeInterest(RequestState& state,
                                std::multimap<std::string, std::string>&& parameters)
{
  if (state.challengeType == "") {
    NDN_THROW(std::runtime_error("The challenge has not been selected."));
  }
  auto challenge = ChallengeModule::createChallengeModule(state.challengeType);
  if (challenge == nullptr) {
    NDN_THROW(std::runtime_error("The challenge selected is not supported by your current version of NDNCERT."));
  }
  auto challengeParams = challenge->genChallengeRequestTLV(state.status, state.challengeStatus, std::move(parameters));

  Name interestName = state.caProfile.caPrefix;
  interestName.append("CA").append("CHALLENGE").append(state.requestId.data(), state.requestId.size());
  auto interest =std::make_shared<Interest>(interestName);
  interest->setMustBeFresh(true);
  interest->setCanBePrefix(false);

  // encrypt the Interest parameters
  auto paramBlock = encodeBlockWithAesGcm128(ndn::tlv::ApplicationParameters, state.aesKey.data(),
                                             challengeParams.value(), challengeParams.value_size(),
                                             state.requestId.data(),
                                             state.requestId.size(),
                                             state.aesBlockCounter);
  interest->setApplicationParameters(paramBlock);
  state.keyChain.sign(*interest, signingByKey(state.keyPair.getName()));
  return interest;
}

void
Requester::onChallengeResponse(RequestState& state, const Data& reply)
{
  if (!security::verifySignature(reply, *state.caProfile.cert)) {
    NDN_LOG_ERROR("Cannot verify replied Data packet signature.");
    NDN_THROW(std::runtime_error("Cannot verify replied Data packet signature."));
  }
  processIfError(reply);
  challengetlv::decodeDataContent(reply.getContent(), state);
}

shared_ptr<Interest>
Requester::genCertFetchInterest(const RequestState& state)
{
  Name interestName = state.issuedCertName;
  auto interest =std::make_shared<Interest>(interestName);
  interest->setMustBeFresh(false);
  interest->setCanBePrefix(false);
  return interest;
}

shared_ptr<security::Certificate>
Requester::onCertFetchResponse(const Data& reply)
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
Requester::endSession(RequestState& state)
{
  if (state.status == Status::SUCCESS) {
    return;
  }
  if (state.isNewlyCreatedIdentity) {
    // put the identity into the if scope is because it may cause an error
    // outside since when endSession is called, identity may not have been created yet.
    auto identity = state.keyChain.getPib().getIdentity(state.identityName);
    state.keyChain.deleteIdentity(identity);
  }
  else if (state.isNewlyCreatedKey) {
    auto identity = state.keyChain.getPib().getIdentity(state.identityName);
    state.keyChain.deleteKey(identity, state.keyPair);
  }
}

void
Requester::processIfError(const Data& data)
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
