/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2017-2021, Regents of the University of California.
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
#include "challenge/challenge-email.hpp"
#include "challenge/challenge-pin.hpp"
#include "detail/info-encoder.hpp"
#include "requester-request.hpp"
#include "test-common.hpp"

namespace ndncert {
namespace tests {

using namespace ca;
using ndn::util::DummyClientFace;
using ndn::security::verifySignature;

BOOST_FIXTURE_TEST_SUITE(TestCaModule, DatabaseFixture)

BOOST_AUTO_TEST_CASE(Initialization)
{
  DummyClientFace face(io, m_keyChain, {true, true});
  CaModule ca(face, m_keyChain, "tests/unit-tests/config-files/config-ca-1", "ca-storage-memory");
  BOOST_CHECK_EQUAL(ca.getCaConf().caProfile.caPrefix, "/ndn");

  advanceClocks(time::milliseconds(20), 60);
  BOOST_CHECK_EQUAL(ca.m_registeredPrefixHandles.size(), 1); // removed local discovery registration
  BOOST_CHECK_EQUAL(ca.m_interestFilterHandles.size(), 5);  // infoMeta, onProbe, onNew, onChallenge, onRevoke
}

BOOST_AUTO_TEST_CASE(HandleProfileFetching)
{
  auto identity = addIdentity(Name("/ndn"));
  auto key = identity.getDefaultKey();
  auto cert = key.getDefaultCertificate();

  DummyClientFace face(io, m_keyChain, {true, true});
  CaModule ca(face, m_keyChain, "tests/unit-tests/config-files/config-ca-1", "ca-storage-memory");
  advanceClocks(time::milliseconds(20), 60);
  auto profileData = ca.getCaProfileData();

  Interest interest = ndn::MetadataObject::makeDiscoveryInterest(Name("/ndn/CA/INFO"));
  std::shared_ptr<Interest> infoInterest = nullptr;

  face.setInterestFilter(
      ndn::InterestFilter("/ndn/CA/INFO"),
      [&](const auto&, const Interest& interest) {
        if (interest.getName() == profileData.getName()) {
          face.put(profileData);
        }
      },
      nullptr, nullptr);
  advanceClocks(time::milliseconds(20), 60);

  int count = 0;
  face.onSendData.connect([&](const Data& response) {
    if (count == 0) {
      count++;
      auto block = response.getContent();
      block.parse();
      infoInterest = std::make_shared<Interest>(Name(block.get(ndn::tlv::Name)).appendSegment(0));
      infoInterest->setCanBePrefix(false);
    }
    else {
      count++;
      BOOST_CHECK(verifySignature(response, cert));
      auto contentBlock = response.getContent();
      contentBlock.parse();
      auto caItem = infotlv::decodeDataContent(contentBlock);
      BOOST_CHECK_EQUAL(caItem.caPrefix, "/ndn");
      BOOST_CHECK_EQUAL(caItem.probeParameterKeys.size(), 1);
      BOOST_CHECK_EQUAL(caItem.probeParameterKeys.front(), "full name");
      BOOST_CHECK_EQUAL(caItem.cert->wireEncode(), cert.wireEncode());
      BOOST_CHECK_EQUAL(caItem.caInfo, "ndn testbed ca");
    }
  });
  face.receive(interest);
  advanceClocks(time::milliseconds(20), 60);
  face.receive(*infoInterest);
  advanceClocks(time::milliseconds(20), 60);

  BOOST_CHECK_EQUAL(count, 2);
}

BOOST_AUTO_TEST_CASE(HandleProbe)
{
  auto identity = addIdentity(Name("/ndn"));
  auto key = identity.getDefaultKey();
  auto cert = key.getDefaultCertificate();

  DummyClientFace face(io, m_keyChain, {true, true});
  CaModule ca(face, m_keyChain, "tests/unit-tests/config-files/config-ca-1", "ca-storage-memory");
  advanceClocks(time::milliseconds(20), 60);

  Interest interest("/ndn/CA/PROBE");
  interest.setCanBePrefix(false);

  Block paramTLV = ndn::makeEmptyBlock(ndn::tlv::ApplicationParameters);
  paramTLV.push_back(ndn::makeStringBlock(tlv::ParameterKey, "name"));
  paramTLV.push_back(ndn::makeStringBlock(tlv::ParameterValue, "zhiyi"));
  paramTLV.encode();

  interest.setApplicationParameters(paramTLV);

  int count = 0;
  face.onSendData.connect([&](const Data& response) {
    count++;
    BOOST_CHECK(verifySignature(response, cert));
    Block contentBlock = response.getContent();
    contentBlock.parse();
    Block probeResponse = contentBlock.get(tlv::ProbeResponse);
    probeResponse.parse();
    Name caName;
    caName.wireDecode(probeResponse.get(ndn::tlv::Name));
    BOOST_CHECK_EQUAL(caName.size(), 2);
  });
  face.receive(interest);

  advanceClocks(time::milliseconds(20), 60);
  BOOST_CHECK_EQUAL(count, 1);
}

BOOST_AUTO_TEST_CASE(HandleProbeUsingDefaultHandler)
{
  auto identity = addIdentity(Name("/ndn"));
  auto key = identity.getDefaultKey();
  auto cert = key.getDefaultCertificate();

  DummyClientFace face(io, m_keyChain, {true, true});
  CaModule ca(face, m_keyChain, "tests/unit-tests/config-files/config-ca-1", "ca-storage-memory");
  advanceClocks(time::milliseconds(20), 60);

  Interest interest("/ndn/CA/PROBE");
  interest.setCanBePrefix(false);

  Block paramTLV = ndn::makeEmptyBlock(ndn::tlv::ApplicationParameters);
  paramTLV.push_back(ndn::makeStringBlock(tlv::ParameterKey, "name"));
  paramTLV.push_back(ndn::makeStringBlock(tlv::ParameterValue, "zhiyi"));
  paramTLV.encode();

  interest.setApplicationParameters(paramTLV);

  int count = 0;
  face.onSendData.connect([&](const Data& response) {
    count++;
    BOOST_CHECK(verifySignature(response, cert));
    auto contentBlock = response.getContent();
    contentBlock.parse();
    auto probeResponseBlock = contentBlock.get(tlv::ProbeResponse);
    probeResponseBlock.parse();
    Name caPrefix;
    caPrefix.wireDecode(probeResponseBlock.get(ndn::tlv::Name));
    BOOST_CHECK(caPrefix != "");
  });
  face.receive(interest);

  advanceClocks(time::milliseconds(20), 60);
  BOOST_CHECK_EQUAL(count, 1);
}

BOOST_AUTO_TEST_CASE(HandleProbeRedirection)
{
  auto identity = addIdentity(Name("/ndn"));
  auto key = identity.getDefaultKey();
  auto cert = key.getDefaultCertificate();

  DummyClientFace face(io, m_keyChain, {true, true});
  CaModule ca(face, m_keyChain, "tests/unit-tests/config-files/config-ca-5", "ca-storage-memory");
  advanceClocks(time::milliseconds(20), 60);

  Interest interest("/ndn/CA/PROBE");
  interest.setCanBePrefix(false);

  Block paramTLV = ndn::makeEmptyBlock(ndn::tlv::ApplicationParameters);
  paramTLV.push_back(ndn::makeStringBlock(tlv::ParameterKey, "name"));
  paramTLV.push_back(ndn::makeStringBlock(tlv::ParameterValue, "zhiyi"));
  paramTLV.encode();

  interest.setApplicationParameters(paramTLV);

  int count = 0;
  face.onSendData.connect([&](const Data& response) {
    count++;
    BOOST_CHECK(verifySignature(response, cert));
    Block contentBlock = response.getContent();
    contentBlock.parse();

    // Test CA sent redirections
    std::vector<Name> redirectionItems;
    for (auto item : contentBlock.elements()) {
      if (item.type() == tlv::ProbeRedirect) {
        redirectionItems.push_back(Name(item.blockFromValue()));
      }
    }
    BOOST_CHECK_EQUAL(redirectionItems.size(), 2);
    BOOST_CHECK_EQUAL(ndn::security::extractIdentityFromCertName(redirectionItems[0].getPrefix(-1)), "/ndn/site1");
    BOOST_CHECK_EQUAL(ndn::security::extractIdentityFromCertName(redirectionItems[1].getPrefix(-1)), "/ndn/site1");
  });
  face.receive(interest);
  advanceClocks(time::milliseconds(20), 60);
  BOOST_CHECK_EQUAL(count, 1);
}

BOOST_AUTO_TEST_CASE(HandleNew)
{
  auto identity = addIdentity(Name("/ndn"));
  auto key = identity.getDefaultKey();
  auto cert = key.getDefaultCertificate();

  DummyClientFace face(io, m_keyChain, {true, true});
  CaModule ca(face, m_keyChain, "tests/unit-tests/config-files/config-ca-1", "ca-storage-memory");
  advanceClocks(time::milliseconds(20), 60);

  CaProfile item;
  item.caPrefix = Name("/ndn");
  item.cert = std::make_shared<Certificate>(cert);
  requester::Request state(m_keyChain, item, RequestType::NEW);
  auto interest = state.genNewInterest(Name("/ndn/zhiyi"),
                                       time::system_clock::now(),
                                       time::system_clock::now() + time::days(1));

  int count = 0;
  face.onSendData.connect([&](const Data& response) {
    count++;
    BOOST_CHECK(verifySignature(response, cert));
    auto contentBlock = response.getContent();
    contentBlock.parse();

    BOOST_CHECK(readString(contentBlock.get(tlv::EcdhPub)) != "");
    BOOST_CHECK(readString(contentBlock.get(tlv::Salt)) != "");
    BOOST_CHECK(readString(contentBlock.get(tlv::RequestId)) != "");

    auto challengeBlockCount = 0;
    for (auto const& element : contentBlock.elements()) {
      if (element.type() == tlv::Challenge) {
        challengeBlockCount++;
      }
    }

    BOOST_CHECK(challengeBlockCount != 0);

    auto challengeList = state.onNewRenewRevokeResponse(response);
    RequestId requestId;
    std::memcpy(requestId.data(), contentBlock.get(tlv::RequestId).value(), contentBlock.get(tlv::RequestId).value_size());
    auto ca_encryption_key = ca.getCaStorage()->getRequest(requestId).encryptionKey;
    BOOST_CHECK_EQUAL_COLLECTIONS(state.m_aesKey.begin(), state.m_aesKey.end(),
                                  ca_encryption_key.begin(), ca_encryption_key.end());
  });
  face.receive(*interest);

  advanceClocks(time::milliseconds(20), 60);
  BOOST_CHECK_EQUAL(count, 1);
}

BOOST_AUTO_TEST_CASE(HandleNewWithInvalidValidityPeriod1)
{
  auto identity = addIdentity(Name("/ndn"));
  auto key = identity.getDefaultKey();
  auto cert = key.getDefaultCertificate();

  DummyClientFace face(io, m_keyChain, {true, true});
  CaModule ca(face, m_keyChain, "tests/unit-tests/config-files/config-ca-1");
  advanceClocks(time::milliseconds(20), 60);

  CaProfile item;
  item.caPrefix = Name("/ndn");
  item.cert = std::make_shared<Certificate>(cert);
  requester::Request state(m_keyChain, item, RequestType::NEW);
  auto current_tp = time::system_clock::now();
  auto interest1 = state.genNewInterest(Name("/ndn/zhiyi"), current_tp, current_tp - time::hours(1));
  auto interest2 = state.genNewInterest(Name("/ndn/zhiyi"), current_tp, current_tp + time::days(361));
  auto interest3 = state.genNewInterest(Name("/ndn/zhiyi"), current_tp - time::hours(1), current_tp + time::hours(2));
  face.onSendData.connect([&](const Data& response) {
    auto contentTlv = response.getContent();
    contentTlv.parse();
    auto errorCode = static_cast<ErrorCode>(readNonNegativeInteger(contentTlv.get(tlv::ErrorCode)));
    BOOST_CHECK(errorCode != ErrorCode::NO_ERROR);
  });
  face.receive(*interest1);
  face.receive(*interest2);
  face.receive(*interest3);

  advanceClocks(time::milliseconds(20), 60);
}

BOOST_AUTO_TEST_CASE(HandleNewWithServerBadValidity)
{
  auto identity = addIdentity(Name("/ndn"));
  auto key = identity.getDefaultKey();

  //build expired cert
  Certificate cert;
  cert.setName(Name(key.getName()).append("self-sign").appendVersion());
  cert.setContentType(ndn::tlv::ContentType_Key);
  cert.setContent(key.getPublicKey().data(), key.getPublicKey().size());
  SignatureInfo signatureInfo;
  signatureInfo.setValidityPeriod(ndn::security::ValidityPeriod(time::system_clock::now() - time::days(1),
                                                                time::system_clock::now() - time::seconds(1)));
  m_keyChain.sign(cert, signingByKey(key.getName()).setSignatureInfo(signatureInfo));
  m_keyChain.setDefaultCertificate(key, cert);

  DummyClientFace face(io, m_keyChain, {true, true});
  CaModule ca(face, m_keyChain, "tests/unit-tests/config-files/config-ca-1", "ca-storage-memory");
  advanceClocks(time::milliseconds(20), 60);

  CaProfile item;
  item.caPrefix = Name("/ndn");
  item.cert = std::make_shared<Certificate>(cert);
  requester::Request state(m_keyChain, item, RequestType::NEW);
  auto interest = state.genNewInterest(Name("/ndn/zhiyi"),
                                       time::system_clock::now(),
                                       time::system_clock::now() + time::days(1));

  int count = 0;
  face.onSendData.connect([&](const Data& response) {
    auto contentTlv = response.getContent();
    contentTlv.parse();
    auto errorCode = static_cast<ErrorCode>(readNonNegativeInteger(contentTlv.get(tlv::ErrorCode)));
    BOOST_CHECK(errorCode != ErrorCode::NO_ERROR);
    count ++;
  });
  face.receive(*interest);

  advanceClocks(time::milliseconds(20), 60);
  BOOST_CHECK_EQUAL(count, 1);
}

BOOST_AUTO_TEST_CASE(HandleNewWithLongSuffix)
{
  auto identity = addIdentity(Name("/ndn"));
  auto key = identity.getDefaultKey();
  auto cert = key.getDefaultCertificate();

  DummyClientFace face(io, m_keyChain, {true, true});
  CaModule ca(face, m_keyChain, "tests/unit-tests/config-files/config-ca-1", "ca-storage-memory");
  advanceClocks(time::milliseconds(20), 60);

  CaProfile item;
  item.caPrefix = Name("/ndn");
  item.cert = std::make_shared<Certificate>(cert);
  requester::Request state(m_keyChain, item, RequestType::NEW);

  auto interest1 = state.genNewInterest(Name("/ndn/a"), time::system_clock::now(),
                                              time::system_clock::now() + time::days(1));
  auto interest2 = state.genNewInterest(Name("/ndn/a/b"), time::system_clock::now(),
                                              time::system_clock::now() + time::days(1));
  auto interest3 = state.genNewInterest(Name("/ndn/a/b/c/d"), time::system_clock::now(),
                                              time::system_clock::now() + time::days(1));

  face.onSendData.connect([&](const Data& response) {
    auto contentTlv = response.getContent();
    contentTlv.parse();
    if (interest3->getName().isPrefixOf(response.getName())) {
      auto errorCode = static_cast<ErrorCode>(readNonNegativeInteger(contentTlv.get(tlv::ErrorCode)));
      BOOST_CHECK(errorCode != ErrorCode::NO_ERROR);
    }
    else {
      // should successfully get responses
      BOOST_CHECK_THROW(readNonNegativeInteger(contentTlv.get(tlv::ErrorCode)), std::runtime_error);
    }
  });
  face.receive(*interest1);
  face.receive(*interest2);
  face.receive(*interest3);
  advanceClocks(time::milliseconds(20), 60);
}

BOOST_AUTO_TEST_CASE(HandleNewWithInvalidLength1)
{
  auto identity = addIdentity(Name("/ndn"));
  auto key = identity.getDefaultKey();
  auto cert = key.getDefaultCertificate();

  DummyClientFace face(io, m_keyChain, {true, true});
  CaModule ca(face, m_keyChain, "tests/unit-tests/config-files/config-ca-1");
  advanceClocks(time::milliseconds(20), 60);

  CaProfile item;
  item.caPrefix = Name("/ndn");
  item.cert = std::make_shared<Certificate>(cert);
  requester::Request state(m_keyChain, item, RequestType::NEW);

  auto current_tp = time::system_clock::now();
  auto interest1 = state.genNewInterest(Name("/ndn"), current_tp, current_tp + time::days(1));
  auto interest2 = state.genNewInterest(Name("/ndn/a/b/c/d"), current_tp, current_tp + time::days(1));
  face.onSendData.connect([&](const Data& response) {
    auto contentTlv = response.getContent();
    contentTlv.parse();
    auto errorCode = static_cast<ErrorCode>(readNonNegativeInteger(contentTlv.get(tlv::ErrorCode)));
    BOOST_CHECK(errorCode != ErrorCode::NO_ERROR);
  });
  face.receive(*interest1);
  face.receive(*interest2);

  advanceClocks(time::milliseconds(20), 60);
}

BOOST_AUTO_TEST_CASE(HandleChallenge)
{
  auto identity = addIdentity(Name("/ndn"));
  auto key = identity.getDefaultKey();
  auto cert = key.getDefaultCertificate();

  DummyClientFace face(io, m_keyChain, {true, true});
  CaModule ca(face, m_keyChain, "tests/unit-tests/config-files/config-ca-1", "ca-storage-memory");
  advanceClocks(time::milliseconds(20), 60);

  // generate NEW Interest
  CaProfile item;
  item.caPrefix = Name("/ndn");
  item.cert = std::make_shared<Certificate>(cert);
  requester::Request state(m_keyChain, item, RequestType::NEW);

  auto newInterest = state.genNewInterest(Name("/ndn/zhiyi"), time::system_clock::now(),
                                                time::system_clock::now() + time::days(1));

  // generate CHALLENGE Interest
  std::shared_ptr<Interest> challengeInterest;
  std::shared_ptr<Interest> challengeInterest2;
  std::shared_ptr<Interest> challengeInterest3;

  int count = 0;
  face.onSendData.connect([&](const Data& response) {
    if (Name("/ndn/CA/NEW").isPrefixOf(response.getName())) {
      auto challengeList = state.onNewRenewRevokeResponse(response);
      auto paramList = state.selectOrContinueChallenge("pin");
      challengeInterest = state.genChallengeInterest(std::move(paramList));
    }
    else if (Name("/ndn/CA/CHALLENGE").isPrefixOf(response.getName()) && count == 0) {
      count++;
      BOOST_CHECK(verifySignature(response, cert));

      state.onChallengeResponse(response);
      BOOST_CHECK(state.m_status == Status::CHALLENGE);
      BOOST_CHECK_EQUAL(state.m_challengeStatus, ChallengePin::NEED_CODE);
      auto paramList = state.selectOrContinueChallenge("pin");
      challengeInterest2 = state.genChallengeInterest(std::move(paramList));
    }
    else if (Name("/ndn/CA/CHALLENGE").isPrefixOf(response.getName()) && count == 1) {
      count++;
      BOOST_CHECK(verifySignature(response, cert));

      state.onChallengeResponse(response);
      BOOST_CHECK(state.m_status == Status::CHALLENGE);
      BOOST_CHECK_EQUAL(state.m_challengeStatus, ChallengePin::WRONG_CODE);

      auto paramList = state.selectOrContinueChallenge("pin");
      auto request = ca.getCertificateRequest(*challengeInterest2);
      auto secret = request->challengeState->secrets.get(ChallengePin::PARAMETER_KEY_CODE, "");
      paramList.begin()->second = secret;
      challengeInterest3 = state.genChallengeInterest(std::move(paramList));
    }
    else if (Name("/ndn/CA/CHALLENGE").isPrefixOf(response.getName()) && count == 2) {
      count++;
      BOOST_CHECK(verifySignature(response, cert));
      state.onChallengeResponse(response);
      BOOST_CHECK(state.m_status == Status::SUCCESS);
    }
  });

  face.receive(*newInterest);
  advanceClocks(time::milliseconds(20), 60);
  face.receive(*challengeInterest);
  advanceClocks(time::milliseconds(20), 60);
  face.receive(*challengeInterest2);
  advanceClocks(time::milliseconds(20), 60);
  face.receive(*challengeInterest3);
  advanceClocks(time::milliseconds(20), 60);
  BOOST_CHECK_EQUAL(count, 3);
}

BOOST_AUTO_TEST_CASE(HandleRevoke)
{
  auto identity = addIdentity(Name("/ndn"));
  auto key = identity.getDefaultKey();
  auto cert = key.getDefaultCertificate();

  DummyClientFace face(io, {true, true});
  CaModule ca(face, m_keyChain, "tests/unit-tests/config-files/config-ca-1", "ca-storage-memory");
  advanceClocks(time::milliseconds(20), 60);

  //generate a certificate
  auto clientIdentity = m_keyChain.createIdentity("/ndn/qwerty");
  auto clientKey = clientIdentity.getDefaultKey();
  Certificate clientCert;
  clientCert.setName(Name(clientKey.getName()).append("cert-request").appendVersion());
  clientCert.setContentType(ndn::tlv::ContentType_Key);
  clientCert.setFreshnessPeriod(time::hours(24));
  clientCert.setContent(clientKey.getPublicKey().data(), clientKey.getPublicKey().size());
  SignatureInfo signatureInfo;
  signatureInfo.setValidityPeriod(ndn::security::ValidityPeriod(time::system_clock::now(),
                                                                time::system_clock::now() + time::hours(10)));
  m_keyChain.sign(clientCert, signingByKey(clientKey.getName()).setSignatureInfo(signatureInfo));
  RequestId requestId = {{101}};
  RequestState certRequest;
  certRequest.caPrefix = Name("/ndn");
  certRequest.requestId = requestId;
  certRequest.requestType = RequestType::NEW;
  certRequest.status = Status::SUCCESS;
  certRequest.cert = clientCert;
  auto issuedCert = ca.issueCertificate(certRequest);

  CaProfile item;
  item.caPrefix = Name("/ndn");
  item.cert = std::make_shared<Certificate>(cert);
  requester::Request state(m_keyChain, item, RequestType::REVOKE);

  auto interest = state.genRevokeInterest(issuedCert);

  int count = 0;
  face.onSendData.connect([&](const Data& response) {
    count++;
    BOOST_CHECK(verifySignature(response, cert));
    auto contentBlock = response.getContent();
    contentBlock.parse();

    BOOST_CHECK(readString(contentBlock.get(tlv::EcdhPub)) != "");
    BOOST_CHECK(readString(contentBlock.get(tlv::Salt)) != "");
    BOOST_CHECK(readString(contentBlock.get(tlv::RequestId)) != "");

    auto challengeBlockCount = 0;
    for (auto const& element : contentBlock.elements()) {
      if (element.type() == tlv::Challenge) {
        challengeBlockCount++;
      }
    }

    BOOST_CHECK(challengeBlockCount != 0);

    auto challengeList = state.onNewRenewRevokeResponse(response);
    RequestId requestId;
    std::memcpy(requestId.data(), contentBlock.get(tlv::RequestId).value(), contentBlock.get(tlv::RequestId).value_size());
    auto ca_encryption_key = ca.getCaStorage()->getRequest(requestId).encryptionKey;
    BOOST_CHECK_EQUAL_COLLECTIONS(state.m_aesKey.begin(), state.m_aesKey.end(),
                                  ca_encryption_key.begin(), ca_encryption_key.end());
  });
  face.receive(*interest);

  advanceClocks(time::milliseconds(20), 60);
  BOOST_CHECK_EQUAL(count, 1);
}

BOOST_AUTO_TEST_CASE(HandleRevokeWithBadCert)
{
  auto identity = addIdentity(Name("/ndn"));
  auto key = identity.getDefaultKey();
  auto cert = key.getDefaultCertificate();

  DummyClientFace face(io, {true, true});
  CaModule ca(face, m_keyChain, "tests/unit-tests/config-files/config-ca-1", "ca-storage-memory");
  advanceClocks(time::milliseconds(20), 60);

  // generate a certificate
  auto clientIdentity = m_keyChain.createIdentity("/ndn/qwerty");
  auto clientKey = clientIdentity.getDefaultKey();
  Certificate clientCert;
  clientCert.setName(Name(clientKey.getName()).append("NDNCERT").append("1473283247810732701"));
  clientCert.setContentType(ndn::tlv::ContentType_Key);
  clientCert.setFreshnessPeriod(time::hours(24));
  clientCert.setContent(clientKey.getPublicKey().data(), clientKey.getPublicKey().size());
  SignatureInfo signatureInfo;
  signatureInfo.setValidityPeriod(ndn::security::ValidityPeriod(time::system_clock::now(),
                                                                time::system_clock::now() + time::hours(10)));
  m_keyChain.sign(clientCert, signingByKey(clientKey.getName()).setSignatureInfo(signatureInfo));

  CaProfile item;
  item.caPrefix = Name("/ndn");
  item.cert = std::make_shared<Certificate>(cert);
  requester::Request state(m_keyChain, item, RequestType::NEW);

  auto interest = state.genRevokeInterest(clientCert);

  bool receiveData = false;
  face.onSendData.connect([&](const Data& response) {
    receiveData = true;
    auto contentTlv = response.getContent();
    contentTlv.parse();
    BOOST_CHECK(static_cast<ErrorCode>(readNonNegativeInteger(contentTlv.get(tlv::ErrorCode))) != ErrorCode::NO_ERROR);
  });
  face.receive(*interest);

  advanceClocks(time::milliseconds(20), 60);
  BOOST_CHECK_EQUAL(receiveData, true);
}

BOOST_AUTO_TEST_SUITE_END() // TestCaModule

} // namespace tests
} // namespace ndncert
