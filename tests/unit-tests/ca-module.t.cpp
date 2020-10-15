/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
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
#include "identity-challenge/challenge-module.hpp"
#include "identity-challenge/challenge-email.hpp"
#include "identity-challenge/challenge-pin.hpp"
#include "detail/info-encoder.hpp"
#include "requester.hpp"
#include "test-common.hpp"

namespace ndn {
namespace ndncert {
namespace tests {

BOOST_FIXTURE_TEST_SUITE(TestCaModule, DatabaseFixture)

BOOST_AUTO_TEST_CASE(Initialization)
{
  util::DummyClientFace face(io, m_keyChain, {true, true});
  CaModule ca(face, m_keyChain, "tests/unit-tests/config-files/config-ca-1", "ca-storage-memory");
  BOOST_CHECK_EQUAL(ca.getCaConf().m_caItem.m_caPrefix, "/ndn");

  advanceClocks(time::milliseconds(20), 60);
  BOOST_CHECK_EQUAL(ca.m_registeredPrefixHandles.size(), 1); // removed local discovery registration
  BOOST_CHECK_EQUAL(ca.m_interestFilterHandles.size(), 5);  // infoMeta, onProbe, onNew, onChallenge, onRevoke
}

BOOST_AUTO_TEST_CASE(HandleProfileFetching)
{
  auto identity = addIdentity(Name("/ndn"));
  auto key = identity.getDefaultKey();
  auto cert = key.getDefaultCertificate();

  util::DummyClientFace face(io, m_keyChain, {true, true});
  CaModule ca(face, m_keyChain, "tests/unit-tests/config-files/config-ca-1", "ca-storage-memory");
  advanceClocks(time::milliseconds(20), 60);
  auto profileData = ca.getCaProfileData();

  Interest interest = MetadataObject::makeDiscoveryInterest(Name("/ndn/CA/INFO"));
  shared_ptr<Interest> infoInterest = nullptr;

  face.setInterestFilter(
      InterestFilter("/ndn/CA/INFO"),
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
      infoInterest =std::make_shared<Interest>(Name(block.get(ndn::tlv::Name)).appendSegment(0));
      infoInterest->setCanBePrefix(false);
    }
    else {
      count++;
      BOOST_CHECK(security::verifySignature(response, cert));
      auto contentBlock = response.getContent();
      contentBlock.parse();
      auto caItem = InfoEncoder::decodeDataContent(contentBlock);
      BOOST_CHECK_EQUAL(caItem.m_caPrefix, "/ndn");
      BOOST_CHECK_EQUAL(caItem.m_probeParameterKeys.size(), 1);
      BOOST_CHECK_EQUAL(caItem.m_probeParameterKeys.front(), "full name");
      BOOST_CHECK_EQUAL(caItem.m_cert->wireEncode(), cert.wireEncode());
      BOOST_CHECK_EQUAL(caItem.m_caInfo, "ndn testbed ca");
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

  util::DummyClientFace face(io, m_keyChain, {true, true});
  CaModule ca(face, m_keyChain, "tests/unit-tests/config-files/config-ca-1", "ca-storage-memory");
  advanceClocks(time::milliseconds(20), 60);

  Interest interest("/ndn/CA/PROBE");
  interest.setCanBePrefix(false);

  Block paramTLV = makeEmptyBlock(ndn::tlv::ApplicationParameters);
  paramTLV.push_back(makeStringBlock(tlv::ParameterKey, "name"));
  paramTLV.push_back(makeStringBlock(tlv::ParameterValue, "zhiyi"));
  paramTLV.encode();

  interest.setApplicationParameters(paramTLV);

  int count = 0;
  face.onSendData.connect([&](const Data& response) {
    count++;
    BOOST_CHECK(security::verifySignature(response, cert));
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

  util::DummyClientFace face(io, m_keyChain, {true, true});
  CaModule ca(face, m_keyChain, "tests/unit-tests/config-files/config-ca-1", "ca-storage-memory");
  advanceClocks(time::milliseconds(20), 60);

  Interest interest("/ndn/CA/PROBE");
  interest.setCanBePrefix(false);

  Block paramTLV = makeEmptyBlock(ndn::tlv::ApplicationParameters);
  paramTLV.push_back(makeStringBlock(tlv::ParameterKey, "name"));
  paramTLV.push_back(makeStringBlock(tlv::ParameterValue, "zhiyi"));
  paramTLV.encode();

  interest.setApplicationParameters(paramTLV);

  int count = 0;
  face.onSendData.connect([&](const Data& response) {
    count++;
    BOOST_CHECK(security::verifySignature(response, cert));
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

  util::DummyClientFace face(io, m_keyChain, {true, true});
  CaModule ca(face, m_keyChain, "tests/unit-tests/config-files/config-ca-5", "ca-storage-memory");
  advanceClocks(time::milliseconds(20), 60);

  Interest interest("/ndn/CA/PROBE");
  interest.setCanBePrefix(false);

  Block paramTLV = makeEmptyBlock(ndn::tlv::ApplicationParameters);
  paramTLV.push_back(makeStringBlock(tlv::ParameterKey, "name"));
  paramTLV.push_back(makeStringBlock(tlv::ParameterValue, "zhiyi"));
  paramTLV.encode();

  interest.setApplicationParameters(paramTLV);

  int count = 0;
  face.onSendData.connect([&](const Data& response) {
    count++;
    BOOST_CHECK(security::verifySignature(response, cert));
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
    BOOST_CHECK_EQUAL(security::extractIdentityFromCertName(redirectionItems[0].getPrefix(-1)), "/ndn/site1");
    BOOST_CHECK_EQUAL(security::extractIdentityFromCertName(redirectionItems[1].getPrefix(-1)), "/ndn/site1");
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

  util::DummyClientFace face(io, m_keyChain, {true, true});
  CaModule ca(face, m_keyChain, "tests/unit-tests/config-files/config-ca-1", "ca-storage-memory");
  advanceClocks(time::milliseconds(20), 60);

  CaProfile item;
  item.m_caPrefix = Name("/ndn");
  item.m_cert = std::make_shared<security::Certificate>(cert);
  RequesterState state(m_keyChain, item, RequestType::NEW);
  auto interest = Requester::genNewInterest(state, Name("/ndn/zhiyi"),
                                            time::system_clock::now(),
                                            time::system_clock::now() + time::days(1));

  int count = 0;
  face.onSendData.connect([&](const Data& response) {
    count++;
    BOOST_CHECK(security::verifySignature(response, cert));
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

    auto challengeList = Requester::onNewRenewRevokeResponse(state, response);
    auto ca_encryption_key = ca.getCaStorage()->getRequest(readString(contentBlock.get(tlv::RequestId))).m_encryptionKey;
    BOOST_CHECK_EQUAL_COLLECTIONS(state.m_aesKey, state.m_aesKey + sizeof(state.m_aesKey),
                                  ca_encryption_key.value(), ca_encryption_key.value() + ca_encryption_key.value_size());
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

  util::DummyClientFace face(io, m_keyChain, {true, true});
  CaModule ca(face, m_keyChain, "tests/unit-tests/config-files/config-ca-1");
  advanceClocks(time::milliseconds(20), 60);

  CaProfile item;
  item.m_caPrefix = Name("/ndn");
  item.m_cert = std::make_shared<security::Certificate>(cert);
  RequesterState state(m_keyChain, item, RequestType::NEW);
  auto current_tp = time::system_clock::now();
  auto interest1 = Requester::genNewInterest(state, Name("/ndn/zhiyi"), current_tp, current_tp - time::hours(1));
  auto interest2 = Requester::genNewInterest(state, Name("/ndn/zhiyi"), current_tp, current_tp + time::days(361));
  auto interest3 = Requester::genNewInterest(state, Name("/ndn/zhiyi"), current_tp - time::hours(1), current_tp + time::hours(2));
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

BOOST_AUTO_TEST_CASE(HandleNewWithLongSuffix)
{
  auto identity = addIdentity(Name("/ndn"));
  auto key = identity.getDefaultKey();
  auto cert = key.getDefaultCertificate();

  util::DummyClientFace face(io, m_keyChain, {true, true});
  CaModule ca(face, m_keyChain, "tests/unit-tests/config-files/config-ca-1", "ca-storage-memory");
  advanceClocks(time::milliseconds(20), 60);

  CaProfile item;
  item.m_caPrefix = Name("/ndn");
  item.m_cert = std::make_shared<security::Certificate>(cert);
  RequesterState state(m_keyChain, item, RequestType::NEW);

  auto interest1 = Requester::genNewInterest(state, Name("/ndn/a"), time::system_clock::now(),
                                              time::system_clock::now() + time::days(1));
  auto interest2 = Requester::genNewInterest(state, Name("/ndn/a/b"), time::system_clock::now(),
                                              time::system_clock::now() + time::days(1));
  auto interest3 = Requester::genNewInterest(state, Name("/ndn/a/b/c/d"), time::system_clock::now(),
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
      BOOST_CHECK_EXCEPTION(readNonNegativeInteger(contentTlv.get(tlv::ErrorCode)), std::runtime_error,
                            [](const auto& e) { return true; });
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

  util::DummyClientFace face(io, m_keyChain, {true, true});
  CaModule ca(face, m_keyChain, "tests/unit-tests/config-files/config-ca-1");
  advanceClocks(time::milliseconds(20), 60);

  CaProfile item;
  item.m_caPrefix = Name("/ndn");
  item.m_cert = std::make_shared<security::Certificate>(cert);
  RequesterState state(m_keyChain, item, RequestType::NEW);

  auto current_tp = time::system_clock::now();
  auto interest1 = Requester::genNewInterest(state, Name("/ndn"), current_tp, current_tp + time::days(1));
  auto interest2 = Requester::genNewInterest(state, Name("/ndn/a/b/c/d"), current_tp, current_tp + time::days(1));
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

  util::DummyClientFace face(io, m_keyChain, {true, true});
  CaModule ca(face, m_keyChain, "tests/unit-tests/config-files/config-ca-1", "ca-storage-memory");
  advanceClocks(time::milliseconds(20), 60);

  // generate NEW Interest
  CaProfile item;
  item.m_caPrefix = Name("/ndn");
  item.m_cert = std::make_shared<security::Certificate>(cert);
  RequesterState state(m_keyChain, item, RequestType::NEW);

  auto newInterest = Requester::genNewInterest(state, Name("/ndn/zhiyi"), time::system_clock::now(),
                                                time::system_clock::now() + time::days(1));

  // generate CHALLENGE Interest
  shared_ptr<Interest> challengeInterest = nullptr;
  shared_ptr<Interest> challengeInterest2 = nullptr;
  shared_ptr<Interest> challengeInterest3 = nullptr;

  int count = 0;
  face.onSendData.connect([&](const Data& response) {
    if (Name("/ndn/CA/NEW").isPrefixOf(response.getName())) {
      auto challengeList = Requester::onNewRenewRevokeResponse(state, response);
      auto paramList = Requester::selectOrContinueChallenge(state, "pin");
      challengeInterest = Requester::genChallengeInterest(state, std::move(paramList));
    }
    else if (Name("/ndn/CA/CHALLENGE").isPrefixOf(response.getName()) && count == 0) {
      count++;
      BOOST_CHECK(security::verifySignature(response, cert));

      Requester::onChallengeResponse(state, response);
      BOOST_CHECK(state.m_status == Status::CHALLENGE);
      BOOST_CHECK_EQUAL(state.m_challengeStatus, ChallengePin::NEED_CODE);
      auto paramList = Requester::selectOrContinueChallenge(state, "pin");
      challengeInterest2 = Requester::genChallengeInterest(state, std::move(paramList));
    }
    else if (Name("/ndn/CA/CHALLENGE").isPrefixOf(response.getName()) && count == 1) {
      count++;
      BOOST_CHECK(security::verifySignature(response, cert));

      Requester::onChallengeResponse(state, response);
      BOOST_CHECK(state.m_status == Status::CHALLENGE);
      BOOST_CHECK_EQUAL(state.m_challengeStatus, ChallengePin::WRONG_CODE);

      auto paramList = Requester::selectOrContinueChallenge(state, "pin");
      auto request = ca.getCertificateRequest(*challengeInterest2);
      auto secret = request.m_challengeState->m_secrets.get(ChallengePin::PARAMETER_KEY_CODE, "");
      std::get<1>(paramList[0]) = secret;
      challengeInterest3 = Requester::genChallengeInterest(state, std::move(paramList));
      std::cout << "CHALLENGE Interest Size: " << challengeInterest3->wireEncode().size() << std::endl;
    }
    else if (Name("/ndn/CA/CHALLENGE").isPrefixOf(response.getName()) && count == 2) {
      count++;
      BOOST_CHECK(security::verifySignature(response, cert));
      Requester::onChallengeResponse(state, response);
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

  util::DummyClientFace face(io, {true, true});
  CaModule ca(face, m_keyChain, "tests/unit-tests/config-files/config-ca-1", "ca-storage-memory");
  advanceClocks(time::milliseconds(20), 60);

  //generate a certificate
  auto clientIdentity = m_keyChain.createIdentity("/ndn/qwerty");
  auto clientKey = clientIdentity.getDefaultKey();
  security::Certificate clientCert;
  clientCert.setName(Name(clientKey.getName()).append("cert-request").appendVersion());
  clientCert.setContentType(ndn::tlv::ContentType_Key);
  clientCert.setFreshnessPeriod(time::hours(24));
  clientCert.setContent(clientKey.getPublicKey().data(), clientKey.getPublicKey().size());
  SignatureInfo signatureInfo;
  signatureInfo.setValidityPeriod(security::ValidityPeriod(time::system_clock::now(),
                                                           time::system_clock::now() + time::hours(10)));
  m_keyChain.sign(clientCert, signingByKey(clientKey.getName()).setSignatureInfo(signatureInfo));
  CaState certRequest(Name("/ndn"), "122", RequestType::NEW, Status::SUCCESS, clientCert, makeEmptyBlock(ndn::tlv::ContentType_Key));
  auto issuedCert = ca.issueCertificate(certRequest);

  CaProfile item;
  item.m_caPrefix = Name("/ndn");
  item.m_cert = std::make_shared<security::Certificate>(cert);
  RequesterState state(m_keyChain, item, RequestType::REVOKE);

  auto interest = Requester::genRevokeInterest(state, issuedCert);

  int count = 0;
  face.onSendData.connect([&](const Data& response) {
    count++;
    BOOST_CHECK(security::verifySignature(response, cert));
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

    auto challengeList = Requester::onNewRenewRevokeResponse(state, response);
    auto ca_encryption_key = ca.getCaStorage()->getRequest(readString(contentBlock.get(tlv::RequestId))).m_encryptionKey;
    BOOST_CHECK_EQUAL_COLLECTIONS(state.m_aesKey, state.m_aesKey + sizeof(state.m_aesKey),
                                  ca_encryption_key.value(), ca_encryption_key.value() + ca_encryption_key.value_size());
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

  util::DummyClientFace face(io, {true, true});
  CaModule ca(face, m_keyChain, "tests/unit-tests/config-files/config-ca-1", "ca-storage-memory");
  advanceClocks(time::milliseconds(20), 60);

  // generate a certificate
  auto clientIdentity = m_keyChain.createIdentity("/ndn/qwerty");
  auto clientKey = clientIdentity.getDefaultKey();
  security::Certificate clientCert;
  clientCert.setName(Name(clientKey.getName()).append("NDNCERT").append(std::to_string(1473283247810732701)));
  clientCert.setContentType(ndn::tlv::ContentType_Key);
  clientCert.setFreshnessPeriod(time::hours(24));
  clientCert.setContent(clientKey.getPublicKey().data(), clientKey.getPublicKey().size());
  SignatureInfo signatureInfo;
  signatureInfo.setValidityPeriod(security::ValidityPeriod(time::system_clock::now(),
                                                           time::system_clock::now() + time::hours(10)));
  m_keyChain.sign(clientCert, signingByKey(clientKey.getName()).setSignatureInfo(signatureInfo));

  CaProfile item;
  item.m_caPrefix = Name("/ndn");
  item.m_cert = std::make_shared<security::Certificate>(cert);
  RequesterState state(m_keyChain, item, RequestType::NEW);

  auto interest = Requester::genRevokeInterest(state, clientCert);

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

BOOST_AUTO_TEST_SUITE_END()  // TestCaModule

} // namespace tests
} // namespace ndncert
} // namespace ndn
