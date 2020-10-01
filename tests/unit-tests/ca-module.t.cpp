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
#include "challenge-module.hpp"
#include "challenge-modules/challenge-email.hpp"
#include "challenge-modules/challenge-pin.hpp"
#include "client-module.hpp"
#include "protocol-detail/info.hpp"
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

  auto identity = addIdentity(Name("/ndn/site2"));
  auto key = identity.getDefaultKey();
  auto cert = key.getDefaultCertificate();
  ca.getCaStorage()->addCertificate("111", cert);
  BOOST_CHECK_EQUAL(ca.getCaStorage()->getCertificate("111").getIdentity(), Name("/ndn/site2"));

  advanceClocks(time::milliseconds(20), 60);
  BOOST_CHECK_EQUAL(ca.m_registeredPrefixHandles.size(), 2);
  BOOST_CHECK_EQUAL(ca.m_interestFilterHandles.size(), 5);  // onInfo, onProbe, onNew, onChallenge, onRevoke
}

BOOST_AUTO_TEST_CASE(HandleInfo)
{
  auto identity = addIdentity(Name("/ndn"));
  auto key = identity.getDefaultKey();
  auto cert = key.getDefaultCertificate();

  util::DummyClientFace face(io, m_keyChain, {true, true});
  CaModule ca(face, m_keyChain, "tests/unit-tests/config-files/config-ca-1", "ca-storage-memory");
  advanceClocks(time::milliseconds(20), 60);

  Interest interest("/ndn/CA/INFO");
  interest.setCanBePrefix(false);

  int count = 0;
  face.onSendData.connect([&](const Data& response) {
    count++;
    BOOST_CHECK(security::verifySignature(response, cert));
    auto contentBlock = response.getContent();
    contentBlock.parse();
    auto caItem = INFO::decodeDataContent(contentBlock);
    BOOST_CHECK_EQUAL(caItem.m_caPrefix, "/ndn");
    BOOST_CHECK_EQUAL(caItem.m_probeParameterKeys.size(), 1);
    BOOST_CHECK_EQUAL(caItem.m_cert->wireEncode(), cert.wireEncode());
    BOOST_CHECK_EQUAL(caItem.m_caInfo, "ndn testbed ca");
  });
  face.receive(interest);

  advanceClocks(time::milliseconds(20), 60);
  BOOST_CHECK_EQUAL(count, 1);
}

BOOST_AUTO_TEST_CASE(HandleProbe)
{
  auto identity = addIdentity(Name("/ndn"));
  auto key = identity.getDefaultKey();
  auto cert = key.getDefaultCertificate();

  util::DummyClientFace face(io, m_keyChain, {true, true});
  CaModule ca(face, m_keyChain, "tests/unit-tests/config-files/config-ca-1", "ca-storage-memory");
  ca.setNameAssignmentFunction([&](const std::vector<std::tuple<std::string, std::string>>) -> std::vector<std::string> {
    std::vector<std::string> result;
    result.push_back("example");
    return result;
  });
  advanceClocks(time::milliseconds(20), 60);

  Interest interest("/ndn/CA/PROBE");
  interest.setCanBePrefix(false);

  Block paramTLV = makeEmptyBlock(tlv::ApplicationParameters);
  paramTLV.push_back(makeStringBlock(tlv_parameter_key, "name"));
  paramTLV.push_back(makeStringBlock(tlv_parameter_value, "zhiyi"));
  paramTLV.encode();

  interest.setApplicationParameters(paramTLV);

  int count = 0;
  face.onSendData.connect([&](const Data& response) {
    count++;
    BOOST_CHECK(security::verifySignature(response, cert));
    Block contentBlock = response.getContent();
    contentBlock.parse();
    Block probeResponse = contentBlock.get(tlv_probe_response);
    probeResponse.parse();
    Name caName;
    caName.wireDecode(probeResponse.get(tlv::Name));
    BOOST_CHECK_EQUAL(caName, "/ndn/example");
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

  Block paramTLV = makeEmptyBlock(tlv::ApplicationParameters);
  paramTLV.push_back(makeStringBlock(tlv_parameter_key, "name"));
  paramTLV.push_back(makeStringBlock(tlv_parameter_value, "zhiyi"));
  paramTLV.encode();

  interest.setApplicationParameters(paramTLV);

  int count = 0;
  face.onSendData.connect([&](const Data& response) {
    count++;
    BOOST_CHECK(security::verifySignature(response, cert));
    auto contentBlock = response.getContent();
    contentBlock.parse();
    auto probeResponseBlock = contentBlock.get(tlv_probe_response);
    probeResponseBlock.parse();
    Name caPrefix;
    caPrefix.wireDecode(probeResponseBlock.get(tlv::Name));
    BOOST_CHECK(caPrefix != "");
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

  ClientModule client(m_keyChain);
  CaConfigItem item;
  item.m_caPrefix = Name("/ndn");
  item.m_cert = std::make_shared<security::v2::Certificate>(cert);
  client.getClientConf().m_caItems.push_back(item);

  auto interest = client.generateNewInterest(time::system_clock::now(),
                                             time::system_clock::now() + time::days(1),
                                             Name("/ndn/zhiyi"));

  int count = 0;
  face.onSendData.connect([&](const Data& response) {
    count++;
    BOOST_CHECK(security::verifySignature(response, cert));
    auto contentBlock = response.getContent();
    contentBlock.parse();

    BOOST_CHECK(readString(contentBlock.get(tlv_ecdh_pub)) != "");
    BOOST_CHECK(readString(contentBlock.get(tlv_salt)) != "");
    BOOST_CHECK(readString(contentBlock.get(tlv_request_id)) != "");

    auto challengeBlockCount = 0;
    for (auto const& element : contentBlock.elements()) {
      if (element.type() == tlv_challenge) {
        challengeBlockCount++;
      }
    }

    BOOST_CHECK(challengeBlockCount != 0);

    client.onNewRenewRevokeResponse(response);
    auto ca_encryption_key = ca.getCaStorage()->getRequest(readString(contentBlock.get(tlv_request_id))).m_encryptionKey;
    BOOST_CHECK_EQUAL_COLLECTIONS(client.m_aesKey, client.m_aesKey + sizeof(client.m_aesKey),
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

  ClientModule client(m_keyChain);
  CaConfigItem item;
  item.m_caPrefix = Name("/ndn");
  item.m_cert = std::make_shared<security::v2::Certificate>(cert);
  client.getClientConf().m_caItems.push_back(item);
  auto current_tp = time::system_clock::now();
  auto interest1 = client.generateNewInterest(current_tp, current_tp - time::hours(1),
                                              Name("/ndn/zhiyi"));
  auto interest2 = client.generateNewInterest(current_tp, current_tp + time::days(361),
                                              Name("/ndn/zhiyi"));
  auto interest3 = client.generateNewInterest(current_tp - time::hours(1),
                                              current_tp + time::hours(2),
                                              Name("/ndn/zhiyi"));
  face.onSendData.connect([&](const Data& response) {
    auto contentTlv = response.getContent();
    contentTlv.parse();
    auto errorCode = static_cast<ErrorCode>(readNonNegativeInteger(contentTlv.get(tlv_error_code)));
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

  ClientModule client(m_keyChain);
  CaConfigItem item;
  item.m_caPrefix = Name("/ndn");
  item.m_cert = std::make_shared<security::v2::Certificate>(cert);
  client.getClientConf().m_caItems.push_back(item);

  auto interest1 = client.generateNewInterest(time::system_clock::now(),
                                              time::system_clock::now() + time::days(1),
                                              Name("/ndn/a"));
  auto interest2 = client.generateNewInterest(time::system_clock::now(),
                                              time::system_clock::now() + time::days(1),
                                              Name("/ndn/a/b"));
  auto interest3 = client.generateNewInterest(time::system_clock::now(),
                                              time::system_clock::now() + time::days(1),
                                              Name("/ndn/a/b/c/d"));

  face.onSendData.connect([&](const Data& response) {
    auto contentTlv = response.getContent();
    contentTlv.parse();
    if (interest3->getName().isPrefixOf(response.getName())) {
      auto errorCode = static_cast<ErrorCode>(readNonNegativeInteger(contentTlv.get(tlv_error_code)));
      BOOST_CHECK(errorCode != ErrorCode::NO_ERROR);
    }
    else {
      // should successfully get responses
      BOOST_CHECK_EXCEPTION(readNonNegativeInteger(contentTlv.get(tlv_error_code)), std::runtime_error,
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

  ClientModule client(m_keyChain);
  CaConfigItem item;
  item.m_caPrefix = Name("/ndn");
  item.m_cert = std::make_shared<security::v2::Certificate>(cert);
  client.getClientConf().m_caItems.push_back(item);
  auto current_tp = time::system_clock::now();
  auto interest1 = client.generateNewInterest(current_tp, current_tp + time::days(1), Name("/ndn"));
  auto interest2 = client.generateNewInterest(current_tp, current_tp + time::days(1), Name("/ndn/a/b/c/d"));
  face.onSendData.connect([&](const Data& response) {
    auto contentTlv = response.getContent();
    contentTlv.parse();
    auto errorCode = static_cast<ErrorCode>(readNonNegativeInteger(contentTlv.get(tlv_error_code)));
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
  ClientModule client(m_keyChain);
  CaConfigItem item;
  item.m_caPrefix = Name("/ndn");
  item.m_cert = std::make_shared<security::v2::Certificate>(cert);
  client.getClientConf().m_caItems.push_back(item);
  auto newInterest = client.generateNewInterest(time::system_clock::now(),
                                                time::system_clock::now() + time::days(1), Name("/ndn/zhiyi"));

  // generate CHALLENGE Interest
  ChallengePin pinChallenge;
  shared_ptr<Interest> challengeInterest = nullptr;
  shared_ptr<Interest> challengeInterest2 = nullptr;
  shared_ptr<Interest> challengeInterest3 = nullptr;

  int count = 0;
  face.onSendData.connect([&](const Data& response) {
    if (Name("/ndn/CA/NEW").isPrefixOf(response.getName())) {
      client.onNewRenewRevokeResponse(response);
      auto paramList = pinChallenge.getRequestedParameterList(client.m_status, client.m_challengeStatus);
      challengeInterest = client.generateChallengeInterest(pinChallenge.genChallengeRequestTLV(client.m_status,
                                                                                               client.m_challengeStatus,
                                                                                               std::move(paramList)));
    }
    else if (Name("/ndn/CA/CHALLENGE").isPrefixOf(response.getName()) && count == 0) {
      count++;
      BOOST_CHECK(security::verifySignature(response, cert));

      client.onChallengeResponse(response);
      BOOST_CHECK(client.m_status == Status::CHALLENGE);
      BOOST_CHECK_EQUAL(client.m_challengeStatus, ChallengePin::NEED_CODE);

      auto paramList = pinChallenge.getRequestedParameterList(client.m_status, client.m_challengeStatus);
      challengeInterest2 = client.generateChallengeInterest(pinChallenge.genChallengeRequestTLV(client.m_status,
                                                                                                client.m_challengeStatus,
                                                                                                std::move(paramList)));
    }
    else if (Name("/ndn/CA/CHALLENGE").isPrefixOf(response.getName()) && count == 1) {
      count++;
      BOOST_CHECK(security::verifySignature(response, cert));

      client.onChallengeResponse(response);
      BOOST_CHECK(client.m_status == Status::CHALLENGE);
      BOOST_CHECK_EQUAL(client.m_challengeStatus, ChallengePin::WRONG_CODE);

      auto paramList = pinChallenge.getRequestedParameterList(client.m_status, client.m_challengeStatus);
      auto request = ca.getCertificateRequest(*challengeInterest2);
      auto secret = request.m_challengeState->m_secrets.get(ChallengePin::PARAMETER_KEY_CODE, "");
      std::get<1>(paramList[0]) = secret;
      challengeInterest3 = client.generateChallengeInterest(pinChallenge.genChallengeRequestTLV(client.m_status,
                                                                                                client.m_challengeStatus,
                                                                                                std::move(paramList)));
    }
    else if (Name("/ndn/CA/CHALLENGE").isPrefixOf(response.getName()) && count == 2) {
      count++;
      BOOST_CHECK(security::verifySignature(response, cert));

      client.onChallengeResponse(response);
      BOOST_CHECK(client.m_status == Status::SUCCESS);
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
  security::v2::Certificate clientCert;
  clientCert.setName(Name(clientKey.getName()).append("cert-request").appendVersion());
  clientCert.setContentType(tlv::ContentType_Key);
  clientCert.setFreshnessPeriod(time::hours(24));
  clientCert.setContent(clientKey.getPublicKey().data(), clientKey.getPublicKey().size());
  SignatureInfo signatureInfo;
  signatureInfo.setValidityPeriod(security::ValidityPeriod(time::system_clock::now(),
                                                           time::system_clock::now() + time::hours(10)));
  m_keyChain.sign(clientCert, signingByKey(clientKey.getName()).setSignatureInfo(signatureInfo));
  RequestState certRequest(Name("/ndn"), "122", RequestType::NEW, Status::SUCCESS, clientCert, makeEmptyBlock(tlv::ContentType_Key));
  auto issuedCert = ca.issueCertificate(certRequest);

  ClientModule client(m_keyChain);
  CaConfigItem item;
  item.m_caPrefix = Name("/ndn");
  item.m_cert = std::make_shared<security::v2::Certificate>(cert);
  client.getClientConf().m_caItems.push_back(item);

  auto interest = client.generateRevokeInterest(issuedCert);

  int count = 0;
  face.onSendData.connect([&](const Data& response) {
    count++;
    BOOST_CHECK(security::verifySignature(response, cert));
    auto contentBlock = response.getContent();
    contentBlock.parse();

    BOOST_CHECK(readString(contentBlock.get(tlv_ecdh_pub)) != "");
    BOOST_CHECK(readString(contentBlock.get(tlv_salt)) != "");
    BOOST_CHECK(readString(contentBlock.get(tlv_request_id)) != "");

    auto challengeBlockCount = 0;
    for (auto const& element : contentBlock.elements()) {
      if (element.type() == tlv_challenge) {
        challengeBlockCount++;
      }
    }

    BOOST_CHECK(challengeBlockCount != 0);

    client.onNewRenewRevokeResponse(response);
    auto ca_encryption_key = ca.getCaStorage()->getRequest(readString(contentBlock.get(tlv_request_id))).m_encryptionKey;
    BOOST_CHECK_EQUAL_COLLECTIONS(client.m_aesKey, client.m_aesKey + sizeof(client.m_aesKey),
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
  security::v2::Certificate clientCert;
  clientCert.setName(Name(clientKey.getName()).append("NDNCERT").append(std::to_string(1473283247810732701)));
  clientCert.setContentType(tlv::ContentType_Key);
  clientCert.setFreshnessPeriod(time::hours(24));
  clientCert.setContent(clientKey.getPublicKey().data(), clientKey.getPublicKey().size());
  SignatureInfo signatureInfo;
  signatureInfo.setValidityPeriod(security::ValidityPeriod(time::system_clock::now(),
                                                           time::system_clock::now() + time::hours(10)));
  m_keyChain.sign(clientCert, signingByKey(clientKey.getName()).setSignatureInfo(signatureInfo));

  ClientModule client(m_keyChain);
  CaConfigItem item;
  item.m_caPrefix = Name("/ndn");
  item.m_cert = std::make_shared<security::v2::Certificate>(cert);
  client.getClientConf().m_caItems.push_back(item);

  auto interest = client.generateRevokeInterest(clientCert);

  bool receiveData = false;
  face.onSendData.connect([&](const Data& response) {
    receiveData = true;
    auto contentTlv = response.getContent();
    contentTlv.parse();
    BOOST_CHECK(static_cast<ErrorCode>(readNonNegativeInteger(contentTlv.get(tlv_error_code))) != ErrorCode::NO_ERROR);
  });
  face.receive(*interest);

  advanceClocks(time::milliseconds(20), 60);
  BOOST_CHECK_EQUAL(receiveData, true);
}

BOOST_AUTO_TEST_SUITE_END()  // TestCaModule

}  // namespace tests
}  // namespace ndncert
}  // namespace ndn
