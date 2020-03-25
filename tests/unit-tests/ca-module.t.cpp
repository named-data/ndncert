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
#include "database-fixture.hpp"
#include "client-module.hpp"
#include "challenge-module.hpp"
#include "challenge-module/challenge-pin.hpp"
#include "challenge-module/challenge-email.hpp"

#include <ndn-cxx/util/dummy-client-face.hpp>
#include <ndn-cxx/security/signing-helpers.hpp>
#include <ndn-cxx/security/transform/public-key.hpp>
#include <ndn-cxx/security/verification-helpers.hpp>

namespace ndn {
namespace ndncert {
namespace tests {

BOOST_FIXTURE_TEST_SUITE(TestCaModule, DatabaseFixture)

BOOST_AUTO_TEST_CASE(Initialization)
{
  util::DummyClientFace face(io, {true, true});
  CaModule ca(face, m_keyChain, "tests/unit-tests/ca.conf.test", "ca-storage-memory");
  BOOST_CHECK_EQUAL(ca.getCaConf().m_caName, "/ndn");

  auto identity = addIdentity(Name("/ndn/site2"));
  auto key = identity.getDefaultKey();
  auto cert = key.getDefaultCertificate();
  ca.getCaStorage()->addCertificate("111", cert);
  BOOST_CHECK_EQUAL(ca.getCaStorage()->getCertificate("111").getIdentity(), Name("/ndn/site2"));

  advanceClocks(time::milliseconds(20), 60);
  BOOST_CHECK_EQUAL(ca.m_registeredPrefixHandles.size(), 2);
  BOOST_CHECK_EQUAL(ca.m_interestFilterHandles.size(), 4);
}

BOOST_AUTO_TEST_CASE(HandleProbe)
{
  auto identity = addIdentity(Name("/ndn"));
  auto key = identity.getDefaultKey();
  auto cert = key.getDefaultCertificate();

  util::DummyClientFace face(io, {true, true});
  CaModule ca(face, m_keyChain, "tests/unit-tests/ca.conf.test", "ca-storage-memory");
  ca.setProbeHandler([&] (const JsonSection& probeInfo) {
      return "example";
    });
  advanceClocks(time::milliseconds(20), 60);

  Interest interest("/ndn/CA/PROBE");
  interest.setCanBePrefix(false);
  JsonSection paramJson;
  paramJson.add(JSON_CLIENT_PROBE_INFO, "zhiyi");
  interest.setApplicationParameters(ClientModule::paramFromJson(paramJson));

  int count = 0;
  face.onSendData.connect([&] (const Data& response) {
      count++;
      BOOST_CHECK(security::verifySignature(response, cert));
      auto contentJson = ClientModule::getJsonFromData(response);
      BOOST_CHECK_EQUAL(contentJson.get<std::string>(JSON_CA_NAME), "/ndn/example");
    });
  face.receive(interest);

  advanceClocks(time::milliseconds(20), 60);
  BOOST_CHECK_EQUAL(count, 1);
}

BOOST_AUTO_TEST_CASE(HandleProbeInfo)
{
  auto identity = addIdentity(Name("/ndn"));
  auto key = identity.getDefaultKey();
  auto cert = key.getDefaultCertificate();

  util::DummyClientFace face(io, {true, true});
  CaModule ca(face, m_keyChain, "tests/unit-tests/ca.conf.test", "ca-storage-memory");
  ca.setProbeHandler([&] (const JsonSection& probeInfo) {
      return "example";
    });
  advanceClocks(time::milliseconds(20), 60);

  Interest interest("/ndn/CA/PROBE/INFO");
  interest.setCanBePrefix(false);

  int count = 0;
  face.onSendData.connect([&] (const Data& response) {
      count++;
      BOOST_CHECK(security::verifySignature(response, cert));
      auto contentJson = ClientModule::getJsonFromData(response);
      auto caItem = ClientConfig::extractCaItem(contentJson);
      BOOST_CHECK_EQUAL(caItem.m_caName, "/ndn");
      BOOST_CHECK_EQUAL(caItem.m_probe, "");
      BOOST_CHECK_EQUAL(caItem.m_anchor.wireEncode(), cert.wireEncode());
      BOOST_CHECK_EQUAL(caItem.m_caInfo, "ndn testbed ca");
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

  util::DummyClientFace face(io, {true, true});
  CaModule ca(face, m_keyChain, "tests/unit-tests/ca.conf.test", "ca-storage-memory");
  advanceClocks(time::milliseconds(20), 60);

  Interest interest("/ndn/CA/PROBE");
  interest.setCanBePrefix(false);
  JsonSection paramJson;
  paramJson.add(JSON_CLIENT_PROBE_INFO, "zhiyi");
  interest.setApplicationParameters(ClientModule::paramFromJson(paramJson));

  int count = 0;
  face.onSendData.connect([&] (const Data& response) {
      count++;
      BOOST_CHECK(security::verifySignature(response, cert));
      auto contentJson = ClientModule::getJsonFromData(response);
      BOOST_CHECK(contentJson.get<std::string>(JSON_CA_NAME) != "");
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

  util::DummyClientFace face(io, {true, true});
  CaModule ca(face, m_keyChain, "tests/unit-tests/ca.conf.test", "ca-storage-memory");
  advanceClocks(time::milliseconds(20), 60);

  ClientModule client(m_keyChain);
  ClientCaItem item;
  item.m_caName = Name("/ndn");
  item.m_anchor = cert;
  client.getClientConf().m_caItems.push_back(item);

  auto interest = client.generateNewInterest(time::system_clock::now(),
                                             time::system_clock::now() + time::days(10),
                                             Name("/ndn/zhiyi"));

  int count = 0;
  face.onSendData.connect([&] (const Data& response) {
      count++;
      BOOST_CHECK(security::verifySignature(response, cert));
      auto contentJson = ClientModule::getJsonFromData(response);
      BOOST_CHECK(contentJson.get<std::string>(JSON_CA_ECDH) != "");
      BOOST_CHECK(contentJson.get<std::string>(JSON_CA_SALT) != "");
      BOOST_CHECK(contentJson.get<std::string>(JSON_CA_REQUEST_ID) != "");
      auto challengesJson = contentJson.get_child(JSON_CA_CHALLENGES);
      BOOST_CHECK(challengesJson.size() != 0);

      client.onNewResponse(response);
      BOOST_CHECK_EQUAL_COLLECTIONS(client.m_aesKey, client.m_aesKey + sizeof(client.m_aesKey),
                                    ca.m_aesKey, ca.m_aesKey + sizeof(ca.m_aesKey));
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

  util::DummyClientFace face(io, {true, true});
  CaModule ca(face, m_keyChain, "tests/unit-tests/ca.conf.test");
  advanceClocks(time::milliseconds(20), 60);

  ClientModule client(m_keyChain);
  ClientCaItem item;
  item.m_caName = Name("/ndn");
  item.m_anchor = cert;
  client.getClientConf().m_caItems.push_back(item);
  auto current_tp = time::system_clock::now();
  auto interest1 = client.generateNewInterest(current_tp, current_tp - time::hours(1),
                                              Name("/ndn/zhiyi"));
  auto interest2 = client.generateNewInterest(current_tp, current_tp + time::days(361),
                                              Name("/ndn/zhiyi"));
  auto interest3 = client.generateNewInterest(current_tp - time::hours(1),
                                              current_tp + time::hours(2),
                                              Name("/ndn/zhiyi"));
  face.onSendData.connect([&] (const Data& response) {
      BOOST_CHECK(false);
    });
  face.receive(*interest1);
  face.receive(*interest2);
  face.receive(*interest3);

  advanceClocks(time::milliseconds(20), 60);
}

BOOST_AUTO_TEST_CASE(HandleNewWithProbeToken)
{
  auto identity = addIdentity(Name("/ndn"));
  auto key = identity.getDefaultKey();
  auto cert = key.getDefaultCertificate();

  util::DummyClientFace face(io, {true, true});
  CaModule ca(face, m_keyChain, "tests/unit-tests/ca.conf.test", "ca-storage-memory");
  ca.m_config.m_probe = "email";
  advanceClocks(time::milliseconds(20), 60);

  ClientModule client(m_keyChain);
  ClientCaItem item;
  item.m_caName = Name("/ndn");
  item.m_anchor = cert;
  client.getClientConf().m_caItems.push_back(item);

  auto data = make_shared<Data>(Name("/ndn/CA/PROBE/123"));
  m_keyChain.sign(*data, signingByIdentity(ca.m_config.m_caName));

  auto interest = client.generateNewInterest(time::system_clock::now(),
                                             time::system_clock::now() + time::days(10),
                                             Name("/ndn/zhiyi"), data);

  int count = 0;
  face.onSendData.connect([&] (const Data& response) {
      count++;
      BOOST_CHECK(security::verifySignature(response, cert));
    });
  face.receive(*interest);

  advanceClocks(time::milliseconds(20), 60);
  BOOST_CHECK_EQUAL(count, 1);
}

BOOST_AUTO_TEST_CASE(HandleChallenge)
{
  auto identity = addIdentity(Name("/ndn"));
  auto key = identity.getDefaultKey();
  auto cert = key.getDefaultCertificate();

  util::DummyClientFace face(io, {true, true});
  CaModule ca(face, m_keyChain, "tests/unit-tests/ca.conf.test", "ca-storage-memory");
  advanceClocks(time::milliseconds(20), 60);

  // generate NEW Interest
  ClientModule client(m_keyChain);
  ClientCaItem item;
  item.m_caName = Name("/ndn");
  item.m_anchor = cert;
  client.getClientConf().m_caItems.push_back(item);
  auto newInterest = client.generateNewInterest(time::system_clock::now(),
                                                time::system_clock::now() + time::days(10), Name("/ndn/zhiyi"));

  // generate CHALLENGE Interest
  ChallengePin pinChallenge;
  shared_ptr<Interest> challengeInterest = nullptr;
  shared_ptr<Interest> challengeInterest2 = nullptr;
  shared_ptr<Interest> challengeInterest3 = nullptr;

  int count = 0;
  face.onSendData.connect([&] (const Data& response) {
    if (Name("/ndn/CA/NEW").isPrefixOf(response.getName())) {
      auto contentJson = ClientModule::getJsonFromData(response);
      client.onNewResponse(response);
      auto paramJson = pinChallenge.getRequirementForChallenge(client.m_status, client.m_challengeStatus);
      challengeInterest = client.generateChallengeInterest(pinChallenge.genChallengeRequestJson(client.m_status,
                                                                                                client.m_challengeStatus,
                                                                                                paramJson));
    }
    else if (Name("/ndn/CA/CHALLENGE").isPrefixOf(response.getName()) && count == 0) {
      count++;
      BOOST_CHECK(security::verifySignature(response, cert));

      client.onChallengeResponse(response);
      BOOST_CHECK_EQUAL(client.m_status, STATUS_CHALLENGE);
      BOOST_CHECK_EQUAL(client.m_challengeStatus, ChallengePin::NEED_CODE);

      auto paramJson = pinChallenge.getRequirementForChallenge(client.m_status, client.m_challengeStatus);
      challengeInterest2 = client.generateChallengeInterest(pinChallenge.genChallengeRequestJson(client.m_status,
                                                                                                 client.m_challengeStatus,
                                                                                                 paramJson));
    }
    else if (Name("/ndn/CA/CHALLENGE").isPrefixOf(response.getName()) && count == 1) {
      count++;
      BOOST_CHECK(security::verifySignature(response, cert));

      client.onChallengeResponse(response);
      BOOST_CHECK_EQUAL(client.m_status, STATUS_CHALLENGE);
      BOOST_CHECK_EQUAL(client.m_challengeStatus, ChallengePin::WRONG_CODE);

      auto paramJson = pinChallenge.getRequirementForChallenge(client.m_status, client.m_challengeStatus);
      auto request = ca.getCertificateRequest(*challengeInterest2);
      auto secret = request.m_challengeSecrets.get(ChallengePin::JSON_PIN_CODE, "");
      for (auto& i : paramJson) {
        if (i.first == ChallengePin::JSON_PIN_CODE)
          i.second.put("", secret);
      }
      challengeInterest3 = client.generateChallengeInterest(pinChallenge.genChallengeRequestJson(client.m_status,
                                                                                                 client.m_challengeStatus,
                                                                                                 paramJson));
    }
    else if (Name("/ndn/CA/CHALLENGE").isPrefixOf(response.getName()) && count == 2) {
      count++;
      BOOST_CHECK(security::verifySignature(response, cert));

      client.onChallengeResponse(response);
      BOOST_CHECK_EQUAL(client.m_status, STATUS_SUCCESS);
      BOOST_CHECK_EQUAL(client.m_challengeStatus, CHALLENGE_STATUS_SUCCESS);
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

BOOST_AUTO_TEST_SUITE_END() // TestCaModule

} // namespace tests
} // namespace ndncert
} // namespace ndn
