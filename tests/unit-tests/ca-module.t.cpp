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

#include "database-fixture.hpp"
#include "client-module.hpp"
#include "challenge-module.hpp"

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
  util::DummyClientFace face(m_io, {true, true});
  CaModule ca(face, m_keyChain, "tests/unit-tests/ca.conf.test");
  BOOST_CHECK_EQUAL(ca.getCaConf().m_caItems.front().m_caName.toUri(), "/ndn");
  BOOST_CHECK_EQUAL(ca.getCaConf().m_caItems.back().m_caName.toUri(), "/ndn/site1");

  auto identity = addIdentity(Name("/ndn/site2"));
  auto key = identity.getDefaultKey();
  auto cert = key.getDefaultCertificate();
  ca.getCaStorage()->addCertificate("111", cert);
  BOOST_CHECK_EQUAL(ca.getCaStorage()->getCertificate("111").getIdentity(), Name("/ndn/site2"));

  advanceClocks(time::milliseconds(20), 60);
  BOOST_CHECK_EQUAL(ca.m_registeredPrefixIds.size(), 4);
  BOOST_CHECK_EQUAL(ca.m_interestFilterIds.size(), 18);
}

BOOST_AUTO_TEST_CASE(HandleProbe)
{
  auto identity = addIdentity(Name("/ndn/site1"));
  auto key = identity.getDefaultKey();
  auto cert = key.getDefaultCertificate();

  util::DummyClientFace face(m_io, {true, true});
  CaModule ca(face, m_keyChain, "tests/unit-tests/ca.conf.test");
  ca.setProbeHandler(Name("/ndn/site1"), [&] (const std::string& probeInfo) {
      return probeInfo + "example";
    });

  advanceClocks(time::milliseconds(20), 60);

  Name interestName("/ndn/site1/CA");
  interestName.append("_PROBE").append("zhiyi");
  Interest interest(interestName);

  int count = 0;
  face.onSendData.connect([&] (const Data& response) {
      count++;
      BOOST_CHECK(security::verifySignature(response, cert));
      JsonSection contentJson = ClientModule::getJsonFromData(response);
      BOOST_CHECK_EQUAL(contentJson.get(JSON_IDNENTIFIER, ""), "/ndn/site1/zhiyiexample");
    });
  face.receive(interest);

  advanceClocks(time::milliseconds(20), 60);
  BOOST_CHECK_EQUAL(count, 1);
}

BOOST_AUTO_TEST_CASE(HandleProbeUsingDefaultHandler)
{
  auto identity = addIdentity(Name("/ndn/site1"));
  auto key = identity.getDefaultKey();
  auto cert = key.getDefaultCertificate();

  util::DummyClientFace face(m_io, {true, true});
  CaModule ca(face, m_keyChain, "tests/unit-tests/ca.conf.test");

  advanceClocks(time::milliseconds(20), 60);

  Name interestName("/ndn/site1/CA");
  interestName.append("_PROBE").append("zhiyi");
  Interest interest(interestName);

  int count = 0;
  face.onSendData.connect([&] (const Data& response) {
      count++;
      BOOST_CHECK(security::verifySignature(response, cert));
      JsonSection contentJson = ClientModule::getJsonFromData(response);
      BOOST_CHECK_EQUAL(contentJson.get(JSON_IDNENTIFIER, ""), "/ndn/site1/zhiyi");
    });
  face.receive(interest);

  advanceClocks(time::milliseconds(20), 60);
  BOOST_CHECK_EQUAL(count, 1);
}

BOOST_AUTO_TEST_CASE(HandleNew)
{
  auto identity = addIdentity(Name("/ndn/site1"));
  auto key = identity.getDefaultKey();
  auto cert = key.getDefaultCertificate();

  util::DummyClientFace face(m_io, {true, true});
  util::DummyClientFace face2(m_io, {true, true});

  CaModule ca(face, m_keyChain, "tests/unit-tests/ca.conf.test");
  advanceClocks(time::milliseconds(20), 60);

  Name identityName("/ndn/site1");
  identityName.append("zhiyi");
  ClientModule client(face2, m_keyChain);
  ClientCaItem item;
  item.m_caName = Name("/ndn/site1/CA");
  item.m_anchor = cert;
  client.getClientConf().m_caItems.push_back(item);

  int nClientInterest = 0;
  int nCaData = 0;
  int nClientCallback = 0;

  face.onSendData.connect([&] (const Data& data) {
      nCaData++;
      JsonSection contentJson = ClientModule::getJsonFromData(data);
      BOOST_CHECK(!contentJson.get(JSON_REQUEST_ID, "").empty());
      face2.receive(data);
    });
  face2.onSendInterest.connect([&] (const Interest& interest) {
      nClientInterest++;
      face.receive(interest);
    });

  client.sendNew(item, identityName,
                 [&] (const shared_ptr<RequestState> state) {
                   nClientCallback++;
                   BOOST_CHECK(state->m_requestId != "");
                 },
                 [] (const std::string& s) { BOOST_CHECK(false); });

  advanceClocks(time::milliseconds(20), 60);

  BOOST_CHECK_EQUAL(nClientCallback, 1);
  BOOST_CHECK_EQUAL(nCaData, 1);
  BOOST_CHECK_EQUAL(nClientInterest, 1);
}

BOOST_AUTO_TEST_CASE(HandleLocalhostList)
{
  auto identity0 = addIdentity(Name("/ndn"));
  auto identity1 = addIdentity(Name("/ndn/edu/ucla/cs/zhiyi"));
  auto identity2 = addIdentity(Name("/ndn/site1"));
  m_keyChain.setDefaultIdentity(identity0);

  util::DummyClientFace face(m_io, {true, true});
  CaModule ca(face, m_keyChain, "tests/unit-tests/ca.conf.test");

  advanceClocks(time::milliseconds(20), 60);
  Interest interest(Name("/localhost/CA/_LIST"));

  int count = 0;
  face.onSendData.connect([&] (const Data& response) {
      count++;
      JsonSection contentJson = ClientModule::getJsonFromData(response);
      ClientConfig clientConf;
      clientConf.load(contentJson);
      BOOST_CHECK_EQUAL(clientConf.m_caItems.size(), 3);
    });
  face.receive(interest);

  advanceClocks(time::milliseconds(20), 60);
  BOOST_CHECK_EQUAL(count, 1);
}

BOOST_AUTO_TEST_CASE(HandleList)
{
  auto identity0 = addIdentity(Name("/ndn"));
  util::DummyClientFace face(m_io, {true, true});
  CaModule ca(face, m_keyChain, "tests/unit-tests/ca.conf.test");

  advanceClocks(time::milliseconds(20), 60);
  Interest interest(Name("/ndn/CA/_LIST"));

  int count = 0;
  face.onSendData.connect([&] (const Data& response) {
      count++;
      JsonSection contentJson = ClientModule::getJsonFromData(response);
      BOOST_CHECK_EQUAL(contentJson.get_child("ca-list").size(), 2);
      std::string schemaDataName = contentJson.get<std::string>("trust-schema");
      BOOST_CHECK_EQUAL(schemaDataName, "TODO: add trust schema");
    });
  face.receive(interest);

  advanceClocks(time::milliseconds(20), 60);
  BOOST_CHECK_EQUAL(count, 1);
}

BOOST_AUTO_TEST_CASE(HandleTargetList)
{
  auto identity0 = addIdentity(Name("/ndn"));
  util::DummyClientFace face(m_io, {true, true});
  CaModule ca(face, m_keyChain, "tests/unit-tests/ca.conf.test");
  ca.setRecommendCaHandler(Name("/ndn"),
    [] (const std::string& input, const std::list<Name>& list) -> std::tuple<Name, std::string> {
      Name recommendedCa;
      std::string identity;
      for (auto caName : list) {
        std::string univName = readString(caName.get(-1));
        if (input.find(univName) != std::string::npos) {
          recommendedCa = caName;
          identity = input.substr(0, input.find("@"));
        }
      }
      return std::make_tuple(recommendedCa, identity);
    });

  advanceClocks(time::milliseconds(20), 60);
  Interest interest(Name("/ndn/CA/_LIST/example@memphis.edu"));

  int count = 0;
  face.onSendData.connect([&] (const Data& response) {
      count++;
      JsonSection contentJson = ClientModule::getJsonFromData(response);
      std::string recommendedCA = contentJson.get<std::string>("recommended-ca");
      std::string recommendedIdentity = contentJson.get<std::string>("recommended-identity");
      std::string schemaDataName = contentJson.get<std::string>("trust-schema");
      BOOST_CHECK_EQUAL(recommendedCA, "/ndn/edu/memphis");
      BOOST_CHECK_EQUAL(recommendedIdentity, "example");
      BOOST_CHECK_EQUAL(schemaDataName, "TODO: add trust schema");
    });
  face.receive(interest);

  advanceClocks(time::milliseconds(20), 60);
  BOOST_CHECK_EQUAL(count, 1);
}

BOOST_AUTO_TEST_SUITE_END() // TestCaModule

} // namespace tests
} // namespace ndncert
} // namespace ndn
