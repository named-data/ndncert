/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
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
#include "client-module.hpp"
#include "challenge-module/challenge-pin.hpp"
#include "protocol-detail/info.hpp"
#include "test-common.hpp"

namespace ndn {
namespace ndncert {
namespace tests {

BOOST_FIXTURE_TEST_SUITE(TestForBenchmark, IdentityManagementTimeFixture)

BOOST_AUTO_TEST_CASE(PacketSize0)
{
  auto identity = addIdentity(Name("/ndn"));
  auto key = identity.getDefaultKey();
  auto cert = key.getDefaultCertificate();

  util::DummyClientFace face(io, m_keyChain, {true, true});
  CaModule ca(face, m_keyChain, "tests/unit-tests/ca.conf.test", "ca-storage-memory");
  advanceClocks(time::milliseconds(20), 60);

  Interest interest = MetadataObject::makeDiscoveryInterest(Name("/ndn/CA/INFO"));
  std::cout << "CA Config discovery Interest Size: " << interest.wireEncode().size() << std::endl;
  shared_ptr<Interest> infoInterest = nullptr;

  int count = 0;
  face.onSendData.connect([&](const Data& response) {
    if (count == 0) {
      count++;
      std::cout << "CA Config MetaData Size: " << response.wireEncode().size() << std::endl;
      auto block = response.getContent();
      block.parse();
      Interest interest(Name(block.get(tlv::Name)));
      interest.setCanBePrefix(true);
      infoInterest = make_shared<Interest>(interest);
      std::cout << "CA Config fetch Interest Size: " << infoInterest->wireEncode().size() << std::endl;

    }
    else {
      count++;
      std::cout << "CA Config Data Size: " << response.wireEncode().size() << std::endl;
      BOOST_CHECK(security::verifySignature(response, cert));
      auto contentBlock = response.getContent();
      contentBlock.parse();
      auto caItem = INFO::decodeClientConfigFromContent(contentBlock);
      BOOST_CHECK_EQUAL(caItem.m_caPrefix, "/ndn");
      BOOST_CHECK_EQUAL(caItem.m_probe, "");
      BOOST_CHECK_EQUAL(caItem.m_anchor.wireEncode(), cert.wireEncode());
      BOOST_CHECK_EQUAL(caItem.m_caInfo, "ndn testbed ca");
    }
  });
  face.receive(interest);
  advanceClocks(time::milliseconds(20), 60);
  face.receive(*infoInterest);
  advanceClocks(time::milliseconds(20), 60);

  BOOST_CHECK_EQUAL(count, 2);
}

BOOST_AUTO_TEST_CASE(PacketSize1)
{
  auto identity = addIdentity(Name("/ndn"));
  auto key = identity.getDefaultKey();
  auto cert = key.getDefaultCertificate();

  util::DummyClientFace face(io, m_keyChain, {true, true});
  CaModule ca(face, m_keyChain, "tests/unit-tests/ca.conf.test", "ca-storage-memory");
  advanceClocks(time::milliseconds(20), 60);

  // generate NEW Interest
  ClientModule client(m_keyChain);
  ClientCaItem item;
  item.m_caPrefix = Name("/ndn");
  item.m_anchor = cert;
  client.getClientConf().m_caItems.push_back(item);
  auto newInterest = client.generateNewInterest(time::system_clock::now(),
                                                time::system_clock::now() + time::days(1), Name("/ndn/alice"));

  std::cout << "New Interest Size: " << newInterest->wireEncode().size() << std::endl;

  // generate CHALLENGE Interest
  ChallengePin pinChallenge;
  shared_ptr<Interest> challengeInterest = nullptr;
  shared_ptr<Interest> challengeInterest2 = nullptr;
  shared_ptr<Interest> challengeInterest3 = nullptr;

  int count = 0;
  face.onSendData.connect([&](const Data& response) {
    if (Name("/ndn/CA/NEW").isPrefixOf(response.getName())) {
      std::cout << "NEW Data Size: " << response.wireEncode().size() << std::endl;
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
      auto secret = request.m_challengeSecrets.get(ChallengePin::PARAMETER_KEY_CODE, "");
      std::get<1>(paramList[0]) = secret;
      challengeInterest3 = client.generateChallengeInterest(pinChallenge.genChallengeRequestTLV(client.m_status,
                                                                                                client.m_challengeStatus,
                                                                                                std::move(paramList)));
      std::cout << "CHALLENGE Interest Size: " << challengeInterest3->wireEncode().size() << std::endl;
    }
    else if (Name("/ndn/CA/CHALLENGE").isPrefixOf(response.getName()) && count == 2) {
      std::cout << "CHALLENGE Data Size: " << response.wireEncode().size() << std::endl;
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

BOOST_AUTO_TEST_SUITE_END()  // TestCaConfig

}  // namespace tests
}  // namespace ndncert
}  // namespace ndn
