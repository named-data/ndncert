/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/**
 * Copyright (c) 2017-2018, Regents of the University of California.
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

#include "client-module.hpp"
#include "identity-management-fixture.hpp"
#include "challenge-module.hpp"
#include <ndn-cxx/util/dummy-client-face.hpp>
#include <ndn-cxx/security/signing-helpers.hpp>
#include <ndn-cxx/security/transform/public-key.hpp>
#include <ndn-cxx/security/verification-helpers.hpp>

namespace ndn {
namespace ndncert {
namespace tests {

BOOST_FIXTURE_TEST_SUITE(TestClientModule, IdentityManagementV2TimeFixture)

BOOST_AUTO_TEST_CASE(ClientModuleInitialize)
{
  util::DummyClientFace face(m_io, {true, true});
  ClientModule client(face, m_keyChain);
  client.getClientConf().load("tests/unit-tests/client.conf.test");
  BOOST_CHECK_EQUAL(client.getClientConf().m_caItems.size(), 2);
}

BOOST_AUTO_TEST_CASE(ProbeAndNew)
{
  util::DummyClientFace face(m_io, {true, true});
  ClientModule client(face, m_keyChain);
  client.getClientConf().load("tests/unit-tests/client.conf.test");

  auto identity = addIdentity(Name("/site"));
  auto key = identity.getDefaultKey();
  auto cert = key.getDefaultCertificate();

  ClientCaItem item;
  item.m_caName = Name("/site/CA");
  item.m_anchor = cert;
  client.getClientConf().m_caItems.push_back(item);

  int nInterest = 0;
  auto processInterest = [&] (const Interest& interest) {
    nInterest++;
    if (nInterest == 1) {
      // PROBE interest and return identifier
      BOOST_CHECK_EQUAL(interest.getName().toUri(), "/site/CA/_PROBE/zhiyi%40cs.ucla.edu");
      BOOST_CHECK_EQUAL(interest.getMustBeFresh(), 1);

      auto data = make_shared<Data>();
      data->setName(interest.getName());
      JsonSection json = genResponseProbeJson(Name("/site/ucla-cs-zhiyi"), Name(""));
      std::stringstream ss;
      boost::property_tree::write_json(ss, json);
      Block dataContent = makeStringBlock(ndn::tlv::Content, ss.str());
      data->setContent(dataContent);
      m_keyChain.sign(*data, signingByCertificate(cert));
      face.receive(*data);
    }
    else {
      // NEW interest and return challenge list, request ID
      BOOST_CHECK_EQUAL(interest.getName().getPrefix(3).toUri(), "/site/CA/_NEW");
      BOOST_CHECK_EQUAL(interest.getName().size(), 6);

      auto data = make_shared<Data>();
      data->setName(interest.getName());
      std::list<std::string> challenges;
      challenges.push_back("EMAIL");
      challenges.push_back("PIN");
      JsonSection json = genResponseNewJson("1234", ChallengeModule::WAIT_SELECTION, challenges);
      std::stringstream ss;
      boost::property_tree::write_json(ss, json);
      Block dataContent = makeStringBlock(ndn::tlv::Content, ss.str());
      data->setContent(dataContent);
      m_keyChain.sign(*data, signingByCertificate(cert));

      face.receive(*data);
    }
  };
  face.onSendInterest.connect([=] (const Interest& interest) { m_io.post([=] { processInterest(interest); }); });

  int nCallback = 0;
  shared_ptr<RequestState> requestState = nullptr;
  ClientModule::RequestCallback requestCallback = [&] (shared_ptr<RequestState> state) {
    nCallback++;
    BOOST_CHECK_EQUAL(state->m_requestId, "1234");
    BOOST_CHECK_EQUAL(state->m_challengeList.size(), 2);
    requestState = state;
  };
  client.sendProbe(item, "zhiyi@cs.ucla.edu", requestCallback, ClientModule::ErrorCallback());

  advanceClocks(time::milliseconds(200), 20);

  BOOST_CHECK_EQUAL(nInterest, 2);
  BOOST_CHECK_EQUAL(nCallback, 1);
  BOOST_CHECK_EQUAL(requestState->m_ca.m_caName.toUri(), "/site/CA");
  BOOST_CHECK_EQUAL(requestState->m_key.getName().getPrefix(3).toUri(), "/site/ucla-cs-zhiyi/KEY");

  // make sure the client did not generate duplicated new keys
  auto clientIdentity = m_keyChain.getPib().getIdentity(Name("/site/ucla-cs-zhiyi"));
  const auto& clientKeys = clientIdentity.getKeys();
  BOOST_CHECK_EQUAL(clientKeys.size(), 1);
}

BOOST_AUTO_TEST_SUITE_END() // TestClientModule

} // namespace tests
} // namespace ndncert
} // namespace ndn
