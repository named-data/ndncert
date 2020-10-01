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

#include <protocol-detail/error.hpp>
#include "client-module.hpp"
#include "challenge-module.hpp"
#include "ca-module.hpp"
#include "test-common.hpp"

namespace ndn {
namespace ndncert {
namespace tests {

BOOST_FIXTURE_TEST_SUITE(TestClientModule, IdentityManagementTimeFixture)

BOOST_AUTO_TEST_CASE(ClientModuleInitialize)
{
  ClientModule client(m_keyChain);
  client.getClientConf().load("tests/unit-tests/config-files/config-client-1");
  BOOST_CHECK_EQUAL(client.getClientConf().m_caItems.size(), 2);
}

BOOST_AUTO_TEST_CASE(Probe)
{
  ClientModule client(m_keyChain);
  client.getClientConf().load("tests/unit-tests/config-files/config-client-1");

  auto identity = addIdentity(Name("/site"));
  auto key = identity.getDefaultKey();
  auto cert = key.getDefaultCertificate();

  CaConfigItem item;
  item.m_probeParameterKeys.push_back("email");
  item.m_probeParameterKeys.push_back("uid");
  item.m_probeParameterKeys.push_back("name");
  item.m_caPrefix = Name("/site");
  item.m_cert = std::make_shared<security::v2::Certificate>(cert);
  client.getClientConf().m_caItems.push_back(item);

  std::vector<std::tuple<std::string, std::string>> probeParams;
  probeParams.push_back(std::make_tuple("email", "zhiyi@cs.ucla.edu"));
  probeParams.push_back(std::make_tuple("uid", "987654321"));
  probeParams.push_back(std::make_tuple("name", "Zhiyi Zhang"));
  auto firstInterest = client.generateProbeInterest(item, std::move(probeParams));
  BOOST_CHECK(firstInterest->getName().at(-1).isParametersSha256Digest());
  // ignore the last name component (ParametersSha256Digest)
  BOOST_CHECK_EQUAL(firstInterest->getName().getPrefix(-1), "/site/CA/PROBE");
  BOOST_CHECK_EQUAL(readString(firstInterest->getApplicationParameters().get(tlv_parameter_value)),
                    "zhiyi@cs.ucla.edu");
}

BOOST_AUTO_TEST_CASE(ErrorHandling)
{
  auto identity = addIdentity(Name("/site"));
  auto key = identity.getDefaultKey();
  auto cert = key.getDefaultCertificate();

  ClientModule client(m_keyChain);
  CaConfigItem item;
  item.m_caPrefix = Name("/site");
  item.m_cert = std::make_shared<security::v2::Certificate>(cert);
  client.getClientConf().m_caItems.push_back(item);

  client.generateProbeInterest(item,std::vector<std::tuple<std::string, std::string>>());

  Data errorPacket;
  errorPacket.setName(Name("/site/pretend/this/is/error/packet"));
  errorPacket.setFreshnessPeriod(time::seconds(100));
  errorPacket.setContent(ErrorTLV::encodeDataContent(ErrorCode::NO_ERROR, "This is a test."));
  m_keyChain.sign(errorPacket, signingByIdentity(identity));

  BOOST_CHECK_THROW(client.onProbeResponse(errorPacket), std::exception);
  BOOST_CHECK_THROW(client.onNewRenewRevokeResponse(errorPacket), std::exception);
  BOOST_CHECK_THROW(client.onChallengeResponse(errorPacket), std::exception);
}

// BOOST_AUTO_TEST_CASE(GenProbeRequestJson)
// {
//   ClientModule client(m_keyChain);
//   client.getClientConf().load("tests/unit-tests/config-files/config-client-1");

//   auto identity = addIdentity(Name("/site"));
//   auto key = identity.getDefaultKey();
//   auto cert = key.getDefaultCertificate();

//   CaConfigItem item;
//   item.m_probe = "email:uid:name";
//   item.m_caPrefix = Name("/site");
//   item.m_cert = std::make_shared<security::v2::Certificate>(cert);
//   client.getClientConf().m_caItems.push_back(item);

//   auto interestPacket = client.genProbeRequestJson(item, "yufeng@ucla.edu:123456789:Yufeng Zhang");
//   BOOST_CHECK_EQUAL(interestPacket.get("email", ""), "yufeng@ucla.edu");
//   BOOST_CHECK_EQUAL(interestPacket.get("uid", ""), "123456789");
//   BOOST_CHECK_EQUAL(interestPacket.get("name", ""), "Yufeng Zhang");
// }

BOOST_AUTO_TEST_SUITE_END() // TestClientModule

} // namespace tests
} // namespace ndncert
} // namespace ndn
