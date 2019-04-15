/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/**
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

#include "client-module.hpp"
#include "identity-management-fixture.hpp"
#include "challenge-module.hpp"
#include "ca-module.hpp"
#include <ndn-cxx/util/dummy-client-face.hpp>
#include <ndn-cxx/security/signing-helpers.hpp>
#include <ndn-cxx/security/transform/public-key.hpp>
#include <ndn-cxx/security/verification-helpers.hpp>

namespace ndn {
namespace ndncert {
namespace tests {

BOOST_FIXTURE_TEST_SUITE(TestClientModule, IdentityManagementTimeFixture)

BOOST_AUTO_TEST_CASE(ClientModuleInitialize)
{
  ClientModule client(m_keyChain);
  client.getClientConf().load("tests/unit-tests/client.conf.test");
  BOOST_CHECK_EQUAL(client.getClientConf().m_caItems.size(), 2);
}

BOOST_AUTO_TEST_CASE(Probe)
{
  ClientModule client(m_keyChain);
  client.getClientConf().load("tests/unit-tests/client.conf.test");

  auto identity = addIdentity(Name("/site"));
  auto key = identity.getDefaultKey();
  auto cert = key.getDefaultCertificate();

  ClientCaItem item;
  item.m_caName = Name("/site");
  item.m_anchor = cert;
  client.getClientConf().m_caItems.push_back(item);

  auto firstInterest = client.generateProbeInterest(item, "zhiyi@cs.ucla.edu");
  BOOST_CHECK_EQUAL(firstInterest->getName().toUri(), "/site/CA/_PROBE");
  BOOST_CHECK_EQUAL(CaModule::jsonFromBlock(firstInterest->getParameters()).get<std::string>(JSON_CLIENT_PROBE_INFO),
                    "zhiyi@cs.ucla.edu");
}

BOOST_AUTO_TEST_SUITE_END() // TestClientModule

} // namespace tests
} // namespace ndncert
} // namespace ndn
