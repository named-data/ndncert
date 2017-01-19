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

#include "identity-management-fixture.hpp"
#include "ca-config.hpp"
#include <ndn-cxx/security/transform/base64-encode.hpp>
#include <ndn-cxx/security/transform/buffer-source.hpp>
#include <ndn-cxx/security/transform/stream-sink.hpp>

namespace ndn {
namespace ndncert {
namespace tests {

BOOST_FIXTURE_TEST_SUITE(TestCaConfig, IdentityManagementV2Fixture)

BOOST_AUTO_TEST_CASE(ReadConfigFileWithFileAnchor)
{
  CaConfig config("tests/unit-tests/ca.conf.test");
  BOOST_CHECK_EQUAL(config.m_caName.toUri(), "/ndn/edu/ucla/cs/zhiyi");
  BOOST_CHECK_EQUAL(config.m_freshPeriod, 720);
  BOOST_CHECK_EQUAL(config.m_anchor->getName().toUri(),
                    "/ndn/site1/KEY/%11%BC%22%F4c%15%FF%17/self/%FD%00%00%01Y%C8%14%D9%A5");
  BOOST_CHECK_EQUAL(config.m_availableChallenges.size(), 1);
}

BOOST_AUTO_TEST_CASE(ReadConfigFileWithBase64Anchor)
{
  auto identity = addIdentity(Name("/ndn/site1"));
  auto key = identity.getDefaultKey();
  auto cert = key.getDefaultCertificate();

  using namespace security::transform;
  std::stringstream ss;
  bufferSource(cert.wireEncode().wire(), cert.wireEncode().size()) >> base64Encode() >> streamSink(ss);

  const std::string certBase64 = ss.str();

  CaConfig config("tests/unit-tests/ca.conf.test");
  config.m_config.put("ca-anchor.type", "base64");
  config.m_config.put("ca-anchor.value", certBase64);
  config.load();
  BOOST_CHECK_EQUAL(*(config.m_anchor), cert);
}

BOOST_AUTO_TEST_SUITE_END() // TestCaConfig

} // namespace tests
} // namespace ndncert
} // namespace ndn
