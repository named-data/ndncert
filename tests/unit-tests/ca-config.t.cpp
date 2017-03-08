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
  CaConfig config;
  config.load("tests/unit-tests/ca.conf.test");
  auto itemA = config.m_caItems.front();
  BOOST_CHECK_EQUAL(itemA.m_caName.toUri(), "/ndn/edu/ucla/cs/zhiyi");
  BOOST_CHECK_EQUAL(itemA.m_probe, "true");
  BOOST_CHECK_EQUAL(itemA.m_freshnessPeriod, time::seconds(720));
  BOOST_CHECK_EQUAL(itemA.m_validityPeriod, time::days(360));
  BOOST_CHECK_EQUAL(itemA.m_anchor.toUri(),
                    "/ndn/edu/ucla/cs/zhiyi/KEY/%9A%E0%C6%C6%09%7C%92i/self/%FD%00%00%01Z%B0%2AJ%B4");
  BOOST_CHECK_EQUAL(itemA.m_supportedChallenges.size(), 1);

  auto itemB = config.m_caItems.back();
  BOOST_CHECK_EQUAL(itemB.m_caName.toUri(), "/ndn/site1");
  BOOST_CHECK_EQUAL(itemB.m_probe, "true");
  BOOST_CHECK_EQUAL(itemB.m_freshnessPeriod, time::seconds(720));
  BOOST_CHECK_EQUAL(itemB.m_validityPeriod, time::days(360));
  BOOST_CHECK_EQUAL(itemB.m_anchor.toUri(),
                    "/ndn/site1/KEY/%11%BC%22%F4c%15%FF%17/self/%FD%00%00%01Y%C8%14%D9%A5");
  BOOST_CHECK_EQUAL(itemB.m_supportedChallenges.size(), 1);
}

BOOST_AUTO_TEST_SUITE_END() // TestCaConfig

} // namespace tests
} // namespace ndncert
} // namespace ndn
