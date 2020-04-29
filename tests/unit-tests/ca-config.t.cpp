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

#include "ca-config.hpp"
#include "protocol-detail/info.hpp"
#include "identity-management-fixture.hpp"

#include <ndn-cxx/security/transform/base64-encode.hpp>
#include <ndn-cxx/security/transform/buffer-source.hpp>
#include <ndn-cxx/security/transform/stream-sink.hpp>

namespace ndn {
namespace ndncert {
namespace tests {

BOOST_FIXTURE_TEST_SUITE(TestCaConfig, IdentityManagementFixture)

BOOST_AUTO_TEST_CASE(ReadConfigFile)
{
  CaConfig config;
  config.load("tests/unit-tests/ca.conf.test");
  BOOST_CHECK_EQUAL(config.m_caPrefix, "/ndn");
  BOOST_CHECK_EQUAL(config.m_caInfo, "ndn testbed ca");
  BOOST_CHECK_EQUAL(config.m_maxValidityPeriod, time::seconds(86400));
  BOOST_CHECK_EQUAL(config.m_probeParameterKeys.size(), 1);
  BOOST_CHECK_EQUAL(config.m_probeParameterKeys.front(), "full name");
  BOOST_CHECK_EQUAL(config.m_supportedChallenges.size(), 1);
  BOOST_CHECK_EQUAL(config.m_supportedChallenges.front(), "pin");
}

BOOST_AUTO_TEST_CASE(ReadNonexistConfigFile)
{
  CaConfig config;
  BOOST_CHECK_THROW(config.load("tests/unit-tests/Nonexist"), CaConfig::Error);
}

BOOST_AUTO_TEST_CASE(ReadConfigFileWithoutCaPrefix)
{
  CaConfig config;
  BOOST_CHECK_THROW(config.load("tests/unit-tests/ca.conf.test2"), CaConfig::Error);
}

BOOST_AUTO_TEST_CASE(ReadConfigFileWithChallengeNotSupported)
{
  CaConfig config;
  BOOST_CHECK_THROW(config.load("tests/unit-tests/ca.conf.test3"), CaConfig::Error);
}

BOOST_AUTO_TEST_CASE(InfoContentEncodingDecoding)
{
  CaConfig config;
  config.load("tests/unit-tests/ca.conf.test");

  const auto& identity = addIdentity("/test");
  const auto& cert = identity.getDefaultKey().getDefaultCertificate();
  auto encoded = INFO::encodeContentFromCAConfig(config, cert);
  auto decoded = INFO::decodeClientConfigFromContent(encoded);
  BOOST_CHECK_EQUAL(config.m_caPrefix, decoded.m_caPrefix);
  BOOST_CHECK_EQUAL(config.m_caInfo, decoded.m_caInfo);
  BOOST_CHECK_EQUAL(config.m_maxValidityPeriod, decoded.m_maxValidityPeriod);
  BOOST_CHECK_EQUAL(config.m_probeParameterKeys.size(), decoded.m_probeParameterKeys.size());
  BOOST_CHECK_EQUAL(config.m_probeParameterKeys.front(), decoded.m_probeParameterKeys.front());
  BOOST_CHECK_EQUAL(cert.wireEncode(), decoded.m_anchor.wireEncode());
}

BOOST_AUTO_TEST_SUITE_END() // TestCaConfig

} // namespace tests
} // namespace ndncert
} // namespace ndn
