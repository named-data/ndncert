/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/**
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

#include "protocol-detail/info.hpp"
#include "protocol-detail/probe.hpp"
#include "protocol-detail/new-renew-revoke.hpp"
#include "protocol-detail/challenge.hpp"
#include "test-common.hpp"

namespace ndn {
namespace ndncert {
namespace tests {

BOOST_FIXTURE_TEST_SUITE(TestProtocolDetail, IdentityManagementTimeFixture)

BOOST_AUTO_TEST_CASE(TestInfo)
{
  CaConfig config;
  config.load("tests/unit-tests/config-files/config-ca-1");

  const auto& identity = addIdentity("/test");
  const auto& cert = identity.getDefaultKey().getDefaultCertificate();
  auto encoded = INFO::encodeDataContent(config.m_caItem, cert);
  auto decoded = INFO::decodeDataContent(encoded);
  BOOST_CHECK_EQUAL(config.m_caItem.m_caPrefix, decoded.m_caPrefix);
  BOOST_CHECK_EQUAL(config.m_caItem.m_caInfo, decoded.m_caInfo);
  BOOST_CHECK_EQUAL(config.m_caItem.m_maxValidityPeriod, decoded.m_maxValidityPeriod);
  BOOST_CHECK_EQUAL(*config.m_caItem.m_maxSuffixLength, *decoded.m_maxSuffixLength);
  BOOST_CHECK_EQUAL(config.m_caItem.m_probeParameterKeys.size(), decoded.m_probeParameterKeys.size());
  BOOST_CHECK_EQUAL(config.m_caItem.m_probeParameterKeys.front(), decoded.m_probeParameterKeys.front());
  BOOST_CHECK_EQUAL(cert.wireEncode(), decoded.m_cert->wireEncode());
}

BOOST_AUTO_TEST_CASE(TestProbe)
{
  std::vector<std::tuple<std::string, std::string>> parameters;
  parameters.push_back(std::make_tuple("email", "zhiyi@cs.ucla.edu"));
  auto appParametersTlv = PROBE::encodeApplicationParameters(std::move(parameters));
  auto decodedParameters = PROBE::decodeApplicationParameters(appParametersTlv);
  BOOST_CHECK_EQUAL(std::get<0>(decodedParameters[0]), "email");
  BOOST_CHECK_EQUAL(std::get<1>(decodedParameters[0]), "zhiyi@cs.ucla.edu");
  BOOST_CHECK_EQUAL(decodedParameters.size(), 1);

  CaConfig config;
  config.load("tests/unit-tests/config-files/config-ca-5");
  std::vector<Name> ids;
  ids.push_back(Name("/example"));
  auto contentTlv = PROBE::encodeDataContent(ids, 2, config.m_redirection);
  std::vector<Name> decodedRedirectionItems;
  std::vector<std::pair<Name, int>> decodedIds;
  PROBE::decodeDataContent(contentTlv, decodedIds, decodedRedirectionItems);
  BOOST_CHECK_EQUAL(decodedIds[0].first, Name("/example"));
  BOOST_CHECK_EQUAL(decodedIds[0].second, 2);
  BOOST_CHECK_EQUAL(decodedRedirectionItems[0], config.m_redirection->at(0)->getFullName());
}

BOOST_AUTO_TEST_SUITE_END() // TestProtocolDetail

}  // namespace tests
}  // namespace ndncert
}  // namespace ndn
