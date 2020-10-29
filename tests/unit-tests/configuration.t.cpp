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

#include "configuration.hpp"
#include "detail/info-encoder.hpp"
#include "test-common.hpp"

namespace ndn {
namespace ndncert {
namespace tests {

BOOST_FIXTURE_TEST_SUITE(TestConfig, IdentityManagementFixture)

BOOST_AUTO_TEST_CASE(CAConfigFile)
{
  ca::CaConfig config;
  config.load("tests/unit-tests/config-files/config-ca-1");
  BOOST_CHECK_EQUAL(config.m_caItem.m_caPrefix, "/ndn");
  BOOST_CHECK_EQUAL(config.m_caItem.m_caInfo, "ndn testbed ca");
  BOOST_CHECK_EQUAL(config.m_caItem.m_maxValidityPeriod, time::seconds(864000));
  BOOST_CHECK_EQUAL(*config.m_caItem.m_maxSuffixLength, 3);
  BOOST_CHECK_EQUAL(config.m_caItem.m_probeParameterKeys.size(), 1);
  BOOST_CHECK_EQUAL(config.m_caItem.m_probeParameterKeys.front(), "full name");
  BOOST_CHECK_EQUAL(config.m_caItem.m_supportedChallenges.size(), 1);
  BOOST_CHECK_EQUAL(config.m_caItem.m_supportedChallenges.front(), "pin");

  config.load("tests/unit-tests/config-files/config-ca-2");
  BOOST_CHECK_EQUAL(config.m_caItem.m_caPrefix, "/ndn");
  BOOST_CHECK_EQUAL(config.m_caItem.m_caInfo, "missing max validity period, max suffix length, and probe");
  BOOST_CHECK_EQUAL(config.m_caItem.m_maxValidityPeriod, time::seconds(86400));
  BOOST_CHECK(!config.m_caItem.m_maxSuffixLength.has_value());
  BOOST_CHECK_EQUAL(config.m_caItem.m_probeParameterKeys.size(), 0);
  BOOST_CHECK_EQUAL(config.m_caItem.m_supportedChallenges.size(), 2);
  BOOST_CHECK_EQUAL(config.m_caItem.m_supportedChallenges.front(), "pin");
  BOOST_CHECK_EQUAL(config.m_caItem.m_supportedChallenges.back(), "email");

  config.load("tests/unit-tests/config-files/config-ca-5");
  BOOST_CHECK_EQUAL(config.m_redirection->at(0)->getName(),
                    "/ndn/site1/KEY/%11%BC%22%F4c%15%FF%17/self/%FD%00%00%01Y%C8%14%D9%A5");
  BOOST_CHECK_EQUAL(config.m_nameAssignmentFuncs.size(), 3);
  BOOST_CHECK_EQUAL(config.m_nameAssignmentFuncs[0]->FACTORY_TYPE, "param");
  BOOST_CHECK_EQUAL(config.m_nameAssignmentFuncs[1]->FACTORY_TYPE, "param");
  BOOST_CHECK_EQUAL(config.m_nameAssignmentFuncs[2]->FACTORY_TYPE, "random");
  BOOST_CHECK_EQUAL(config.m_nameAssignmentFuncs[0]->m_nameFormat[0], "group");
  BOOST_CHECK_EQUAL(config.m_nameAssignmentFuncs[0]->m_nameFormat[1], "email");
  std::vector<std::tuple<std::string, std::string>> params;
  params.emplace_back("email", "1@1.edu");
  params.emplace_back("group", "irl");
  params.emplace_back("name", "ndncert");
  std::vector<Name> names;
  for (auto& assignment : config.m_nameAssignmentFuncs) {
    auto results = assignment->assignName(params);
    BOOST_CHECK_EQUAL(results.size(), 1);
    names.insert(names.end(), results.begin(), results.end());
  }
  BOOST_CHECK_EQUAL(names.size(), 3);
  BOOST_CHECK_EQUAL(names[0], Name("/irl/1@1.edu"));
  BOOST_CHECK_EQUAL(names[1], Name("/irl/ndncert"));
  BOOST_CHECK_EQUAL(names[2].size(), 1);
}

BOOST_AUTO_TEST_CASE(CAConfigFileWithErrors)
{
  ca::CaConfig config;
  // nonexistent file
  BOOST_CHECK_THROW(config.load("tests/unit-tests/config-files/Nonexist"), std::runtime_error);
  // missing challenge
  BOOST_CHECK_THROW(config.load("tests/unit-tests/config-files/config-ca-3"), std::runtime_error);
  // unsupported challenge
  BOOST_CHECK_THROW(config.load("tests/unit-tests/config-files/config-ca-4"), std::runtime_error);
  // unsupported name assignment
  BOOST_CHECK_THROW(config.load("tests/unit-tests/config-files/config-ca-6"), std::runtime_error);
}

BOOST_AUTO_TEST_CASE(RequesterCaCacheFile)
{
  RequesterCaCache config;
  config.load("tests/unit-tests/config-files/config-client-1");
  BOOST_CHECK_EQUAL(config.m_caItems.size(), 2);

  auto& config1 = config.m_caItems.front();
  BOOST_CHECK_EQUAL(config1.m_caPrefix, "/ndn/edu/ucla");
  BOOST_CHECK_EQUAL(config1.m_caInfo, "ndn testbed ca");
  BOOST_CHECK_EQUAL(config1.m_maxValidityPeriod, time::seconds(864000));
  BOOST_CHECK_EQUAL(*config1.m_maxSuffixLength, 3);
  BOOST_CHECK_EQUAL(config1.m_probeParameterKeys.size(), 1);
  BOOST_CHECK_EQUAL(config1.m_probeParameterKeys.front(), "email");
  BOOST_CHECK_EQUAL(config1.m_cert->getName(),
                    "/ndn/site1/KEY/%11%BC%22%F4c%15%FF%17/self/%FD%00%00%01Y%C8%14%D9%A5");

  auto& config2 = config.m_caItems.back();
  BOOST_CHECK_EQUAL(config2.m_caPrefix, "/ndn/edu/ucla/zhiyi");
  BOOST_CHECK_EQUAL(config2.m_caInfo, "");
  BOOST_CHECK_EQUAL(config2.m_maxValidityPeriod, time::seconds(86400));
  BOOST_CHECK(!config2.m_maxSuffixLength);
  BOOST_CHECK_EQUAL(config2.m_probeParameterKeys.size(), 0);
  BOOST_CHECK_EQUAL(config2.m_cert->getName(),
                    "/ndn/site1/KEY/%11%BC%22%F4c%15%FF%17/self/%FD%00%00%01Y%C8%14%D9%A5");
}

BOOST_AUTO_TEST_CASE(RequesterCaCacheFileWithErrors)
{
  RequesterCaCache config;
  // nonexistent file
  BOOST_CHECK_THROW(config.load("tests/unit-tests/config-files/Nonexist"), std::runtime_error);
  // missing certificate
  BOOST_CHECK_THROW(config.load("tests/unit-tests/config-files/config-client-2"), std::runtime_error);
  // missing ca prefix
  BOOST_CHECK_THROW(config.load("tests/unit-tests/config-files/config-client-3"), std::runtime_error);
}

BOOST_AUTO_TEST_CASE(RequesterCaCacheFileAddAndremoveCaProfile)
{
  RequesterCaCache config;
  config.load("tests/unit-tests/config-files/config-client-1");

  CaProfile item;
  item.m_caPrefix = Name("/test");
  item.m_caInfo = "test";

  config.m_caItems.push_back(item);
  BOOST_CHECK_EQUAL(config.m_caItems.size(), 3);
  auto lastItem = config.m_caItems.back();
  BOOST_CHECK_EQUAL(lastItem.m_caPrefix, "/test");

  config.removeCaProfile(Name("/test"));
  BOOST_CHECK_EQUAL(config.m_caItems.size(), 2);
  lastItem = config.m_caItems.back();
  BOOST_CHECK_EQUAL(lastItem.m_caPrefix, "/ndn/edu/ucla/zhiyi");
}

BOOST_AUTO_TEST_SUITE_END()  // TestCaConfig

} // namespace tests
} // namespace ndncert
} // namespace ndn
