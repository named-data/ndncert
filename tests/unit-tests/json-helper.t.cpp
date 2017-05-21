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

#include "boost-test.hpp"
#include "json-helper.hpp"

namespace ndn {
namespace ndncert {
namespace tests {

BOOST_AUTO_TEST_SUITE(TestJsonHelper)

BOOST_AUTO_TEST_CASE(GenerateProbeJson)
{
  auto result = genResponseProbeJson(Name("/ndn/edu/ucla/cs/zhiyi/macbook"),
                                     Name("/ndn/edu/ucla/cs/zhiyi/ca-info"));
  BOOST_CHECK_EQUAL(result.get<std::string>(JSON_IDNENTIFIER), "/ndn/edu/ucla/cs/zhiyi/macbook");
  BOOST_CHECK_EQUAL(result.get<std::string>(JSON_CA_INFO), "/ndn/edu/ucla/cs/zhiyi/ca-info");
}

BOOST_AUTO_TEST_CASE(GenerateNewResponseJson)
{
  std::list<std::string> challenges;
  challenges.push_back("PIN");
  challenges.push_back("EMAIL");
  auto result = genResponseNewJson("598234759", "wait-selection", challenges);

  BOOST_CHECK_EQUAL(result.get<std::string>(JSON_REQUEST_ID), "598234759");
  BOOST_CHECK_EQUAL(result.get<std::string>(JSON_STATUS), "wait-selection");
  auto child = result.get_child(JSON_CHALLENGES);
  auto it = child.begin();
  BOOST_CHECK_EQUAL(it->second.get<std::string>(JSON_CHALLENGE_TYPE), "PIN");
  it++;
  BOOST_CHECK_EQUAL(it->second.get<std::string>(JSON_CHALLENGE_TYPE), "EMAIL");
}

BOOST_AUTO_TEST_CASE(GenerateChallengeResponseJson)
{
  auto result = genResponseChallengeJson("598234759", "EMAIL", "need-code");

  BOOST_CHECK_EQUAL(result.get<std::string>(JSON_REQUEST_ID), "598234759");
  BOOST_CHECK_EQUAL(result.get<std::string>(JSON_CHALLENGE_TYPE), "EMAIL");
  BOOST_CHECK_EQUAL(result.get<std::string>(JSON_STATUS), "need-code");

  result = genResponseChallengeJson("598234759", "EMAIL", "need-code", Name("/ndn/test"));

  BOOST_CHECK_EQUAL(result.get<std::string>(JSON_REQUEST_ID), "598234759");
  BOOST_CHECK_EQUAL(result.get<std::string>(JSON_CHALLENGE_TYPE), "EMAIL");
  BOOST_CHECK_EQUAL(result.get<std::string>(JSON_STATUS), "need-code");
  BOOST_CHECK_EQUAL(result.get<std::string>(JSON_CERTIFICATE), "/ndn/test");
}

BOOST_AUTO_TEST_CASE(GenerateFailureJson)
{
  auto result = genFailureJson("598234759", "EMAIL", "failure",
                               "The certificate name already exists");
  BOOST_CHECK_EQUAL(result.get<std::string>(JSON_STATUS), "failure");
  BOOST_CHECK_EQUAL(result.get<std::string>(JSON_FAILURE_INFO),
                    "The certificate name already exists");
}

BOOST_AUTO_TEST_SUITE_END() // TestJsonHelper

} // namespace tests
} // namespace ndncert
} // namespace ndn
