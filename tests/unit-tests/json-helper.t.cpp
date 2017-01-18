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
#include "json-helper.hpp"

namespace ndn {
namespace ndncert {
namespace tests {

BOOST_FIXTURE_TEST_SUITE(TestJsonHelper, IdentityManagementV2Fixture)

BOOST_AUTO_TEST_CASE(GenerateProbeJson)
{
  auto result = genResponseProbeJson(Name("/ndn/edu/ucla/cs/zhiyi/macbook"),
                                     Name("/ndn/edu/ucla/cs/zhiyi/ca-info"));
  BOOST_CHECK_EQUAL(result.get<std::string>(JSON_IDNENTIFIER), "/ndn/edu/ucla/cs/zhiyi/macbook");
  BOOST_CHECK_EQUAL(result.get<std::string>(JSON_CA_INFO), "/ndn/edu/ucla/cs/zhiyi/ca-info");
}

BOOST_AUTO_TEST_CASE(GenerateNewResponseJson)
{
  auto identity = addIdentity(Name("/ndn/site1"));
  auto key = identity.getDefaultKey();
  auto cert = key.getDefaultCertificate();

  CertificateRequest request(Name("/ndn/site1"), "598234759", cert);
  std::list<std::tuple<std::string, std::string>> challenges;
  challenges.push_back(std::make_tuple("PIN", "Please ask ca officer"));
  challenges.push_back(std::make_tuple("EMAIL", "Please provide your email"));
  auto result = genResponseNewJson(request, challenges);

  BOOST_CHECK_EQUAL(result.get<std::string>(JSON_STATUS), "pending");
  BOOST_CHECK_EQUAL(result.get<std::string>(JSON_REQUEST_ID), "598234759");
  auto child = result.get_child(JSON_CHALLENGES);
  auto it = child.begin();
  BOOST_CHECK_EQUAL(it->second.get<std::string>(JSON_CHALLENGE_TYPE), "PIN");
  BOOST_CHECK_EQUAL(it->second.get<std::string>(JSON_CHALLENGE_INSTRUCTION),
                    "Please ask ca officer");
  it++;
  BOOST_CHECK_EQUAL(it->second.get<std::string>(JSON_CHALLENGE_TYPE), "EMAIL");
  BOOST_CHECK_EQUAL(it->second.get<std::string>(JSON_CHALLENGE_INSTRUCTION),
                    "Please provide your email");
}

BOOST_AUTO_TEST_CASE(GeneratePollResponseJson)
{
  auto identity = addIdentity(Name("/ndn/site1"));
  auto key = identity.getDefaultKey();
  auto cert = key.getDefaultCertificate();

  CertificateRequest request(Name("/ndn/site1"), "598234759", CertificateRequest::Verifying,
                             "Email", "NEED_CODE", "111", cert);
  request.setChallengeInstruction("Please provide verification code");
  auto result = genResponsePollJson(request);

  BOOST_CHECK_EQUAL(result.get<std::string>(JSON_STATUS), "verifying");
  BOOST_CHECK_EQUAL(result.get<std::string>(JSON_CHALLENGE_TYPE), "Email");
  BOOST_CHECK_EQUAL(result.get<std::string>(JSON_CHALLENGE_STATUS), "NEED_CODE");
  BOOST_CHECK_EQUAL(result.get<std::string>(JSON_CHALLENGE_INSTRUCTION),
                    "Please provide verification code");
}

BOOST_AUTO_TEST_CASE(GenerateErrorJson)
{
  auto result = genErrorJson("The certificate name already exists");
  BOOST_CHECK_EQUAL(result.get<std::string>(JSON_STATUS), "error");
  BOOST_CHECK_EQUAL(result.get<std::string>(JSON_ERROR_INFO),
                    "The certificate name already exists");
}

BOOST_AUTO_TEST_SUITE_END() // TestJsonHelper

} // namespace tests
} // namespace ndncert
} // namespace ndn
