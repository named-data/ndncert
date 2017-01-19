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
#include "challenge-module/challenge-pin.hpp"

namespace ndn {
namespace ndncert {
namespace tests {

BOOST_FIXTURE_TEST_SUITE(TestChallengePin, IdentityManagementV2Fixture)

BOOST_AUTO_TEST_CASE(TestGetInitInfo)
{
  ChallengePin challenge;
  BOOST_CHECK_EQUAL(challenge.CHALLENGE_TYPE, "PIN");
}

BOOST_AUTO_TEST_CASE(ParseStoredSecret)
{
  time::system_clock::TimePoint tp = time::fromIsoString("20170207T120000");
  JsonSection json;
  json.put(ChallengePin::JSON_CODE_TP, time::toIsoString(tp));
  json.put(ChallengePin::JSON_PIN_CODE, "1234");
  json.put(ChallengePin::JSON_ATTEMPT_TIMES, std::to_string(3));

  auto result = ChallengePin::parseStoredSecrets(json);
  BOOST_CHECK_EQUAL(std::get<0>(result), tp);
  BOOST_CHECK_EQUAL(std::get<1>(result), "1234");
  BOOST_CHECK_EQUAL(std::get<2>(result), 3);
}

BOOST_AUTO_TEST_CASE(OnSelectInterestComingWithEmptyInfo)
{
  auto identity = addIdentity(Name("/ndn/site1"));
  auto key = identity.getDefaultKey();
  auto cert = key.getDefaultCertificate();
  CertificateRequest request(Name("/ndn/site1"), "123", cert);

  Name interestName("/ndn/site1");
  interestName.append("_SELECT").append("Fake-Request-ID").append("PIN");
  Interest interest(interestName);

  ChallengePin challenge;
  challenge.handleChallengeRequest(interest, request);

  BOOST_CHECK_EQUAL(request.getStatus(), ChallengePin::NEED_CODE);
  BOOST_CHECK_EQUAL(request.getChallengeType(), "PIN");
}

BOOST_AUTO_TEST_CASE(OnValidateInterestComingWithCode)
{
  auto identity = addIdentity(Name("/ndn/site1"));
  auto key = identity.getDefaultKey();
  auto cert = key.getDefaultCertificate();
  CertificateRequest request(Name("/ndn/site1"), "123", cert);
  request.setChallengeType("PIN");
  request.setStatus(ChallengePin::NEED_CODE);

  time::system_clock::TimePoint tp = time::system_clock::now();
  JsonSection json;
  json.put(ChallengePin::JSON_CODE_TP, time::toIsoString(tp));
  json.put(ChallengePin::JSON_PIN_CODE, "1234");
  json.put(ChallengePin::JSON_ATTEMPT_TIMES, std::to_string(3));

  request.setChallengeSecrets(json);

  JsonSection infoJson;
  infoJson.put(ChallengePin::JSON_PIN_CODE, "123");
  std::stringstream ss;
  boost::property_tree::write_json(ss, json);
  std::string jsonString = ss.str();
  Block jsonContent = makeStringBlock(ndn::tlv::NameComponent, ss.str());

  Name interestName("/ndn/site1");
  interestName.append("_VALIDATE").append("Fake-Request-ID").append("PIN").append(jsonContent);
  Interest interest(interestName);

  ChallengePin challenge;
  challenge.handleChallengeRequest(interest, request);

  BOOST_CHECK_EQUAL(request.getStatus(), ChallengeModule::SUCCESS);
  BOOST_CHECK_EQUAL(request.getChallengeSecrets().empty(), true);
}

BOOST_AUTO_TEST_CASE(ClientSendSelect)
{
  ChallengePin challenge;
  auto requirementList = challenge.getSelectRequirements();
  BOOST_CHECK_EQUAL(requirementList.size(), 0);

  auto json = challenge.genChallengeInfo("_SELECT", ChallengeModule::WAIT_SELECTION, requirementList);
  BOOST_CHECK_EQUAL(json.empty(), true);
}

BOOST_AUTO_TEST_CASE(ClientSendValidate)
{
  ChallengePin challenge;
  auto requirementList = challenge.getValidateRequirements(ChallengePin::NEED_CODE);
  BOOST_CHECK_EQUAL(requirementList.size(), 1);

  requirementList.clear();
  requirementList.push_back("123");

  auto json = challenge.genChallengeInfo("_VALIDATE", ChallengePin::NEED_CODE, requirementList);
  BOOST_CHECK_EQUAL(json.empty(), false);
  BOOST_CHECK_EQUAL(json.get<std::string>(ChallengePin::JSON_PIN_CODE), "123");
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace tests
} // namespace ndncert
} // namespace ndn
