/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/**
 * Copyright (c) 2017-2018, Regents of the University of California.
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

#include "challenge-module/challenge-email.hpp"
#include "identity-management-fixture.hpp"

namespace ndn {
namespace ndncert {
namespace tests {

BOOST_FIXTURE_TEST_SUITE(TestChallengeEmail, IdentityManagementV2Fixture)

BOOST_AUTO_TEST_CASE(TestChallengeType)
{
  ChallengeEmail challenge;
  BOOST_CHECK_EQUAL(challenge.CHALLENGE_TYPE, "Email");
}

BOOST_AUTO_TEST_CASE(ParseStoredSecret)
{
  time::system_clock::TimePoint tp = time::fromIsoString("20170207T120000");
  JsonSection json;
  json.put(ChallengeEmail::JSON_CODE_TP, time::toIsoString(tp));
  json.put(ChallengeEmail::JSON_CODE, "1234");
  json.put(ChallengeEmail::JSON_ATTEMPT_TIMES, std::to_string(3));

  auto result = ChallengeEmail::parseStoredSecrets(json);
  BOOST_CHECK_EQUAL(std::get<0>(result), tp);
  BOOST_CHECK_EQUAL(std::get<1>(result), "1234");
  BOOST_CHECK_EQUAL(std::get<2>(result), 3);
}

BOOST_AUTO_TEST_CASE(EmailAddressChecker)
{
  BOOST_CHECK_EQUAL(ChallengeEmail::isValidEmailAddress("zhiyi@cs.ucla.edu"), true);
  BOOST_CHECK_EQUAL(ChallengeEmail::isValidEmailAddress("zhiyi@cs"), false);
  BOOST_CHECK_EQUAL(ChallengeEmail::isValidEmailAddress("zhiyi.ucla.edu"), false);
}

BOOST_AUTO_TEST_CASE(OnSelectInterestComingWithEmail)
{
  auto identity = addIdentity(Name("/ndn/site1"));
  auto key = identity.getDefaultKey();
  auto cert = key.getDefaultCertificate();
  CertificateRequest request(Name("/ndn/site1"), "123", cert);

  JsonSection emailJson;
  emailJson.put(ChallengeEmail::JSON_EMAIL, "zhiyi@cs.ucla.edu");
  std::stringstream ss;
  boost::property_tree::write_json(ss, emailJson);
  Block jsonContent = makeStringBlock(ndn::tlv::GenericNameComponent, ss.str());

  Name interestName("/ndn/site1/CA");
  interestName.append("_SELECT").append("Fake-Request-ID").append("EMAIL").append(jsonContent);
  Interest interest(interestName);

  ChallengeEmail challenge("./tests/unit-tests/test-send-email.sh");
  challenge.handleChallengeRequest(interest, request);

  BOOST_CHECK_EQUAL(request.getStatus(), ChallengeEmail::NEED_CODE);
  BOOST_CHECK_EQUAL(request.getChallengeType(), "Email");

  std::string line = "";
  std::string delimiter = " ";
  std::ifstream emailFile("tmp.txt");
  if (emailFile.is_open())
  {
    getline(emailFile, line);
    emailFile.close();
  }
  std::string recipientEmail = line.substr(0, line.find(delimiter));
  std::string secret = line.substr(line.find(delimiter) + 1);

  BOOST_CHECK_EQUAL(recipientEmail, "zhiyi@cs.ucla.edu");
  auto stored_secret = request.getChallengeSecrets().get<std::string>(ChallengeEmail::JSON_CODE);
  BOOST_CHECK_EQUAL(secret, stored_secret);

  std::remove("tmp.txt");
}

BOOST_AUTO_TEST_CASE(OnSelectInterestComingWithInvalidEmail)
{
  auto identity = addIdentity(Name("/ndn/site1"));
  auto key = identity.getDefaultKey();
  auto cert = key.getDefaultCertificate();
  CertificateRequest request(Name("/ndn/site1"), "123", cert);

  JsonSection emailJson;
  emailJson.put(ChallengeEmail::JSON_EMAIL, "zhiyi@cs");
  std::stringstream ss;
  boost::property_tree::write_json(ss, emailJson);
  Block jsonContent = makeStringBlock(ndn::tlv::GenericNameComponent, ss.str());

  Name interestName("/ndn/site1/CA");
  interestName.append("_SELECT").append("Fake-Request-ID").append("EMAIL").append(jsonContent);
  Interest interest(interestName);

  ChallengeEmail challenge;
  challenge.handleChallengeRequest(interest, request);

  BOOST_CHECK_EQUAL(request.getStatus(), ChallengeEmail::FAILURE_INVALID_EMAIL);
  BOOST_CHECK_EQUAL(request.getChallengeType(), "Email");
}

BOOST_AUTO_TEST_CASE(OnValidateInterestComingWithCode)
{
  auto identity = addIdentity(Name("/ndn/site1"));
  auto key = identity.getDefaultKey();
  auto cert = key.getDefaultCertificate();
  CertificateRequest request(Name("/ndn/site1"), "123", cert);
  request.setChallengeType("EMAIL");
  request.setStatus(ChallengeEmail::NEED_CODE);

  time::system_clock::TimePoint tp = time::system_clock::now();
  JsonSection json;
  json.put(ChallengeEmail::JSON_CODE_TP, time::toIsoString(tp));
  json.put(ChallengeEmail::JSON_CODE, "4567");
  json.put(ChallengeEmail::JSON_ATTEMPT_TIMES, std::to_string(3));

  request.setChallengeSecrets(json);

  JsonSection infoJson;
  infoJson.put(ChallengeEmail::JSON_CODE, "4567");
  std::stringstream ss;
  boost::property_tree::write_json(ss, infoJson);
  Block jsonContent = makeStringBlock(ndn::tlv::GenericNameComponent, ss.str());

  Name interestName("/ndn/site1/CA");
  interestName.append("_VALIDATE").append("Fake-Request-ID").append("EMAIL").append(jsonContent);
  Interest interest(interestName);

  ChallengeEmail challenge;
  challenge.handleChallengeRequest(interest, request);

  BOOST_CHECK_EQUAL(request.getStatus(), ChallengeModule::SUCCESS);
  BOOST_CHECK_EQUAL(request.getChallengeSecrets().empty(), true);
}

BOOST_AUTO_TEST_CASE(OnValidateInterestComingWithWrongCode)
{
  auto identity = addIdentity(Name("/ndn/site1"));
  auto key = identity.getDefaultKey();
  auto cert = key.getDefaultCertificate();
  CertificateRequest request(Name("/ndn/site1"), "123", cert);
  request.setChallengeType("EMAIL");
  request.setStatus(ChallengeEmail::NEED_CODE);

  time::system_clock::TimePoint tp = time::system_clock::now();
  JsonSection json;
  json.put(ChallengeEmail::JSON_CODE_TP, time::toIsoString(tp));
  json.put(ChallengeEmail::JSON_CODE, "4567");
  json.put(ChallengeEmail::JSON_ATTEMPT_TIMES, std::to_string(3));

  request.setChallengeSecrets(json);

  JsonSection infoJson;
  infoJson.put(ChallengeEmail::JSON_CODE, "1234");
  std::stringstream ss;
  boost::property_tree::write_json(ss, infoJson);
  Block jsonContent = makeStringBlock(ndn::tlv::GenericNameComponent, ss.str());

  Name interestName("/ndn/site1/CA");
  interestName.append("_VALIDATE").append("Fake-Request-ID").append("EMAIL").append(jsonContent);
  Interest interest(interestName);

  ChallengeEmail challenge;
  challenge.handleChallengeRequest(interest, request);

  BOOST_CHECK_EQUAL(request.getStatus(), ChallengeEmail::WRONG_CODE);
  BOOST_CHECK_EQUAL(request.getChallengeSecrets().empty(), false);
}

BOOST_AUTO_TEST_CASE(ClientSendSelect)
{
  ChallengeEmail challenge;
  auto requirementList = challenge.getSelectRequirements();
  BOOST_CHECK_EQUAL(requirementList.size(), 1);

  requirementList.clear();
  requirementList.push_back("zhiyi@cs.ucla.edu");

  auto json = challenge.genSelectParamsJson(ChallengeModule::WAIT_SELECTION, requirementList);
  BOOST_CHECK_EQUAL(json.empty(), false);
  BOOST_CHECK_EQUAL(json.get<std::string>(ChallengeEmail::JSON_EMAIL), "zhiyi@cs.ucla.edu");
}

BOOST_AUTO_TEST_CASE(ClientSendValidate)
{
  ChallengeEmail challenge;
  auto requirementList = challenge.getValidateRequirements(ChallengeEmail::NEED_CODE);
  BOOST_CHECK_EQUAL(requirementList.size(), 1);

  requirementList.clear();
  requirementList.push_back("123");

  auto json = challenge.genValidateParamsJson(ChallengeEmail::NEED_CODE, requirementList);
  BOOST_CHECK_EQUAL(json.empty(), false);
  BOOST_CHECK_EQUAL(json.get<std::string>(ChallengeEmail::JSON_CODE), "123");
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace tests
} // namespace ndncert
} // namespace ndn
