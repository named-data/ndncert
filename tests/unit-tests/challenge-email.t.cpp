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

#include "challenge-module/challenge-email.hpp"
#include "test-common.hpp"

namespace ndn {
namespace ndncert {
namespace tests {

BOOST_FIXTURE_TEST_SUITE(TestChallengeEmail, IdentityManagementFixture)

BOOST_AUTO_TEST_CASE(ChallengeType)
{
  ChallengeEmail challenge;
  BOOST_CHECK_EQUAL(challenge.CHALLENGE_TYPE, "email");
}

BOOST_AUTO_TEST_CASE(EmailAddressChecker)
{
  BOOST_CHECK_EQUAL(ChallengeEmail::isValidEmailAddress("zhiyi@cs.ucla.edu"), true);
  BOOST_CHECK_EQUAL(ChallengeEmail::isValidEmailAddress("zhiyi@cs"), false);
  BOOST_CHECK_EQUAL(ChallengeEmail::isValidEmailAddress("zhiyi.ucla.edu"), false);
}

BOOST_AUTO_TEST_CASE(OnChallengeRequestWithEmail)
{
  auto identity = addIdentity(Name("/ndn/site1"));
  auto key = identity.getDefaultKey();
  auto cert = key.getDefaultCertificate();
  CertificateRequest request(Name("/ndn/site1"), "123", RequestType::NEW, Status::BEFORE_CHALLENGE, cert);

  Block paramTLV = makeEmptyBlock(tlv_encrypted_payload);
  paramTLV.push_back(makeStringBlock(tlv_parameter_key, ChallengeEmail::PARAMETER_KEY_EMAIL));
  paramTLV.push_back(makeStringBlock(tlv_parameter_value, "zhiyi@cs.ucla.edu"));

  ChallengeEmail challenge("./tests/unit-tests/test-send-email.sh");
  challenge.handleChallengeRequest(paramTLV, request);

  BOOST_CHECK(request.m_status == Status::CHALLENGE);
  BOOST_CHECK_EQUAL(request.m_challengeStatus, ChallengeEmail::NEED_CODE);
  BOOST_CHECK(request.m_challengeSecrets.get<std::string>(ChallengeEmail::PARAMETER_KEY_CODE) != "");
  BOOST_CHECK(request.m_remainingTime != 0);
  BOOST_CHECK(request.m_remainingTries != 0);
  BOOST_CHECK(request.m_challengeTp != "");
  BOOST_CHECK_EQUAL(request.m_challengeType, "email");

  std::string line = "";
  std::string delimiter = " ";
  std::ifstream emailFile("tmp.txt");
  if (emailFile.is_open()) {
    getline(emailFile, line);
    emailFile.close();
  }
  int end = line.find(delimiter);
  std::string recipientEmail = line.substr(0, end);
  BOOST_CHECK_EQUAL(recipientEmail, "zhiyi@cs.ucla.edu");
  line = line.substr(end + 1);

  end = line.find(delimiter);
  std::string secret = line.substr(0, end);
  auto stored_secret = request.m_challengeSecrets.get<std::string>(ChallengeEmail::PARAMETER_KEY_CODE);
  BOOST_CHECK_EQUAL(secret, stored_secret);
  line = line.substr(end + 1);

  end = line.find(delimiter);
  std::string caName = line.substr(0, end);
  BOOST_CHECK_EQUAL(caName, Name("/ndn/site1"));
  line = line.substr(end + 1);

  std::string certName = line;
  BOOST_CHECK_EQUAL(certName, cert.getName());
  std::remove("tmp.txt");
}

BOOST_AUTO_TEST_CASE(OnChallengeRequestWithInvalidEmail)
{
  auto identity = addIdentity(Name("/ndn/site1"));
  auto key = identity.getDefaultKey();
  auto cert = key.getDefaultCertificate();
  CertificateRequest request(Name("/ndn/site1"), "123", RequestType::NEW, Status::BEFORE_CHALLENGE, cert);

  Block paramTLV = makeEmptyBlock(tlv_encrypted_payload);
  paramTLV.push_back(makeStringBlock(tlv_parameter_key, ChallengeEmail::PARAMETER_KEY_EMAIL));
  paramTLV.push_back(makeStringBlock(tlv_parameter_value, "zhiyi@cs"));

  ChallengeEmail challenge;
  challenge.handleChallengeRequest(paramTLV, request);

  BOOST_CHECK(request.m_status == Status::FAILURE);
}

BOOST_AUTO_TEST_CASE(OnChallengeRequestWithCode)
{
  auto identity = addIdentity(Name("/ndn/site1"));
  auto key = identity.getDefaultKey();
  auto cert = key.getDefaultCertificate();
  JsonSection json;
  json.put(ChallengeEmail::PARAMETER_KEY_CODE, "4567");
  CertificateRequest request(Name("/ndn/site1"), "123", RequestType::NEW, Status::CHALLENGE, ChallengeEmail::NEED_CODE,
                             "Email", time::toIsoString(time::system_clock::now()), 3600, 3, json, cert);

  Block paramTLV = makeEmptyBlock(tlv_encrypted_payload);
  paramTLV.push_back(makeStringBlock(tlv_parameter_key, ChallengeEmail::PARAMETER_KEY_CODE));
  paramTLV.push_back(makeStringBlock(tlv_parameter_value, "4567"));

  ChallengeEmail challenge;
  challenge.handleChallengeRequest(paramTLV, request);

  BOOST_CHECK(request.m_status == Status::PENDING);
  BOOST_CHECK_EQUAL(request.m_challengeSecrets.empty(), true);
}

BOOST_AUTO_TEST_CASE(OnValidateInterestComingWithWrongCode)
{
  auto identity = addIdentity(Name("/ndn/site1"));
  auto key = identity.getDefaultKey();
  auto cert = key.getDefaultCertificate();
  JsonSection json;
  json.put(ChallengeEmail::PARAMETER_KEY_CODE, "4567");
  CertificateRequest request(Name("/ndn/site1"), "123", RequestType::NEW, Status::CHALLENGE, ChallengeEmail::NEED_CODE,
                             "email", time::toIsoString(time::system_clock::now()), 3600, 3, json, cert);

  Block paramTLV = makeEmptyBlock(tlv_encrypted_payload);
  paramTLV.push_back(makeStringBlock(tlv_parameter_key, ChallengeEmail::PARAMETER_KEY_CODE));
  paramTLV.push_back(makeStringBlock(tlv_parameter_value, "7890"));

  ChallengeEmail challenge;
  challenge.handleChallengeRequest(paramTLV, request);

  BOOST_CHECK_EQUAL(request.m_challengeStatus, ChallengeEmail::WRONG_CODE);
  BOOST_CHECK(request.m_status == Status::CHALLENGE);
  BOOST_CHECK_EQUAL(request.m_challengeSecrets.empty(), false);
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace tests
} // namespace ndncert
} // namespace ndn
