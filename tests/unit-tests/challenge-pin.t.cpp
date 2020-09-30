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

#include "challenge-module/challenge-pin.hpp"
#include "test-common.hpp"

namespace ndn {
namespace ndncert {
namespace tests {

BOOST_FIXTURE_TEST_SUITE(TestChallengePin, IdentityManagementFixture)

BOOST_AUTO_TEST_CASE(ChallengeType)
{
  ChallengePin challenge;
  BOOST_CHECK_EQUAL(challenge.CHALLENGE_TYPE, "pin");
}

BOOST_AUTO_TEST_CASE(OnChallengeRequestWithEmptyInfo)
{
  auto identity = addIdentity(Name("/ndn/site1"));
  auto key = identity.getDefaultKey();
  auto cert = key.getDefaultCertificate();
  CertificateRequest request(Name("/ndn/site1"), "123", RequestType::NEW, Status::BEFORE_CHALLENGE, cert);

  ChallengePin challenge;
  challenge.handleChallengeRequest(makeEmptyBlock(tlv_encrypted_payload), request);

  BOOST_CHECK(request.m_status == Status::CHALLENGE);
  BOOST_CHECK_EQUAL(request.m_challengeState->m_challengeStatus, ChallengePin::NEED_CODE);
  BOOST_CHECK_EQUAL(request.m_challengeType, "pin");
}

BOOST_AUTO_TEST_CASE(OnChallengeRequestWithCode)
{
  auto identity = addIdentity(Name("/ndn/site1"));
  auto key = identity.getDefaultKey();
  auto cert = key.getDefaultCertificate();
  JsonSection secret;
  secret.add(ChallengePin::PARAMETER_KEY_CODE, "12345");
  CertificateRequest request(Name("/ndn/site1"), "123", RequestType::NEW, Status::CHALLENGE, cert,
                             "pin", ChallengePin::NEED_CODE, time::system_clock::now(),
                             3, time::seconds(3600), std::move(secret));

  Block paramTLV = makeEmptyBlock(tlv_encrypted_payload);
  paramTLV.push_back(makeStringBlock(tlv_parameter_key, ChallengePin::PARAMETER_KEY_CODE));
  paramTLV.push_back(makeStringBlock(tlv_parameter_value, "12345"));

  ChallengePin challenge;
  challenge.handleChallengeRequest(paramTLV, request);

  BOOST_CHECK(request.m_status == Status::PENDING);
  BOOST_CHECK(!request.m_challengeState);
}

BOOST_AUTO_TEST_CASE(OnChallengeRequestWithWrongCode)
{
  auto identity = addIdentity(Name("/ndn/site1"));
  auto key = identity.getDefaultKey();
  auto cert = key.getDefaultCertificate();
  JsonSection secret;
  secret.add(ChallengePin::PARAMETER_KEY_CODE, "12345");
  CertificateRequest request(Name("/ndn/site1"), "123", RequestType::NEW, Status::CHALLENGE, cert,
                             "pin", ChallengePin::NEED_CODE, time::system_clock::now(),
                             3, time::seconds(3600), std::move(secret));

  Block paramTLV = makeEmptyBlock(tlv_encrypted_payload);
  paramTLV.push_back(makeStringBlock(tlv_parameter_key, ChallengePin::PARAMETER_KEY_CODE));
  paramTLV.push_back(makeStringBlock(tlv_parameter_value, "45678"));

  ChallengePin challenge;
  challenge.handleChallengeRequest(paramTLV, request);

  BOOST_CHECK(request.m_status == Status::CHALLENGE);
  BOOST_CHECK_EQUAL(request.m_challengeState->m_challengeStatus, ChallengePin::WRONG_CODE);
  BOOST_CHECK_EQUAL(request.m_challengeState->m_secrets.empty(), false);
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace tests
} // namespace ndncert
} // namespace ndn
