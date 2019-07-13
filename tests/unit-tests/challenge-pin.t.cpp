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

#include "challenge-module/challenge-pin.hpp"

#include "identity-management-fixture.hpp"

namespace ndn {
namespace ndncert {
namespace tests {

BOOST_FIXTURE_TEST_SUITE(TestChallengePin, IdentityManagementFixture)

BOOST_AUTO_TEST_CASE(ChallengeType)
{
  ChallengePin challenge;
  BOOST_CHECK_EQUAL(challenge.CHALLENGE_TYPE, "PIN");
}

BOOST_AUTO_TEST_CASE(OnChallengeRequestWithEmptyInfo)
{
  auto identity = addIdentity(Name("/ndn/site1"));
  auto key = identity.getDefaultKey();
  auto cert = key.getDefaultCertificate();
  CertificateRequest request(Name("/ndn/site1"), "123", STATUS_BEFORE_CHALLENGE, cert);

  ChallengePin challenge;
  challenge.handleChallengeRequest(JsonSection(), request);

  BOOST_CHECK_EQUAL(request.m_status, STATUS_CHALLENGE);
  BOOST_CHECK_EQUAL(request.m_challengeStatus, ChallengePin::NEED_CODE);
  BOOST_CHECK_EQUAL(request.m_challengeType, "PIN");
}

BOOST_AUTO_TEST_CASE(OnChallengeRequestWithCode)
{
  auto identity = addIdentity(Name("/ndn/site1"));
  auto key = identity.getDefaultKey();
  auto cert = key.getDefaultCertificate();
  JsonSection secret;
  secret.add(ChallengePin::JSON_PIN_CODE, "12345");
  CertificateRequest request(Name("/ndn/site1"), "123", STATUS_CHALLENGE, ChallengePin::NEED_CODE, "PIN",
                             time::toIsoString(time::system_clock::now()), 3600, 3, secret, cert);

  JsonSection paramJson;
  paramJson.put(ChallengePin::JSON_PIN_CODE, "12345");

  ChallengePin challenge;
  challenge.handleChallengeRequest(paramJson, request);

  BOOST_CHECK_EQUAL(request.m_status, STATUS_PENDING);
  BOOST_CHECK_EQUAL(request.m_challengeStatus, CHALLENGE_STATUS_SUCCESS);
  BOOST_CHECK_EQUAL(request.m_challengeSecrets.empty(), true);
}

BOOST_AUTO_TEST_CASE(OnChallengeRequestWithWrongCode)
{
  auto identity = addIdentity(Name("/ndn/site1"));
  auto key = identity.getDefaultKey();
  auto cert = key.getDefaultCertificate();
  JsonSection secret;
  secret.add(ChallengePin::JSON_PIN_CODE, "12345");
  CertificateRequest request(Name("/ndn/site1"), "123", STATUS_CHALLENGE, ChallengePin::NEED_CODE, "PIN",
                             time::toIsoString(time::system_clock::now()), 3600, 3, secret, cert);

  JsonSection paramJson;
  paramJson.put(ChallengePin::JSON_PIN_CODE, "45678");

  ChallengePin challenge;
  challenge.handleChallengeRequest(paramJson, request);

  BOOST_CHECK_EQUAL(request.m_status, STATUS_CHALLENGE);
  BOOST_CHECK_EQUAL(request.m_challengeStatus, ChallengePin::WRONG_CODE);
  BOOST_CHECK_EQUAL(request.m_challengeSecrets.empty(), false);
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace tests
} // namespace ndncert
} // namespace ndn
