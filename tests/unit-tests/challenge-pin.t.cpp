/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2017-2022, Regents of the University of California.
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

#include "challenge/challenge-pin.hpp"

#include "tests/boost-test.hpp"
#include "tests/key-chain-fixture.hpp"

namespace ndncert::tests {

BOOST_FIXTURE_TEST_SUITE(TestChallengePin, KeyChainFixture)

BOOST_AUTO_TEST_CASE(ChallengeType)
{
  ChallengePin challenge;
  BOOST_CHECK_EQUAL(challenge.CHALLENGE_TYPE, "pin");
}

BOOST_AUTO_TEST_CASE(OnChallengeRequestWithEmptyInfo)
{
  auto identity = m_keyChain.createIdentity(Name("/ndn/site1"));
  auto key = identity.getDefaultKey();
  auto cert = key.getDefaultCertificate();
  RequestId requestId = {{101}};
  ca::RequestState request;
  request.caPrefix = Name("/ndn/site1");
  request.requestId = requestId;
  request.requestType = RequestType::NEW;
  request.cert = cert;

  ChallengePin challenge;
  challenge.handleChallengeRequest(ndn::makeEmptyBlock(tlv::EncryptedPayload), request);

  BOOST_CHECK(request.status == Status::CHALLENGE);
  BOOST_CHECK_EQUAL(request.challengeState->challengeStatus, ChallengePin::NEED_CODE);
  BOOST_CHECK_EQUAL(request.challengeType, "pin");
}

BOOST_AUTO_TEST_CASE(OnChallengeRequestWithCode)
{
  auto identity = m_keyChain.createIdentity(Name("/ndn/site1"));
  auto key = identity.getDefaultKey();
  auto cert = key.getDefaultCertificate();
  JsonSection secret;
  secret.add(ChallengePin::PARAMETER_KEY_CODE, "12345");
  RequestId requestId = {{101}};
  ca::RequestState request;
  request.caPrefix = Name("/ndn/site1");
  request.requestId = requestId;
  request.requestType = RequestType::NEW;
  request.status = Status::CHALLENGE;
  request.cert = cert;
  request.challengeType = "pin";
  request.challengeState = ca::ChallengeState(ChallengePin::NEED_CODE, time::system_clock::now(),
                                              3, time::seconds(3600), std::move(secret));

  Block paramTLV = ndn::makeEmptyBlock(tlv::EncryptedPayload);
  paramTLV.push_back(ndn::makeStringBlock(tlv::ParameterKey, ChallengePin::PARAMETER_KEY_CODE));
  paramTLV.push_back(ndn::makeStringBlock(tlv::ParameterValue, "12345"));

  ChallengePin challenge;
  challenge.handleChallengeRequest(paramTLV, request);

  BOOST_CHECK(request.status == Status::PENDING);
  BOOST_CHECK(!request.challengeState);
}

BOOST_AUTO_TEST_CASE(OnChallengeRequestWithWrongCode)
{
  auto identity = m_keyChain.createIdentity(Name("/ndn/site1"));
  auto key = identity.getDefaultKey();
  auto cert = key.getDefaultCertificate();
  JsonSection secret;
  secret.add(ChallengePin::PARAMETER_KEY_CODE, "12345");
  RequestId requestId = {{101}};
  ca::RequestState request;
  request.caPrefix = Name("/ndn/site1");
  request.requestId = requestId;
  request.requestType = RequestType::NEW;
  request.status = Status::CHALLENGE;
  request.cert = cert;
  request.challengeType = "pin";
  request.challengeState = ca::ChallengeState(ChallengePin::NEED_CODE, time::system_clock::now(),
                                              3, time::seconds(3600), std::move(secret));

  Block paramTLV = ndn::makeEmptyBlock(tlv::EncryptedPayload);
  paramTLV.push_back(ndn::makeStringBlock(tlv::ParameterKey, ChallengePin::PARAMETER_KEY_CODE));
  paramTLV.push_back(ndn::makeStringBlock(tlv::ParameterValue, "45678"));

  ChallengePin challenge;
  challenge.handleChallengeRequest(paramTLV, request);

  BOOST_CHECK(request.status == Status::CHALLENGE);
  BOOST_CHECK_EQUAL(request.challengeState->challengeStatus, ChallengePin::WRONG_CODE);
  BOOST_CHECK_EQUAL(request.challengeState->secrets.empty(), false);
}

BOOST_AUTO_TEST_SUITE_END() // TestChallengePin

} // namespace ndncert::tests
