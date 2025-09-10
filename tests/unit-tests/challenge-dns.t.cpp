/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2017-2025, Regents of the University of California.
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

#include "challenge/challenge-dns.hpp"
#include "detail/ca-request-state.hpp"

#include "tests/boost-test.hpp"
#include "tests/key-chain-fixture.hpp"

#include <ndn-cxx/security/signing-helpers.hpp>

namespace ndncert::tests {

BOOST_AUTO_TEST_SUITE(TestChallengeDns)

class DnsChallengeFixture : public KeyChainFixture
{
public:
  DnsChallengeFixture()
    : challenge(3, time::seconds(1800))
    , identity(m_keyChain.createIdentity("/example"))
    , key(identity.getDefaultKey())
    , cert(key.getDefaultCertificate())
  {
    state.caPrefix = Name("/example");
    state.requestId = {0x01, 0x02, 0x03, 0x04};
    state.cert = cert;
    state.status = Status::BEFORE_CHALLENGE;
  }

public:
  ChallengeDns challenge;
  ndn::security::Identity identity;
  ndn::security::Key key;
  Certificate cert;
  ca::RequestState state;
};

BOOST_FIXTURE_TEST_CASE(TestDomainValidation, DnsChallengeFixture)
{
  BOOST_CHECK(ChallengeDns::isValidDomainName("example.com"));
  BOOST_CHECK(ChallengeDns::isValidDomainName("sub.example.com"));
  BOOST_CHECK(ChallengeDns::isValidDomainName("test-domain.example.org"));
  BOOST_CHECK(ChallengeDns::isValidDomainName("a.b"));
  
  // Invalid domains
  BOOST_CHECK(!ChallengeDns::isValidDomainName(""));
  BOOST_CHECK(!ChallengeDns::isValidDomainName("-example.com"));
  BOOST_CHECK(!ChallengeDns::isValidDomainName("example-.com"));
  BOOST_CHECK(!ChallengeDns::isValidDomainName("example..com"));
  BOOST_CHECK(!ChallengeDns::isValidDomainName(".example.com"));
  BOOST_CHECK(!ChallengeDns::isValidDomainName("example.com."));
}

BOOST_FIXTURE_TEST_CASE(TestChallengeResponse, DnsChallengeFixture)
{
  std::string token = "test-token-123";
  std::string keyHash = "abcdef123456";
  
  std::string response = ChallengeDns::computeChallengeResponse(token, keyHash);
  
  // Should be a valid hex string
  BOOST_CHECK_GT(response.length(), 0);
  BOOST_CHECK_EQUAL(response.length(), 64); // SHA-256 hex = 64 chars
  
  // Should be deterministic
  std::string response2 = ChallengeDns::computeChallengeResponse(token, keyHash);
  BOOST_CHECK_EQUAL(response, response2);
  
  // Should be different for different inputs
  std::string response3 = ChallengeDns::computeChallengeResponse("different-token", keyHash);
  BOOST_CHECK_NE(response, response3);
}

BOOST_FIXTURE_TEST_CASE(TestDnsRecordName, DnsChallengeFixture)
{
  std::string recordName = challenge.getDnsRecordName("example.com");
  BOOST_CHECK_EQUAL(recordName, "_ndncert-challenge.example.com");
  
  recordName = challenge.getDnsRecordName("sub.example.org");
  BOOST_CHECK_EQUAL(recordName, "_ndncert-challenge.sub.example.org");
}

BOOST_FIXTURE_TEST_CASE(TestInitialRequest, DnsChallengeFixture)
{
  // Create initial request with domain
  Block params(tlv::EncryptedPayload);
  params.push_back(ndn::makeStringBlock(tlv::ParameterKey, "domain"));
  params.push_back(ndn::makeStringBlock(tlv::ParameterValue, "example.com"));
  params.encode();

  auto [errorCode, errorInfo] = challenge.handleChallengeRequest(params, state);

  BOOST_CHECK_EQUAL(static_cast<uint64_t>(errorCode), static_cast<uint64_t>(ErrorCode::NO_ERROR));
  BOOST_CHECK(state.status == Status::CHALLENGE);
  BOOST_CHECK_EQUAL(state.challengeState->challengeStatus, ChallengeDns::NEED_RECORD);
  
  // Check that secrets contain expected fields
  auto secrets = state.challengeState->secrets;
  BOOST_CHECK(secrets.count("token") > 0);
  BOOST_CHECK(secrets.count("domain") > 0);
  BOOST_CHECK(secrets.count("key-hash") > 0);
  BOOST_CHECK(secrets.count("expected-value") > 0);
  BOOST_CHECK(secrets.count("record-name") > 0);
  
  BOOST_CHECK_EQUAL(secrets.get<std::string>("domain"), "example.com");
  BOOST_CHECK_EQUAL(secrets.get<std::string>("record-name"), "_ndncert-challenge.example.com");
}

BOOST_FIXTURE_TEST_CASE(TestInvalidDomain, DnsChallengeFixture)
{
  // Create request with invalid domain
  Block params(tlv::EncryptedPayload);
  params.push_back(ndn::makeStringBlock(tlv::ParameterKey, "domain"));
  params.push_back(ndn::makeStringBlock(tlv::ParameterValue, "invalid..domain"));
  params.encode();

  auto [errorCode, errorInfo] = challenge.handleChallengeRequest(params, state);

  BOOST_CHECK_EQUAL(static_cast<uint64_t>(errorCode), static_cast<uint64_t>(ErrorCode::INVALID_PARAMETER));
  BOOST_CHECK(state.status == Status::FAILURE);
}

BOOST_FIXTURE_TEST_CASE(TestConfirmationStep, DnsChallengeFixture)
{
  // First, initialize challenge
  Block params1(tlv::EncryptedPayload);
  params1.push_back(ndn::makeStringBlock(tlv::ParameterKey, "domain"));
  params1.push_back(ndn::makeStringBlock(tlv::ParameterValue, "example.com"));
  params1.encode();

  auto [errorCode1, errorInfo1] = challenge.handleChallengeRequest(params1, state);
  BOOST_REQUIRE_EQUAL(static_cast<uint64_t>(errorCode1), static_cast<uint64_t>(ErrorCode::NO_ERROR));

  // Now send confirmation
  Block params2(tlv::EncryptedPayload);
  params2.push_back(ndn::makeStringBlock(tlv::ParameterKey, "confirmation"));
  params2.push_back(ndn::makeStringBlock(tlv::ParameterValue, "ready"));
  params2.encode();

  auto [errorCode2, errorInfo2] = challenge.handleChallengeRequest(params2, state);

  BOOST_CHECK_EQUAL(static_cast<uint64_t>(errorCode2), static_cast<uint64_t>(ErrorCode::NO_ERROR));
  BOOST_CHECK_EQUAL(state.challengeState->challengeStatus, ChallengeDns::READY_FOR_VALIDATION);
}

BOOST_FIXTURE_TEST_CASE(TestInvalidConfirmation, DnsChallengeFixture)
{
  // First, initialize challenge
  Block params1(tlv::EncryptedPayload);
  params1.push_back(ndn::makeStringBlock(tlv::ParameterKey, "domain"));
  params1.push_back(ndn::makeStringBlock(tlv::ParameterValue, "example.com"));
  params1.encode();

  auto [errorCode1, errorInfo1] = challenge.handleChallengeRequest(params1, state);
  BOOST_REQUIRE_EQUAL(static_cast<uint64_t>(errorCode1), static_cast<uint64_t>(ErrorCode::NO_ERROR));

  // Send invalid confirmation
  Block params2(tlv::EncryptedPayload);
  params2.push_back(ndn::makeStringBlock(tlv::ParameterKey, "confirmation"));
  params2.push_back(ndn::makeStringBlock(tlv::ParameterValue, "invalid"));
  params2.encode();

  auto [errorCode2, errorInfo2] = challenge.handleChallengeRequest(params2, state);

  BOOST_CHECK_EQUAL(static_cast<uint64_t>(errorCode2), static_cast<uint64_t>(ErrorCode::INVALID_PARAMETER));
}

BOOST_FIXTURE_TEST_CASE(TestParameterRequests, DnsChallengeFixture)
{
  // Test parameter requests for different states
  auto params1 = challenge.getRequestedParameterList(Status::BEFORE_CHALLENGE, "");
  BOOST_CHECK_EQUAL(params1.size(), 1);
  BOOST_CHECK(params1.find("domain") != params1.end());

  auto params2 = challenge.getRequestedParameterList(Status::CHALLENGE, ChallengeDns::NEED_RECORD);
  BOOST_CHECK_EQUAL(params2.size(), 1);
  BOOST_CHECK(params2.find("confirmation") != params2.end());

  auto params3 = challenge.getRequestedParameterList(Status::CHALLENGE, ChallengeDns::READY_FOR_VALIDATION);
  BOOST_CHECK_EQUAL(params3.size(), 0);

  auto params4 = challenge.getRequestedParameterList(Status::CHALLENGE, ChallengeDns::WRONG_RECORD);
  BOOST_CHECK_EQUAL(params4.size(), 1);
  BOOST_CHECK(params4.find("confirmation") != params4.end());
}

BOOST_FIXTURE_TEST_CASE(TestTLVGeneration, DnsChallengeFixture)
{
  std::multimap<std::string, std::string> params;

  // Test initial request TLV
  params.clear();
  params.emplace("domain", "example.com");
  auto tlv1 = challenge.genChallengeRequestTLV(Status::BEFORE_CHALLENGE, "", params);
  BOOST_CHECK_GT(tlv1.size(), 0);

  // Test confirmation TLV  
  params.clear();
  params.emplace("confirmation", "ready");
  auto tlv2 = challenge.genChallengeRequestTLV(Status::CHALLENGE, ChallengeDns::NEED_RECORD, params);
  BOOST_CHECK_GT(tlv2.size(), 0);

  // Test validation TLV
  params.clear();
  auto tlv3 = challenge.genChallengeRequestTLV(Status::CHALLENGE, ChallengeDns::READY_FOR_VALIDATION, params);
  BOOST_CHECK_GT(tlv3.size(), 0);
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace ndncert::tests