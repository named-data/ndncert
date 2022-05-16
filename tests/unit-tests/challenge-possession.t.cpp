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

#include "challenge/challenge-possession.hpp"
#include "detail/challenge-encoder.hpp"

#include "tests/boost-test.hpp"
#include "tests/key-chain-fixture.hpp"

namespace ndncert::tests {

class ChallengePossessionFixture : public KeyChainFixture
{
public:
  void
  createTrustAnchor()
  {
    trustAnchor = m_keyChain.createIdentity("/trust").getDefaultKey().getDefaultCertificate();
    challenge.parseConfigFile();
    challenge.m_trustAnchors.front() = trustAnchor;
  }

  void
  createCertificateRequest()
  {
    state.caPrefix = "/example";
    state.requestId = RequestId{{101}};
    state.requestType = RequestType::NEW;
    state.cert = m_keyChain.createIdentity("/example").getDefaultKey().getDefaultCertificate();
  }

  void
  createRequesterCredential()
  {
    auto keyB = m_keyChain.createIdentity("/trust/cert").getDefaultKey();
    ndn::security::MakeCertificateOptions opts;
    opts.issuerId = ndn::name::Component("Credential");
    opts.validity.emplace(ndn::security::ValidityPeriod::makeRelative(-1_s, 1_min));
    credential = m_keyChain.makeCertificate(keyB, signingByCertificate(trustAnchor), opts);
    m_keyChain.addCertificate(keyB, credential);
  }

  void
  signCertRequest()
  {
    auto params = challenge.getRequestedParameterList(state.status, "");
    ChallengePossession::fulfillParameters(params, m_keyChain, credential.getName(), std::array<uint8_t, 16>{});
    Block paramsTlv = challenge.genChallengeRequestTLV(state.status, "", params);
    challenge.handleChallengeRequest(paramsTlv, state);
    BOOST_CHECK_EQUAL(statusToString(state.status), statusToString(Status::CHALLENGE));
    BOOST_REQUIRE(state.challengeState.has_value());
    BOOST_CHECK_EQUAL(state.challengeState->challengeStatus, "need-proof");
  }

  void
  replyFromServer(ndn::span<const uint8_t, 16> nonce)
  {
    auto params2 = challenge.getRequestedParameterList(state.status, state.challengeState->challengeStatus);
    ChallengePossession::fulfillParameters(params2, m_keyChain, credential.getName(), nonce);
    Block paramsTlv2 = challenge.genChallengeRequestTLV(state.status, state.challengeState->challengeStatus, params2);
    challenge.handleChallengeRequest(paramsTlv2, state);
  }

public:
  ChallengePossession challenge{"tests/unit-tests/config-files/config-challenge-possession"};
  Certificate trustAnchor;
  ca::RequestState state;
  Certificate credential;
};

BOOST_FIXTURE_TEST_SUITE(TestChallengePossession, ChallengePossessionFixture)

BOOST_AUTO_TEST_CASE(LoadConfig)
{
  BOOST_CHECK_EQUAL(challenge.CHALLENGE_TYPE, "Possession");

  challenge.parseConfigFile();
  BOOST_CHECK_EQUAL(challenge.m_trustAnchors.size(), 1);
  auto cert = challenge.m_trustAnchors.front();
  BOOST_CHECK_EQUAL(cert.getName(),
                    "/ndn/site1/KEY/%11%BC%22%F4c%15%FF%17/self/%FD%00%00%01Y%C8%14%D9%A5");
}

BOOST_AUTO_TEST_CASE(HandleChallengeRequest)
{
  createTrustAnchor();
  createCertificateRequest();
  createRequesterCredential();
  signCertRequest();

  auto nonceBuf = ndn::fromHex(state.challengeState->secrets.get("nonce", ""));
  std::array<uint8_t, 16> nonce{};
  memcpy(nonce.data(), nonceBuf->data(), 16);
  replyFromServer(nonce);
  BOOST_CHECK_EQUAL(statusToString(state.status), statusToString(Status::PENDING));
}

BOOST_AUTO_TEST_CASE(HandleChallengeRequestProofFail)
{
  createTrustAnchor();
  createCertificateRequest();
  createRequesterCredential();
  signCertRequest();

  std::array<uint8_t, 16> nonce{};
  replyFromServer(nonce);
  BOOST_CHECK_EQUAL(statusToString(state.status), statusToString(Status::FAILURE));
}

BOOST_AUTO_TEST_SUITE_END() // TestChallengePossession

} // namespace ndncert::tests
