/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/**
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

#include "challenge-module/challenge-private-key.hpp"
#include "test-common.hpp"
#include <ndn-cxx/security/signing-helpers.hpp>
#include <ndn-cxx/util/io.hpp>

namespace ndn {
namespace ndncert {
namespace tests {

BOOST_FIXTURE_TEST_SUITE(TestChallengeCredential, IdentityManagementFixture)

BOOST_AUTO_TEST_CASE(HandlePrivateKeyChallengeRequest)
{
  // create trust anchor
  ChallengePrivateKey challenge;

  // create certificate request
  auto identityA = addIdentity(Name("/example"));
  auto keyA = identityA.getDefaultKey();
  auto certA = keyA.getDefaultCertificate();
  CertificateRequest request(Name("/example"), "123", REQUEST_TYPE_REVOKE, STATUS_BEFORE_CHALLENGE, certA);

  security::v2::Certificate privateKeyProof;
  privateKeyProof.setName(Name(keyA.getName()).append("proof-of-private-key").appendVersion());
  privateKeyProof.setContent(makeStringBlock(tlv::Content, "123"));
  m_keyChain.sign(privateKeyProof, signingByKey(keyA));

  std::stringstream ss;
  io::save<security::v2::Certificate>(privateKeyProof, ss);
  auto checkCert = *(io::load<security::v2::Certificate>(ss));
  BOOST_CHECK_EQUAL(checkCert, privateKeyProof);
  ss.str("");
  ss.clear();

  io::save<security::v2::Certificate>(privateKeyProof, ss);
  std::string selfSignedStr = ss.str();
  ss.str("");
  ss.clear();

  Block params = makeEmptyBlock(tlv_encrypted_payload);
  params.push_back(makeStringBlock(tlv_selected_challenge, "Private Key"));
  params.push_back(makeStringBlock(tlv_parameter_key, ChallengePrivateKey::JSON_PROOF_OF_PRIVATE_KEY));
  params.push_back(makeStringBlock(tlv_parameter_value, selfSignedStr));
  params.encode();

  challenge.handleChallengeRequest(params, request);
  BOOST_CHECK_EQUAL(request.m_status, STATUS_PENDING);
  BOOST_CHECK_EQUAL(request.m_challengeStatus, CHALLENGE_STATUS_SUCCESS);
}

BOOST_AUTO_TEST_SUITE_END()

}  // namespace tests
}  // namespace ndncert
}  // namespace ndn
