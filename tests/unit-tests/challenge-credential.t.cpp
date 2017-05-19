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
#include "challenge-module/challenge-credential.hpp"
#include <ndn-cxx/security/signing-helpers.hpp>
#include <ndn-cxx/util/io.hpp>

namespace ndn {
namespace ndncert {
namespace tests {

BOOST_FIXTURE_TEST_SUITE(TestChallengeCredential, IdentityManagementV2Fixture)

BOOST_AUTO_TEST_CASE(LoadConfig)
{
  ChallengeCredential challenge("./tests/unit-tests/challenge-credential.conf.test");
  BOOST_CHECK_EQUAL(challenge.CHALLENGE_TYPE, "Credential");

  challenge.parseConfigFile();
  BOOST_CHECK_EQUAL(challenge.m_trustAnchors.size(), 1);
  auto cert = challenge.m_trustAnchors.front();
  BOOST_CHECK_EQUAL(cert.getName(),
                    "/ndn/site1/KEY/%11%BC%22%F4c%15%FF%17/self/%FD%00%00%01Y%C8%14%D9%A5");
}

BOOST_AUTO_TEST_CASE(HandleSelect)
{
  // create trust anchor
  ChallengeCredential challenge("./tests/unit-tests/challenge-credential.conf.test");
  auto identity = addIdentity(Name("/trust"));
  auto key = identity.getDefaultKey();
  auto trustAnchor = key.getDefaultCertificate();
  challenge.parseConfigFile();
  challenge.m_trustAnchors.front() = trustAnchor;

  // create certificate request
  auto identityA = addIdentity(Name("/example"));
  auto keyA = identityA.getDefaultKey();
  auto certA = key.getDefaultCertificate();
  CertificateRequest request(Name("/example"), "123", certA);

  // create requester's existing cert
  auto identityB = addIdentity(Name("/trust/cert"));
  auto keyB = identityB.getDefaultKey();
  auto certB = key.getDefaultCertificate();

  // using trust anchor to sign cert request to get credential
  Name credentialName = certB.getKeyName();
  credentialName.append("Credential").appendVersion();
  security::v2::Certificate credential = certB;
  credential.setName(credentialName);
  credential.setContent(certB.getContent());
  m_keyChain.sign(credential, signingByCertificate(trustAnchor));

  // generate SELECT interest
  std::stringstream ss;
  io::save<security::v2::Certificate>(credential, ss);
  auto checkCert = *(io::load<security::v2::Certificate>(ss));
  BOOST_CHECK_EQUAL(checkCert, credential);
  ss.str("");
  ss.clear();

  std::list<std::string> paramList;
  io::save<security::v2::Certificate>(credential, ss);
  std::string paramString = ss.str();
  paramList.push_back(paramString);
  ss.str("");
  ss.clear();

  io::save<security::v2::Certificate>(certB, ss);
  paramString = ss.str();
  paramList.push_back(paramString);
  ss.str("");
  ss.clear();
  JsonSection credentialJson = challenge.genSelectParamsJson(ChallengeModule::WAIT_SELECTION, paramList);

  boost::property_tree::write_json(ss, credentialJson);
  Block jsonContent = makeStringBlock(ndn::tlv::NameComponent, ss.str());

  Name interestName("/example/CA");
  interestName.append("_SELECT").append("Fake-Request-ID").append("CREDENTIAL").append(jsonContent);
  Interest interest(interestName);

  challenge.processSelectInterest(interest, request);
  BOOST_CHECK_EQUAL(request.getStatus(), ChallengeModule::SUCCESS);
  BOOST_CHECK_EQUAL(request.getChallengeSecrets().empty(), true);
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace tests
} // namespace ndncert
} // namespace ndn
