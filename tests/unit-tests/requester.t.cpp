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

#include "requester.hpp"
#include "detail/error-encoder.hpp"
#include "detail/probe-encoder.hpp"
#include "identity-challenge/challenge-module.hpp"
#include "ca-module.hpp"
#include "test-common.hpp"

namespace ndn {
namespace ndncert {
namespace tests {

using namespace requester;

BOOST_FIXTURE_TEST_SUITE(TestRequester, IdentityManagementTimeFixture)

/* PROBE */
BOOST_AUTO_TEST_CASE(GenProbeInterest)
{
  auto identity = addIdentity(Name("/site"));
  auto key = identity.getDefaultKey();
  auto cert = key.getDefaultCertificate();

  CaProfile ca_profile;
  ca_profile.m_probeParameterKeys.push_back("email");
  ca_profile.m_probeParameterKeys.push_back("uid");
  ca_profile.m_probeParameterKeys.push_back("name");
  ca_profile.m_caPrefix = Name("/site");
  ca_profile.m_cert = std::make_shared<security::Certificate>(cert);

  std::vector<std::tuple<std::string, std::string>> probeParams;
  probeParams.push_back(std::make_tuple("email", "zhiyi@cs.ucla.edu"));
  probeParams.push_back(std::make_tuple("uid", "987654321"));
  probeParams.push_back(std::make_tuple("name", "Zhiyi Zhang"));
  auto firstInterest = Requester::genProbeInterest(ca_profile, std::move(probeParams));

  BOOST_CHECK(firstInterest->getName().at(-1).isParametersSha256Digest());
  // ignore the last name component (ParametersSha256Digest)
  BOOST_CHECK_EQUAL(firstInterest->getName().getPrefix(-1), "/site/CA/PROBE");
  BOOST_CHECK_EQUAL(readString(firstInterest->getApplicationParameters().get(tlv::ParameterValue)), "zhiyi@cs.ucla.edu");
}

BOOST_AUTO_TEST_CASE(OnProbeResponse){
  auto identity = addIdentity(Name("/site"));
  auto key = identity.getDefaultKey();
  auto cert = key.getDefaultCertificate();

  CaProfile ca_profile;
  ca_profile.m_probeParameterKeys.push_back("email");
  ca_profile.m_probeParameterKeys.push_back("uid");
  ca_profile.m_probeParameterKeys.push_back("name");
  ca_profile.m_caPrefix = Name("/site");
  ca_profile.m_cert = std::make_shared<security::Certificate>(cert);

  std::vector<Name> availableNames;
  availableNames.push_back(Name("/site1"));
  availableNames.push_back(Name("/site2"));

  util::DummyClientFace face(io, m_keyChain, {true, true});
  ca::CaModule ca(face, m_keyChain, "tests/unit-tests/config-files/config-ca-5", "ca-storage-memory");

  Data reply;
  reply.setName(Name("/site/CA/PROBE"));
  reply.setFreshnessPeriod(time::seconds(100));
  reply.setContent(ProbeEncoder::encodeDataContent(availableNames, 3, ca.m_config.m_redirection));
  m_keyChain.sign(reply, signingByIdentity(identity));

  std::vector<std::pair<Name, int>> names;
  std::vector<Name> redirects;
  Requester::onProbeResponse(reply, ca_profile, names, redirects);

  // Test names and redirects are properly stored
  BOOST_CHECK_EQUAL(names.size(), 2);
  BOOST_CHECK_EQUAL(names[0].first.toUri(), "/site1");
  BOOST_CHECK_EQUAL(names[0].second, 3);
  BOOST_CHECK_EQUAL(names[1].first.toUri(), "/site2");
  BOOST_CHECK_EQUAL(names[1].second, 3);

  BOOST_CHECK_EQUAL(redirects.size(), 2);
  BOOST_CHECK_EQUAL(security::extractIdentityFromCertName(redirects[0].getPrefix(-1)), "/ndn/site1");
  BOOST_CHECK_EQUAL(security::extractIdentityFromCertName(redirects[1].getPrefix(-1)), "/ndn/site1");
}

BOOST_AUTO_TEST_CASE(ErrorHandling)
{
  auto identity = addIdentity(Name("/site"));
  auto key = identity.getDefaultKey();
  auto cert = key.getDefaultCertificate();

  CaProfile item;
  item.m_caPrefix = Name("/site");
  item.m_cert = std::make_shared<security::Certificate>(cert);
  RequesterState state(m_keyChain, item, RequestType::NEW);

  Data errorPacket;
  errorPacket.setName(Name("/site/pretend/this/is/error/packet"));
  errorPacket.setFreshnessPeriod(time::seconds(100));
  errorPacket.setContent(ErrorEncoder::encodeDataContent(ErrorCode::INVALID_PARAMETER, "This is a test."));
  m_keyChain.sign(errorPacket, signingByIdentity(identity));

  std::vector<std::pair<Name, int>> ids;
  std::vector<Name> cas;
  BOOST_CHECK_THROW(Requester::onProbeResponse(errorPacket, item, ids, cas), std::runtime_error);
  BOOST_CHECK_THROW(Requester::onNewRenewRevokeResponse(state, errorPacket), std::runtime_error);
  BOOST_CHECK_THROW(Requester::onChallengeResponse(state, errorPacket), std::runtime_error);
}

BOOST_AUTO_TEST_SUITE_END() // TestRequester

} // namespace tests
} // namespace ndncert
} // namespace ndn
