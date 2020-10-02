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

#include <protocol-detail/error.hpp>
#include "requester.hpp"
#include "challenge-module.hpp"
#include "ca-module.hpp"
#include "test-common.hpp"

namespace ndn {
namespace ndncert {
namespace tests {

BOOST_FIXTURE_TEST_SUITE(TestRequester, IdentityManagementTimeFixture)

BOOST_AUTO_TEST_CASE(ErrorHandling)
{
  auto identity = addIdentity(Name("/site"));
  auto key = identity.getDefaultKey();
  auto cert = key.getDefaultCertificate();

  CaProfile item;
  item.m_caPrefix = Name("/site");
  item.m_cert = std::make_shared<security::v2::Certificate>(cert);
  RequesterState state(m_keyChain, item, RequestType::NEW);

  Data errorPacket;
  errorPacket.setName(Name("/site/pretend/this/is/error/packet"));
  errorPacket.setFreshnessPeriod(time::seconds(100));
  errorPacket.setContent(ErrorTLV::encodeDataContent(ErrorCode::INVALID_PARAMETER, "This is a test."));
  m_keyChain.sign(errorPacket, signingByIdentity(identity));

  std::vector<Name> ids, cas;
  BOOST_CHECK_THROW(Requester::onProbeResponse(errorPacket, item, ids, cas), std::runtime_error);
  BOOST_CHECK_THROW(Requester::onNewRenewRevokeResponse(state, errorPacket), std::runtime_error);
  BOOST_CHECK_THROW(Requester::onChallengeResponse(state, errorPacket), std::runtime_error);
}

BOOST_AUTO_TEST_SUITE_END() // TestRequester

} // namespace tests
} // namespace ndncert
} // namespace ndn
