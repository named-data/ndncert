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

#include "detail/challenge-encoder.hpp"
#include "detail/error-encoder.hpp"
#include "detail/info-encoder.hpp"
#include "detail/probe-encoder.hpp"
#include "detail/request-encoder.hpp"
#include "detail/ca-configuration.hpp"

#include "tests/boost-test.hpp"
#include "tests/clock-fixture.hpp"
#include "tests/key-chain-fixture.hpp"

namespace ndncert::tests {

BOOST_AUTO_TEST_SUITE(TestProtocolEncoding)

BOOST_AUTO_TEST_CASE(InfoEncoding)
{
  ca::CaConfig config;
  config.load("tests/unit-tests/config-files/config-ca-1");

  requester::ProfileStorage caCache;
  caCache.load("tests/unit-tests/config-files/config-client-1");
  auto& cert = caCache.getKnownProfiles().front().cert;

  auto b = infotlv::encodeDataContent(config.caProfile, *cert);
  auto item = infotlv::decodeDataContent(b);

  BOOST_CHECK_EQUAL(*item.cert, *cert);
  BOOST_CHECK_EQUAL(item.caInfo, config.caProfile.caInfo);
  BOOST_CHECK_EQUAL(item.caPrefix, config.caProfile.caPrefix);
  BOOST_CHECK_EQUAL_COLLECTIONS(item.probeParameterKeys.begin(), item.probeParameterKeys.end(),
                                config.caProfile.probeParameterKeys.begin(), config.caProfile.probeParameterKeys.end());
  BOOST_CHECK_EQUAL(item.maxValidityPeriod, config.caProfile.maxValidityPeriod);
}

BOOST_AUTO_TEST_CASE(ErrorEncoding)
{
  std::string msg = "Just to test";
  auto b = errortlv::encodeDataContent(ErrorCode::NAME_NOT_ALLOWED, msg);
  auto item = errortlv::decodefromDataContent(b);
  BOOST_CHECK_EQUAL(std::get<0>(item), ErrorCode::NAME_NOT_ALLOWED);
  BOOST_CHECK_EQUAL(std::get<1>(item), msg);
}

BOOST_AUTO_TEST_CASE(ProbeEncodingAppParam)
{
  std::multimap<std::string, std::string> parameters;
  parameters.emplace("key1", "value1");
  parameters.emplace("key2", "value2");
  auto appParam = probetlv::encodeApplicationParameters(std::move(parameters));
  auto param1 = probetlv::decodeApplicationParameters(appParam);
  BOOST_CHECK_EQUAL(param1.size(), 2);
  BOOST_CHECK_EQUAL(param1.find("key1")->second, "value1");
  BOOST_CHECK_EQUAL(param1.find("key2")->second, "value2");
}

BOOST_AUTO_TEST_CASE(ProbeEncodingData)
{
  ca::CaConfig config;
  config.load("tests/unit-tests/config-files/config-ca-5");
  std::vector<Name> names;
  names.emplace_back("/ndn/1");
  names.emplace_back("/ndn/2");
  std::vector<Name> redirectionNames;
  for (const auto& i : config.redirection) redirectionNames.push_back(i.first->getFullName());
  auto b = probetlv::encodeDataContent(names, 2, redirectionNames);
  std::vector<std::pair<Name, int>> retNames;
  std::vector<Name> redirection;
  probetlv::decodeDataContent(b, retNames, redirection);
  BOOST_CHECK_EQUAL(retNames.size(), names.size());
  auto it1 = retNames.begin();
  auto it2 = names.begin();
  for (; it1 != retNames.end() && it2 != names.end(); it1++, it2++) {
    BOOST_CHECK_EQUAL(it1->first, *it2);
    BOOST_CHECK_EQUAL(it1->second, 2);
  }
  BOOST_CHECK_EQUAL(redirection.size(), config.redirection.size());
  auto it3 = redirection.begin();
  auto it4 = config.redirection.begin();
  for (; it3 != redirection.end() && it4 != config.redirection.end(); it3++, it4++) {
    BOOST_CHECK_EQUAL(*it3, it4->first->getFullName());
  }
}

BOOST_AUTO_TEST_CASE(NewRevokeEncodingParam)
{
  requester::ProfileStorage caCache;
  caCache.load("tests/unit-tests/config-files/config-client-1");
  auto& certRequest = caCache.getKnownProfiles().front().cert;
  std::vector<uint8_t> pub = ECDHState().getSelfPubKey();
  auto b = requesttlv::encodeApplicationParameters(RequestType::REVOKE, pub, *certRequest);
  std::vector<uint8_t> returnedPub;
  std::shared_ptr<Certificate> returnedCert;
  requesttlv::decodeApplicationParameters(b, RequestType::REVOKE, returnedPub, returnedCert);

  BOOST_TEST(returnedPub == pub, boost::test_tools::per_element());
  BOOST_CHECK_EQUAL(*returnedCert, *certRequest);
}

BOOST_AUTO_TEST_CASE(NewRevokeEncodingData)
{
  std::vector<uint8_t> pub = ECDHState().getSelfPubKey();
  std::array<uint8_t, 32> salt = {{101}};
  RequestId id = {{102}};
  std::vector<std::string> list;
  list.emplace_back("abc");
  list.emplace_back("def");
  auto b = requesttlv::encodeDataContent(pub, salt, id, list);
  std::vector<uint8_t> returnedPub;
  std::array<uint8_t, 32> returnedSalt;
  RequestId returnedId;
  auto retlist = requesttlv::decodeDataContent(b, returnedPub, returnedSalt, returnedId);
  BOOST_CHECK_EQUAL_COLLECTIONS(returnedPub.begin(), returnedPub.end(), pub.begin(), pub.end());
  BOOST_CHECK_EQUAL_COLLECTIONS(returnedSalt.begin(), returnedSalt.end(), salt.begin(), salt.end());
  BOOST_CHECK_EQUAL_COLLECTIONS(returnedId.begin(), returnedId.end(), id.begin(), id.end());
}

class ChallengeEncodingFixture : public ClockFixture, public KeyChainFixture
{
};

BOOST_FIXTURE_TEST_CASE(ChallengeEncoding, ChallengeEncodingFixture)
{
  const uint8_t key[] = {0x23, 0x70, 0xe3, 0x20, 0xd4, 0x34, 0x42, 0x08,
                         0xe0, 0xff, 0x56, 0x83, 0xf2, 0x43, 0xb2, 0x13};
  requester::ProfileStorage caCache;
  caCache.load("tests/unit-tests/config-files/config-client-1");
  auto certRequest = *caCache.getKnownProfiles().front().cert;
  RequestId id = {{102}};
  ca::RequestState state;
  state.caPrefix = Name("/ndn/ucla");
  state.requestId = id;
  state.requestType = RequestType::NEW;
  state.status = Status::PENDING;
  state.cert = certRequest;
  std::memcpy(state.encryptionKey.data(), key, sizeof(key));
  state.challengeType = "pin";
  auto tp = time::system_clock::now();
  state.challengeState = ca::ChallengeState("test", tp, 3, time::seconds(3600), JsonSection());
  auto contentBlock = challengetlv::encodeDataContent(state, Name("/ndn/ucla/a/b/c"));

  requester::Request context(m_keyChain, caCache.getKnownProfiles().front(), RequestType::NEW);
  context.m_requestId = id;
  std::memcpy(context.m_aesKey.data(), key, sizeof(key));
  advanceClocks(time::seconds(10));
  challengetlv::decodeDataContent(contentBlock, context);

  BOOST_CHECK_EQUAL(static_cast<size_t>(context.m_status), static_cast<size_t>(Status::PENDING));
  BOOST_CHECK_EQUAL(context.m_challengeStatus, "test");
  BOOST_CHECK_EQUAL(context.m_remainingTries, 3);
  BOOST_CHECK_EQUAL(context.m_freshBefore, tp + time::seconds(3600) + time::seconds(10));
  BOOST_CHECK_EQUAL(context.m_issuedCertName, "/ndn/ucla/a/b/c");
}

BOOST_AUTO_TEST_SUITE_END() // TestProtocolEncoding

} // namespace ndncert::tests
