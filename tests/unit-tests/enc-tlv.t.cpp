/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/**
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

#include "crypto-support/enc-tlv.hpp"
#include "crypto-support/crypto-helper.hpp"
#include "test-common.hpp"

namespace ndn {
namespace ndncert {
namespace tests {

BOOST_AUTO_TEST_SUITE(TestEncTlv)

BOOST_AUTO_TEST_CASE(Test0)
{
  ECDHState aliceState;
  auto alicePub = aliceState.getRawSelfPubKey();
  BOOST_CHECK(aliceState.context->publicKeyLen != 0);

  ECDHState bobState;
  auto bobPub = bobState.getRawSelfPubKey();
  BOOST_CHECK(bobState.context->publicKeyLen != 0);

  auto aliceResult = aliceState.deriveSecret(bobPub, bobState.context->publicKeyLen);
  BOOST_CHECK(aliceState.context->sharedSecretLen != 0);

  auto bobResult = bobState.deriveSecret(alicePub, aliceState.context->publicKeyLen);
  BOOST_CHECK(bobState.context->sharedSecretLen != 0);

  BOOST_CHECK_EQUAL_COLLECTIONS(aliceResult, aliceResult + 32,
                                bobResult, bobResult + 32);

  auto aliceIv = aes_generateIV();
  std::string payload = "I am the payload, I am the payload!";
  auto aliceBlock = genEncBlock(tlv::Content, aliceResult, 32, (const uint8_t*)payload.c_str(), payload.size());

  auto result = parseEncBlock(bobResult, 32, aliceBlock);
  std::string bobPayload((const char*)result.data());
  BOOST_CHECK_EQUAL(payload, bobPayload);
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace tests
} // namespace ndncert
} // namespace ndn
