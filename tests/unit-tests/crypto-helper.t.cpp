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

#include "crypto-support/crypto-helper.hpp"
#include "test-common.hpp"
#include <iostream>

namespace ndn {
namespace ndncert {
namespace tests {

BOOST_AUTO_TEST_SUITE(TestCryptoHelper)

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
}

BOOST_AUTO_TEST_CASE(Test1)
{
  ECDHState aliceState;
  auto alicePub = aliceState.getBase64PubKey();
  BOOST_CHECK(alicePub != "");

  ECDHState bobState;
  auto bobPub = bobState.getBase64PubKey();
  BOOST_CHECK(bobPub != "");

  auto aliceResult = aliceState.deriveSecret(bobPub);
  BOOST_CHECK(aliceState.context->sharedSecretLen != 0);

  auto bobResult = bobState.deriveSecret(alicePub);
  BOOST_CHECK(bobState.context->sharedSecretLen != 0);

  BOOST_CHECK_EQUAL_COLLECTIONS(aliceResult, aliceResult + 32,
                                bobResult, bobResult + 32);
}

BOOST_AUTO_TEST_CASE(test2)
{
  uint8_t secret[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07};
  uint8_t salt[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07};
  uint8_t result[32];
  auto resultLen = hkdf(secret, sizeof(secret), salt, sizeof(salt),result, 32);
  BOOST_CHECK(resultLen != 0);
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace tests
} // namespace ndncert
} // namespace ndn
