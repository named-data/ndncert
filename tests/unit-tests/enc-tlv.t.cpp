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

#include "protocol-detail/crypto-helper.hpp"
#include "protocol-detail/enc-tlv.hpp"
#include "test-common.hpp"

namespace ndn {
namespace ndncert {
namespace tests {

BOOST_AUTO_TEST_SUITE(TestEncTlv)

BOOST_AUTO_TEST_CASE(EncodingDecoding)
{
  const uint8_t key[] = {0xbc, 0x22, 0xf3, 0xf0, 0x5c, 0xc4, 0x0d, 0xb9,
                         0x31, 0x1e, 0x41, 0x92, 0x96, 0x6f, 0xee, 0x92};
  const std::string plaintext = "alongstringalongstringalongstringalongstringalongstringalongstringalongstringalongstring";
  const std::string associatedData = "test";
  auto block = encodeBlockWithAesGcm128(tlv::Content, key, (uint8_t*)plaintext.c_str(), plaintext.size(),
                                        (uint8_t*)associatedData.c_str(), associatedData.size());
  auto decoded = decodeBlockWithAesGcm128(block, key, (uint8_t*)associatedData.c_str(), associatedData.size());
  BOOST_CHECK_EQUAL(plaintext, std::string((char*)decoded.get<uint8_t>(), decoded.size()));
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace tests
} // namespace ndncert
} // namespace ndn
