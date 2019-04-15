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

#ifndef NDNCERT_CRYPTO_SUPPORT_ENC_TLV_HPP
#define NDNCERT_CRYPTO_SUPPORT_ENC_TLV_HPP

#include <ndn-cxx/encoding/block-helpers.hpp>

namespace ndn {
namespace ndncert {

enum {
  ENCRYPTED_PAYLOAD = 630,
  INITIAL_VECTOR = 632,
};

Block
genEncBlock(uint32_t tlv_type, const uint8_t* key, size_t keyLen, const uint8_t* payload, size_t payloadSize);

Buffer
parseEncBlock(const uint8_t* key, size_t keyLen, const Block& block);


} // namespace ndncert
} // namespace ndn

#endif // NDNCERT_CRYPTO_SUPPORT_ENC_TLV_HPP
