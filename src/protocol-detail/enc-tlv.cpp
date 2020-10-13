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

#include "enc-tlv.hpp"
#include "crypto-helper.hpp"
#include <ndn-cxx/encoding/buffer-stream.hpp>
#include <ndn-cxx/security/transform/block-cipher.hpp>
#include <ndn-cxx/security/transform/buffer-source.hpp>
#include <ndn-cxx/security/transform/stream-sink.hpp>
#include <ndn-cxx/util/random.hpp>

namespace ndn {
namespace ndncert {

Block
encodeBlockWithAesGcm128(uint32_t tlv_type, const uint8_t* key, const uint8_t* payload, size_t payloadSize,
                         const uint8_t* associatedData, size_t associatedDataSize)
{
  Buffer iv;
  iv.resize(12);
  random::generateSecureBytes(iv.data(), iv.size());

  uint8_t encryptedPayload[payloadSize];
  uint8_t tag[16];
  size_t encryptedPayloadLen = aes_gcm_128_encrypt(payload, payloadSize, associatedData, associatedDataSize,
                                                   key, iv.data(), encryptedPayload, tag);
  auto content = makeEmptyBlock(tlv_type);
  content.push_back(makeBinaryBlock(tlv_initialization_vector, iv.data(), iv.size()));
  content.push_back(makeBinaryBlock(tlv_authentication_tag, tag, 16));
  content.push_back(makeBinaryBlock(tlv_encrypted_payload, encryptedPayload, encryptedPayloadLen));
  content.encode();
  return content;
}

Buffer
decodeBlockWithAesGcm128(const Block& block, const uint8_t* key, const uint8_t* associatedData, size_t associatedDataSize)
{
  block.parse();
  Buffer result;
  result.resize(block.get(tlv_encrypted_payload).value_size());
  int resultLen = aes_gcm_128_decrypt(block.get(tlv_encrypted_payload).value(),
                                      block.get(tlv_encrypted_payload).value_size(),
                                      associatedData, associatedDataSize, block.get(tlv_authentication_tag).value(),
                                      key, block.get(tlv_initialization_vector).value(), result.data());
  if (resultLen == -1 || resultLen != (int)block.get(tlv_encrypted_payload).value_size()) {
    return Buffer();
  }
  return result;
}

} // namespace ndncert
} // namespace ndn
