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

#ifndef NDNCERT_CRYPTO_SUPPORT_ENC_TLV_HPP
#define NDNCERT_CRYPTO_SUPPORT_ENC_TLV_HPP

#include "../ndncert-common.hpp"

namespace ndn {
namespace ndncert {

/**
 * Encode the payload into TLV block with Authenticated GCM 128 Encryption
 * @p tlv_type, intput, the TLV TYPE of the encoded block, either ApplicationParameters or Content
 * @p key, intput, 16 Bytes, the AES key used for encryption
 * @p payload, input, the plaintext payload
 * @p payloadSize, input, the size of the plaintext payload
 * @p associatedData, input, associated data used for authentication
 * @p associatedDataSize, input, the size of associated data
 * @return the TLV block with @p tlv_type TLV TYPE
 */
Block
encodeBlockWithAesGcm128(uint32_t tlv_type, const uint8_t* key, const uint8_t* payload, size_t payloadSize,
                         const uint8_t* associatedData, size_t associatedDataSize);

/**
 * Decode the payload from TLV block with Authenticated GCM 128 Encryption
 * @p block, intput, the TLV block in the format of NDNCERT protocol
 * @p key, intput, 16 Bytes, the AES key used for encryption
 * @p associatedData, input, associated data used for authentication
 * @p associatedDataSize, input, the size of associated data
 * @return the plaintext buffer
 */
Buffer
decodeBlockWithAesGcm128(const Block& block, const uint8_t* key,
                         const uint8_t* associatedData, size_t associatedDataSize);

} // namespace ndncert
} // namespace ndn

#endif // NDNCERT_CRYPTO_SUPPORT_ENC_TLV_HPP
