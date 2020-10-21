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

#ifndef NDNCERT_DETAIL_CRYPTO_HELPERS_HPP
#define NDNCERT_DETAIL_CRYPTO_HELPERS_HPP

#include "ndncert-common.hpp"
#include <openssl/evp.h>

namespace ndn {
namespace ndncert {

/**
 * @brief State for ECDH.
 *
 * The ECDH is based on prime256v1.
 */
class ECDHState : noncopyable
{
public:
  ECDHState();
  ~ECDHState();

  /**
   * @brief Derive ECDH secret from peer's EC public key and self's private key.
   *
   * @param peerkey Peer's EC public key in the uncompressed octet string format.
   *                See details in https://www.openssl.org/docs/man1.1.1/man3/EC_POINT_point2oct.html.
   * @return const std::vector<uint8_t>& the derived secret.
   */
  const std::vector<uint8_t>&
  deriveSecret(const std::vector<uint8_t>& peerkey);

  /**
   * @brief Get the Self Pub Key object
   *
   * @return const std::vector<uint8_t>& the Self public key in the uncompressed oct string format.
   *         See details in https://www.openssl.org/docs/man1.1.1/man3/EC_POINT_point2oct.html.
   */
  const std::vector<uint8_t>&
  getSelfPubKey();

private:
  EVP_PKEY* m_privkey = nullptr;
  std::vector<uint8_t> m_pubKey;
  std::vector<uint8_t> m_secret;
};

/**
 * @brief HMAC based key derivation function (HKDF).
 *
 * @param secret The input to the HKDF.
 * @param secretLen The length of the secret.
 * @param salt The salt used in HKDF.
 * @param saltLen The length of the salt.
 * @param output The output of the HKDF.
 * @param outputLen The length of expected output.
 * @param info The additional information used in HKDF.
 * @param infoLen The length of the additional information.
 * @return size_t The length of the derived key if successful.
 */
size_t
hkdf(const uint8_t* secret, size_t secretLen,
     const uint8_t* salt, size_t saltLen,
     uint8_t* output, size_t outputLen,
     const uint8_t* info = nullptr, size_t infoLen = 0);

/**
 * @brief HMAC based on SHA-256.
 *
 * @param data The intput array to hmac.
 * @param dataLen The length of the input array.
 * @param key The HMAC key.
 * @param keyLen The length of the HMAC key.
 * @param result The result of the HMAC. Enough memory (32 Bytes) must be allocated beforehands.
 * @throw runtime_error when an error occurred in the underlying HMAC.
 */
void
hmacSha256(const uint8_t* data, size_t dataLen,
           const uint8_t* key, size_t keyLen,
           uint8_t* result);

/**
 * @brief Authenticated GCM 128 Encryption with associated data.
 *
 * @param plaintext The plaintext.
 * @param plaintextLen The size of plaintext.
 * @param associated The associated authentication data.
 * @param associatedLen The size of associated authentication data.
 * @param key 16 bytes AES key.
 * @param iv 12 bytes IV.
 * @param ciphertext The output and enough memory must be allocated beforehands.
 * @param tag 16 bytes tag.
 * @return size_t The size of ciphertext.
 * @throw runtime_error When there is an error in the process of encryption.
 */
size_t
aesGcm128Encrypt(const uint8_t* plaintext, size_t plaintextLen, const uint8_t* associated, size_t associatedLen,
                 const uint8_t* key, const uint8_t* iv, uint8_t* ciphertext, uint8_t* tag);

/**
 * @brief Authenticated GCM 128 Decryption with associated data.
 *
 * @param ciphertext The ciphertext.
 * @param ciphertextLen The size of ciphertext.
 * @param associated The associated authentication data.
 * @param associatedLen The size of associated authentication data.
 * @param tag 16 bytes tag.
 * @param key 16 bytes AES key.
 * @param iv 12 bytes IV.
 * @param plaintext The output and enough memory must be allocated beforehands.
 * @return size_t The size of plaintext.
 * @throw runtime_error When there is an error in the process of decryption.
 */
size_t
aesGcm128Decrypt(const uint8_t* ciphertext, size_t ciphertextLen, const uint8_t* associated, size_t associatedLen,
                 const uint8_t* tag, const uint8_t* key, const uint8_t* iv, uint8_t* plaintext);

/**
 * @brief Encode the payload into TLV block with Authenticated GCM 128 Encryption.
 *
 * The TLV spec: https://github.com/named-data/ndncert/wiki/NDNCERT-Protocol-0.3#242-aes-gcm-encryption.
 *
 * @param tlv_type The TLV TYPE of the encoded block, either ApplicationParameters or Content.
 * @param key The AES key used for encryption.
 * @param payload The plaintext payload.
 * @param payloadSize The size of the plaintext payload.
 * @param associatedData The associated data used for authentication.
 * @param associatedDataSize The size of associated data.
 * @param counter An opaque counter that must be passed to subsequent invocations of this function
 *                with the same @p key.
 * @return Block The TLV block with @p tlv_type TLV TYPE.
 */
Block
encodeBlockWithAesGcm128(uint32_t tlvType, const uint8_t* key, const uint8_t* payload, size_t payloadSize,
                         const uint8_t* associatedData, size_t associatedDataSize, uint32_t& counter);

/**
 * @brief Decode the payload from TLV block with Authenticated GCM 128 Encryption.
 *
 * The TLV spec: https://github.com/named-data/ndncert/wiki/NDNCERT-Protocol-0.3#242-aes-gcm-encryption.
 *
 * @param block The TLV block in the format of NDNCERT protocol.
 * @param key The AES key used for encryption.
 * @param associatedData The associated data used for authentication.
 * @param associatedDataSize The size of associated data.
 * @return Buffer The plaintext buffer.
 */
Buffer
decodeBlockWithAesGcm128(const Block& block, const uint8_t* key,
                         const uint8_t* associatedData, size_t associatedDataSize);

} // namespace ndncert
} // namespace ndn

#endif // NDNCERT_DETAIL_CRYPTO_HELPERS_HPP
