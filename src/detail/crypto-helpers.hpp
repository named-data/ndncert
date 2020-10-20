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

#ifndef NDNCERT_PROTOCOL_DETAIL_CRYPTO_HELPER_HPP
#define NDNCERT_PROTOCOL_DETAIL_CRYPTO_HELPER_HPP

#include "ndncert-common.hpp"

namespace ndn {
namespace ndncert {

class ECDHState
{
public:
  ECDHState();
  ~ECDHState();

  std::string
  getBase64PubKey();

  uint8_t*
  deriveSecret(const std::string& peerKeyStr);

NDNCERT_PUBLIC_WITH_TESTS_ELSE_PRIVATE:
  uint8_t*
  deriveSecret(const uint8_t* peerkey, size_t peerKeySize);

  uint8_t*
  getRawSelfPubKey();

public:
  uint8_t m_publicKey[256];
  size_t m_publicKeyLen = 0;
  uint8_t m_sharedSecret[256];
  size_t m_sharedSecretLen = 0;

private:
  struct ECDH_CTX;
  unique_ptr<ECDH_CTX> context;
};

/**
 * @brief HMAC based key derivation function (HKDF).
 *
 * @param secret The input to the HKDF.
 * @param secret_len The length of the secret.
 * @param salt The salt used in HKDF.
 * @param salt_len The length of the salt.
 * @param output The output of the HKDF.
 * @param output_len The length of expected output.
 * @param info The additional information used in HKDF.
 * @param info_len The length of the additional information.
 * @return int The length of the derived key if successful, -1 if failed.
 */
int
hkdf(const uint8_t* secret, size_t secret_len,
     const uint8_t* salt, size_t salt_len,
     uint8_t* output, size_t output_len,
     const uint8_t* info = nullptr, size_t info_len = 0);

/**
 * @brief HMAC based on SHA-256.
 *
 * @param data The intput array to hmac.
 * @param data_length The length of the input array.
 * @param key The HMAC key.
 * @param key_length The length of the HMAC key.
 * @param result The result of the HMAC. Enough memory (32 Bytes) must be allocated beforehands.
 * @throw runtime_error when an error occurred in the underlying HMAC.
 */
void
hmac_sha256(const uint8_t* data, size_t data_length,
            const uint8_t* key, size_t key_length,
            uint8_t* result);

/**
 * @brief Authenticated GCM 128 Encryption with associated data.
 *
 * @param plaintext The plaintext.
 * @param plaintext_len The size of plaintext.
 * @param associated The associated authentication data.
 * @param associated_len The size of associated authentication data.
 * @param key 16 bytes AES key.
 * @param iv 12 bytes IV.
 * @param ciphertext The output and enough memory must be allocated beforehands.
 * @param tag 16 bytes tag.
 * @return int The size of ciphertext.
 * @throw runtime_error When there is an error in the process of encryption.
 */
int
aes_gcm_128_encrypt(const uint8_t* plaintext, size_t plaintext_len, const uint8_t* associated, size_t associated_len,
                    const uint8_t* key, const uint8_t* iv, uint8_t* ciphertext, uint8_t* tag);

/**
 * @brief Authenticated GCM 128 Decryption with associated data.
 *
 * @param ciphertext The ciphertext.
 * @param ciphertext_len The size of ciphertext.
 * @param associated The associated authentication data.
 * @param associated_len The size of associated authentication data.
 * @param tag 16 bytes tag.
 * @param key 16 bytes AES key.
 * @param iv 12 bytes IV.
 * @param plaintext The output and enough memory must be allocated beforehands.
 * @return int The size of plaintext or -1 if the verification fails.
 * @throw runtime_error When there is an error in the process of encryption.
 */
int
aes_gcm_128_decrypt(const uint8_t* ciphertext, size_t ciphertext_len, const uint8_t* associated, size_t associated_len,
                    const uint8_t* tag, const uint8_t* key, const uint8_t* iv, uint8_t* plaintext);

/**
 * @brief Encode the payload into TLV block with Authenticated GCM 128 Encryption.
 *
 * @param tlv_type The TLV TYPE of the encoded block, either ApplicationParameters or Content.
 * @param key The AES key used for encryption.
 * @param payload The plaintext payload.
 * @param payloadSize The size of the plaintext payload.
 * @param associatedData The associated data used for authentication.
 * @param associatedDataSize The size of associated data.
 * @param counter The counter of blocks that have been encrypted by the requester/CA.
 * @return Block The TLV block with @param tlv_type TLV TYPE.
 */
Block
encodeBlockWithAesGcm128(uint32_t tlv_type, const uint8_t* key, const uint8_t* payload, size_t payloadSize,
                         const uint8_t* associatedData, size_t associatedDataSize, uint32_t& counter);

/**
 * @brief Decode the payload from TLV block with Authenticated GCM 128 Encryption.
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

#endif // NDNCERT_PROTOCOL_DETAIL_CRYPTO_HELPER_HPP
