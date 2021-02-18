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

#include "detail/crypto-helpers.hpp"

#include <boost/endian/conversion.hpp>
#include <cstring>
#include <ndn-cxx/encoding/buffer-stream.hpp>
#include <ndn-cxx/security/transform/base64-decode.hpp>
#include <ndn-cxx/security/transform/base64-encode.hpp>
#include <ndn-cxx/security/transform/buffer-source.hpp>
#include <ndn-cxx/security/transform/stream-sink.hpp>
#include <ndn-cxx/util/random.hpp>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/hmac.h>
#include <openssl/kdf.h>
#include <openssl/pem.h>

namespace ndn {
namespace ndncert {

ECDHState::ECDHState()
{
  auto EC_NID = NID_X9_62_prime256v1;
  // params context
  EVP_PKEY_CTX* ctx_params = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr);
  if (ctx_params == nullptr) {
    NDN_THROW(std::runtime_error("Could not create context"));
  }
  if (EVP_PKEY_paramgen_init(ctx_params) != 1) {
    EVP_PKEY_CTX_free(ctx_params);
    NDN_THROW(std::runtime_error("Could not initialize parameter generation"));
  }
  if (1 != EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx_params, EC_NID)) {
    EVP_PKEY_CTX_free(ctx_params);
    NDN_THROW(std::runtime_error("Likely unknown elliptical curve ID specified"));
  }
  // generate params
  EVP_PKEY* params = nullptr;
  if (!EVP_PKEY_paramgen(ctx_params, &params)) {
    EVP_PKEY_CTX_free(ctx_params);
    NDN_THROW(std::runtime_error("Could not create parameter object parameters"));
  }
  // key generation context
  EVP_PKEY_CTX* ctx_keygen = EVP_PKEY_CTX_new(params, nullptr);
  if (ctx_keygen == nullptr) {
    EVP_PKEY_free(params);
    EVP_PKEY_CTX_free(ctx_params);
    NDN_THROW(std::runtime_error("Could not create the context for the key generation"));
  }
  if (1 != EVP_PKEY_keygen_init(ctx_keygen)) {
    EVP_PKEY_CTX_free(ctx_keygen);
    EVP_PKEY_free(params);
    EVP_PKEY_CTX_free(ctx_params);
    NDN_THROW(std::runtime_error("Could not init context for key generation"));
  }
  if (1 != EVP_PKEY_keygen(ctx_keygen, &m_privkey)) {
    EVP_PKEY_CTX_free(ctx_keygen);
    EVP_PKEY_free(params);
    EVP_PKEY_CTX_free(ctx_params);
    NDN_THROW(std::runtime_error("Could not generate DHE keys in final step"));
  }
  EVP_PKEY_CTX_free(ctx_keygen);
  EVP_PKEY_free(params);
  EVP_PKEY_CTX_free(ctx_params);
}

ECDHState::~ECDHState()
{
  if (m_privkey != nullptr) {
    EVP_PKEY_free(m_privkey);
  }
}

const std::vector<uint8_t>&
ECDHState::getSelfPubKey()
{
  auto privECKey = EVP_PKEY_get1_EC_KEY(m_privkey);
  if (privECKey == nullptr) {
    NDN_THROW(std::runtime_error("Could not get key when calling EVP_PKEY_get1_EC_KEY()"));
  }
  auto ecPoint = EC_KEY_get0_public_key(privECKey);
  auto group = EC_KEY_get0_group(privECKey);
  auto requiredBufLen = EC_POINT_point2oct(group, ecPoint, POINT_CONVERSION_UNCOMPRESSED, nullptr, 0, nullptr);
  m_pubKey.resize(requiredBufLen);
  auto rev = EC_POINT_point2oct(group, ecPoint, POINT_CONVERSION_UNCOMPRESSED,
                                m_pubKey.data(), requiredBufLen, nullptr);
  EC_KEY_free(privECKey);
  if (rev == 0) {
    NDN_THROW(std::runtime_error("Could not convert EC_POINTS to octet string when calling EC_POINT_point2oct()"));
  }
  return m_pubKey;
}

const std::vector<uint8_t>&
ECDHState::deriveSecret(const std::vector<uint8_t>& peerKey)
{
  // prepare self private key
  auto privECKey = EVP_PKEY_get1_EC_KEY(m_privkey);
  if (privECKey == nullptr) {
    NDN_THROW(std::runtime_error("Cannot not get key when calling EVP_PKEY_get1_EC_KEY()"));
  }
  auto group = EC_KEY_get0_group(privECKey);
  EC_KEY_free(privECKey);
  // prepare the peer public key
  auto peerPoint = EC_POINT_new(group);
  if (peerPoint == nullptr) {
    NDN_THROW(std::runtime_error("Cannot create the EC_POINT for peer key when calling EC_POINT_new()"));
  }
  if (EC_POINT_oct2point(group, peerPoint, peerKey.data(), peerKey.size(), nullptr) == 0) {
    EC_POINT_free(peerPoint);
    NDN_THROW(std::runtime_error("Cannot convert peer's key into a EC point when calling EC_POINT_oct2point()"));
  }
  EC_KEY* ecPeerkey = EC_KEY_new();
  if (ecPeerkey == nullptr) {
    EC_POINT_free(peerPoint);
    NDN_THROW(std::runtime_error("Cannot create EC_KEY for peer key when calling EC_KEY_new()"));
  }
  if (EC_KEY_set_group(ecPeerkey, group) != 1) {
    EC_POINT_free(peerPoint);
    NDN_THROW(std::runtime_error("Cannot set group for peer key's EC_KEY when calling EC_KEY_set_group()"));
  }
  if (EC_KEY_set_public_key(ecPeerkey, peerPoint) == 0) {
    EC_KEY_free(ecPeerkey);
    EC_POINT_free(peerPoint);
    NDN_THROW(std::runtime_error("Cannot initialize peer EC_KEY with the EC_POINT when calling EC_KEY_set_public_key()"));
  }
  EVP_PKEY* evpPeerkey = EVP_PKEY_new();
  if (EVP_PKEY_set1_EC_KEY(evpPeerkey, ecPeerkey) == 0) {
    EC_KEY_free(ecPeerkey);
    EC_POINT_free(peerPoint);
    NDN_THROW(std::runtime_error("Cannot create EVP_PKEY for peer key when calling EVP_PKEY_new()"));
  }
  EC_KEY_free(ecPeerkey);
  EC_POINT_free(peerPoint);
  // ECDH context
  EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(m_privkey, nullptr);
  if (ctx == nullptr) {
    EVP_PKEY_free(evpPeerkey);
    NDN_THROW(std::runtime_error("Cannot create context for ECDH when calling EVP_PKEY_CTX_new()"));
  }
  // Initialize
  if (1 != EVP_PKEY_derive_init(ctx)) {
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(evpPeerkey);
    NDN_THROW(std::runtime_error("Cannot initialize context for ECDH when calling EVP_PKEY_derive_init()"));
  }
  // Provide the peer public key
  if (1 != EVP_PKEY_derive_set_peer(ctx, evpPeerkey)) {
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(evpPeerkey);
    NDN_THROW(std::runtime_error("Cannot set peer key for ECDH when calling EVP_PKEY_derive_set_peer()"));
  }
  // Determine buffer length for shared secret
  size_t secretLen = 0;
  if (1 != EVP_PKEY_derive(ctx, nullptr, &secretLen)) {
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(evpPeerkey);
    NDN_THROW(std::runtime_error("Cannot determine the needed buffer length when calling EVP_PKEY_derive()"));
  }
  m_secret.resize(secretLen);
  // Derive the shared secret
  if (1 != (EVP_PKEY_derive(ctx, m_secret.data(), &secretLen))) {
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(evpPeerkey);
    NDN_THROW(std::runtime_error("Cannot derive ECDH secret when calling EVP_PKEY_derive()"));
  }
  EVP_PKEY_CTX_free(ctx);
  EVP_PKEY_free(evpPeerkey);
  return m_secret;
}

void
hmacSha256(const uint8_t* data, size_t dataLen,
           const uint8_t* key, size_t keyLen,
           uint8_t* result)
{
  auto ret = HMAC(EVP_sha256(), key, keyLen,
                  data, dataLen, result, nullptr);
  if (ret == nullptr) {
    NDN_THROW(std::runtime_error("Error computing HMAC when calling HMAC()"));
  }
}

size_t
hkdf(const uint8_t* secret, size_t secretLen, const uint8_t* salt,
     size_t saltLen, uint8_t* output, size_t outputLen,
     const uint8_t* info, size_t infoLen)
{
  EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
  if (EVP_PKEY_derive_init(pctx) <= 0) {
    EVP_PKEY_CTX_free(pctx);
    NDN_THROW(std::runtime_error("HKDF: Cannot init ctx when calling EVP_PKEY_derive_init()"));
  }
  if (EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256()) <= 0) {
    EVP_PKEY_CTX_free(pctx);
    NDN_THROW(std::runtime_error("HKDF: Cannot set md when calling EVP_PKEY_CTX_set_hkdf_md()"));
  }
  if (EVP_PKEY_CTX_set1_hkdf_salt(pctx, salt, saltLen) <= 0) {
    EVP_PKEY_CTX_free(pctx);
    NDN_THROW(std::runtime_error("HKDF: Cannot set salt when calling EVP_PKEY_CTX_set1_hkdf_salt()"));
  }
  if (EVP_PKEY_CTX_set1_hkdf_key(pctx, secret, secretLen) <= 0) {
    EVP_PKEY_CTX_free(pctx);
    NDN_THROW(std::runtime_error("HKDF: Cannot set secret when calling EVP_PKEY_CTX_set1_hkdf_key()"));
  }
  if (EVP_PKEY_CTX_add1_hkdf_info(pctx, info, infoLen) <= 0) {
    EVP_PKEY_CTX_free(pctx);
    NDN_THROW(std::runtime_error("HKDF: Cannot set info when calling EVP_PKEY_CTX_add1_hkdf_info()"));
  }
  size_t outLen = outputLen;
  if (EVP_PKEY_derive(pctx, output, &outLen) <= 0) {
    EVP_PKEY_CTX_free(pctx);
    NDN_THROW(std::runtime_error("HKDF: Cannot derive result when calling EVP_PKEY_derive()"));
  }
  EVP_PKEY_CTX_free(pctx);
  return outLen;
}

size_t
aesGcm128Encrypt(const uint8_t* plaintext, size_t plaintextLen, const uint8_t* associated, size_t associatedLen,
                 const uint8_t* key, const uint8_t* iv, uint8_t* ciphertext, uint8_t* tag)
{
  EVP_CIPHER_CTX* ctx;
  int len;
  size_t ciphertextLen;
  if (!(ctx = EVP_CIPHER_CTX_new())) {
    NDN_THROW(std::runtime_error("Cannot create and initialise the context when calling EVP_CIPHER_CTX_new()"));
  }
  if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), nullptr, nullptr, nullptr)) {
    EVP_CIPHER_CTX_free(ctx);
    NDN_THROW(std::runtime_error("Cannot initialize the encryption operation when calling EVP_EncryptInit_ex()"));
  }
  if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr)) {
    EVP_CIPHER_CTX_free(ctx);
    NDN_THROW(std::runtime_error("Cannot set IV length when calling EVP_CIPHER_CTX_ctrl()"));
  }
  if (1 != EVP_EncryptInit_ex(ctx, nullptr, nullptr, key, iv)) {
    EVP_CIPHER_CTX_free(ctx);
    NDN_THROW(std::runtime_error("Cannot initialize key and IV when calling EVP_EncryptInit_ex()"));
  }
  if (1 != EVP_EncryptUpdate(ctx, nullptr, &len, associated, associatedLen)) {
    EVP_CIPHER_CTX_free(ctx);
    NDN_THROW(std::runtime_error("Cannot set associated authentication data when calling EVP_EncryptUpdate()"));
  }
  if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintextLen)) {
    EVP_CIPHER_CTX_free(ctx);
    NDN_THROW(std::runtime_error("Cannot encrypt when calling EVP_EncryptUpdate()"));
  }
  ciphertextLen = len;
  if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) {
    EVP_CIPHER_CTX_free(ctx);
    NDN_THROW(std::runtime_error("Cannot finalise the encryption when calling EVP_EncryptFinal_ex()"));
  }
  ciphertextLen += len;
  if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag)) {
    EVP_CIPHER_CTX_free(ctx);
    NDN_THROW(std::runtime_error("Cannot get tag when calling EVP_CIPHER_CTX_ctrl()"));
  }
  EVP_CIPHER_CTX_free(ctx);
  return ciphertextLen;
}

size_t
aesGcm128Decrypt(const uint8_t* ciphertext, size_t ciphertextLen, const uint8_t* associated, size_t associatedLen,
                 const uint8_t* tag, const uint8_t* key, const uint8_t* iv, uint8_t* plaintext)
{
  EVP_CIPHER_CTX* ctx;
  int len;
  size_t plaintextLen;
  if (!(ctx = EVP_CIPHER_CTX_new())) {
    NDN_THROW(std::runtime_error("Cannot create and initialise the context when calling EVP_CIPHER_CTX_new()"));
  }
  if (!EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), nullptr, nullptr, nullptr)) {
    EVP_CIPHER_CTX_free(ctx);
    NDN_THROW(std::runtime_error("Cannot initialise the decryption operation when calling EVP_DecryptInit_ex()"));
  }
  if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr)) {
    EVP_CIPHER_CTX_free(ctx);
    NDN_THROW(std::runtime_error("Cannot set IV length when calling EVP_CIPHER_CTX_ctrl"));
  }
  if (!EVP_DecryptInit_ex(ctx, nullptr, nullptr, key, iv)) {
    EVP_CIPHER_CTX_free(ctx);
    NDN_THROW(std::runtime_error("Cannot initialise key and IV when calling EVP_DecryptInit_ex()"));
  }
  if (!EVP_DecryptUpdate(ctx, nullptr, &len, associated, associatedLen)) {
    EVP_CIPHER_CTX_free(ctx);
    NDN_THROW(std::runtime_error("Cannot set associated authentication data when calling EVP_EncryptUpdate()"));
  }
  if (!EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertextLen)) {
    EVP_CIPHER_CTX_free(ctx);
    NDN_THROW(std::runtime_error("Cannot decrypt when calling EVP_DecryptUpdate()"));
  }
  plaintextLen = len;
  if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, const_cast<void*>(reinterpret_cast<const void*>(tag)))) {
    EVP_CIPHER_CTX_free(ctx);
    NDN_THROW(std::runtime_error("Cannot set tag value when calling EVP_CIPHER_CTX_ctrl()"));
  }
  auto ret = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);
  EVP_CIPHER_CTX_free(ctx);
  if (ret > 0) {
    plaintextLen += len;
    return plaintextLen;
  }
  else {
    NDN_THROW(std::runtime_error("Cannot finalize the decryption when calling EVP_DecryptFinal_ex()"));
  }
}

// Can be removed after boost version 1.72, replaced by boost::endian::load_big_u32
static uint32_t
loadBigU32(const std::vector<uint8_t>& iv, size_t pos)
{
  uint32_t result = iv[pos] << 24 | iv[pos + 1] << 16 | iv[pos + 2] << 8 | iv[pos + 3];
  return result;
}

// Can be removed after boost version 1.72, replaced by boost::endian::store_big_u32
static void
storeBigU32(uint8_t* iv, uint32_t counter)
{
  uint32_t temp = boost::endian::native_to_big(counter);
  std::memcpy(iv, reinterpret_cast<const uint8_t*>(&temp), 4);
  return;
}

static void
updateIv(std::vector<uint8_t>& iv, size_t payloadSize)
{
  // uint32_t counter = boost::endian::load_big_u32(&iv[8]);
  uint32_t counter = loadBigU32(iv, 8);
  uint32_t increment = (payloadSize + 15) / 16;
  if (std::numeric_limits<uint32_t>::max() - counter <= increment) {
    NDN_THROW(std::runtime_error("Error incrementing the AES block counter: "
                                 "too many blocks have been encrypted for the same request instance"));
  }
  else {
    counter += increment;
  }
  // boost::endian::store_big_u32(&iv[8], counter);
  storeBigU32(&iv[8], counter);
}

Block
encodeBlockWithAesGcm128(uint32_t tlvType, const uint8_t* key,
                         const uint8_t* payload, size_t payloadSize,
                         const uint8_t* associatedData, size_t associatedDataSize,
                         std::vector<uint8_t>& encryptionIv)
{
  // The spec of AES encrypted payload TLV used in NDNCERT:
  //   https://github.com/named-data/ndncert/wiki/NDNCERT-Protocol-0.3#242-aes-gcm-encryption
  Buffer encryptedPayload(payloadSize);
  uint8_t tag[16];
  if (encryptionIv.empty()) {
    encryptionIv.resize(12, 0);
    random::generateSecureBytes(encryptionIv.data(), 8);
  }
  size_t encryptedPayloadLen = aesGcm128Encrypt(payload, payloadSize, associatedData, associatedDataSize,
                                                key, encryptionIv.data(), encryptedPayload.data(), tag);
  Block content(tlvType);
  content.push_back(makeBinaryBlock(tlv::InitializationVector, encryptionIv.data(), encryptionIv.size()));
  content.push_back(makeBinaryBlock(tlv::AuthenticationTag, tag, 16));
  content.push_back(makeBinaryBlock(tlv::EncryptedPayload, encryptedPayload.data(), encryptedPayloadLen));
  content.encode();
  // update IV's counter
  updateIv(encryptionIv, payloadSize);
  return content;
}

Buffer
decodeBlockWithAesGcm128(const Block& block, const uint8_t* key,
                         const uint8_t* associatedData, size_t associatedDataSize,
                         std::vector<uint8_t>& decryptionIv)
{
  // The spec of AES encrypted payload TLV used in NDNCERT:
  //   https://github.com/named-data/ndncert/wiki/NDNCERT-Protocol-0.3#242-aes-gcm-encryption
  block.parse();
  const auto& encryptedPayloadBlock = block.get(tlv::EncryptedPayload);
  Buffer result(encryptedPayloadBlock.value_size());
  if (block.get(tlv::InitializationVector).value_size() != 12 || block.get(tlv::AuthenticationTag).value_size() != 16) {
    NDN_THROW(std::runtime_error("Error when decrypting the AES Encrypted Block: "
                                 "The observed IV or Authentication Tag is incorrectly formed."));
  }
  std::vector<uint8_t> currentIv(block.get(tlv::InitializationVector).value(),
                                 block.get(tlv::InitializationVector).value() + 12);
  if (decryptionIv.empty()) {
    decryptionIv = currentIv;
  }
  else {
    if (loadBigU32(currentIv, 8) < loadBigU32(decryptionIv, 8)) {
      NDN_THROW(std::runtime_error("Error when decrypting the AES Encrypted Block: "
                                   "The observed IV is incorrectly formed."));
    }
    else {
      decryptionIv = currentIv;
    }
  }
  auto resultLen = aesGcm128Decrypt(encryptedPayloadBlock.value(), encryptedPayloadBlock.value_size(),
                                    associatedData, associatedDataSize, block.get(tlv::AuthenticationTag).value(),
                                    key, currentIv.data(), result.data());
  if (resultLen != encryptedPayloadBlock.value_size()) {
    NDN_THROW(std::runtime_error("Error when decrypting the AES Encrypted Block: "
                                 "Decrypted payload is of an unexpected size"));
  }
  updateIv(decryptionIv, resultLen);
  return result;
}

} // namespace ndncert
} // namespace ndn
