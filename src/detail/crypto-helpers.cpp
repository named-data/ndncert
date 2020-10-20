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

#include "crypto-helpers.hpp"

#include <boost/endian/conversion.hpp>
#include <cmath>
#include <ndn-cxx/encoding/buffer-stream.hpp>
#include <ndn-cxx/security/transform/base64-decode.hpp>
#include <ndn-cxx/security/transform/base64-encode.hpp>
#include <ndn-cxx/security/transform/buffer-source.hpp>
#include <ndn-cxx/security/transform/stream-sink.hpp>
#include <ndn-cxx/util/random.hpp>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/kdf.h>
#include <openssl/pem.h>

namespace ndn {
namespace ndncert {

struct ECDHState::ECDH_CTX
{
  ~ECDH_CTX()
  {
    // Contexts
    if (ctx_params != nullptr) {
      EVP_PKEY_CTX_free(ctx_params);
    }
    if (ctx_keygen != nullptr) {
      EVP_PKEY_CTX_free(ctx_keygen);
    }
    // Keys
    if (privkey != nullptr) {
      EVP_PKEY_free(privkey);
    }
    if (peerkey != nullptr) {
      EVP_PKEY_free(peerkey);
    }
    if (params != nullptr) {
      EVP_PKEY_free(params);
    }
  }
  EVP_PKEY_CTX* ctx_params = nullptr;
  EVP_PKEY_CTX* ctx_keygen = nullptr;
  EVP_PKEY* privkey = nullptr;
  EVP_PKEY* peerkey = nullptr;
  EVP_PKEY* params = nullptr;
};

ECDHState::ECDHState()
{
  context = std::make_unique<ECDH_CTX>();
  auto EC_NID = NID_X9_62_prime256v1;

  if (nullptr == (context->ctx_params = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr))) {
    NDN_THROW(std::runtime_error("Could not create context."));
  }
  if (EVP_PKEY_paramgen_init(context->ctx_params) != 1) {
    context.reset();
    NDN_THROW(std::runtime_error("Could not initialize parameter generation."));
  }
  if (1 != EVP_PKEY_CTX_set_ec_paramgen_curve_nid(context->ctx_params, EC_NID)) {
    context.reset();
    NDN_THROW(std::runtime_error("Likely unknown elliptical curve ID specified."));
  }
  if (!EVP_PKEY_paramgen(context->ctx_params, &context->params)) {
    context.reset();
    NDN_THROW(std::runtime_error("Could not create parameter object parameters."));
  }
  if (nullptr == (context->ctx_keygen = EVP_PKEY_CTX_new(context->params, nullptr))) {
    context.reset();
    NDN_THROW(std::runtime_error("Could not create the context for the key generation"));
  }
  if (1 != EVP_PKEY_keygen_init(context->ctx_keygen)) {
    context.reset();
    NDN_THROW(std::runtime_error("Could not init context for key generation."));
  }
  if (1 != EVP_PKEY_keygen(context->ctx_keygen, &context->privkey)) {
    context.reset();
    NDN_THROW(std::runtime_error("Could not generate DHE keys in final step"));
  }
}

ECDHState::~ECDHState()
{}

uint8_t*
ECDHState::getRawSelfPubKey()
{
  auto privECKey = EVP_PKEY_get1_EC_KEY(context->privkey);
  if (privECKey == nullptr) {
    context.reset();
    NDN_THROW(std::runtime_error("Could not get key when calling EVP_PKEY_get1_EC_KEY()."));
  }
  auto ecPoint = EC_KEY_get0_public_key(privECKey);
  const EC_GROUP* group = EC_KEY_get0_group(privECKey);
  m_publicKeyLen = EC_POINT_point2oct(group, ecPoint, POINT_CONVERSION_COMPRESSED,
                                      m_publicKey, 256, nullptr);
  EC_KEY_free(privECKey);
  if (m_publicKeyLen == 0) {
    context.reset();
    NDN_THROW(std::runtime_error("Could not convert EC_POINTS to octet string when calling EC_POINT_point2oct."));
  }
  return m_publicKey;
}

std::string
ECDHState::getBase64PubKey()
{
  if (m_publicKeyLen == 0) {
    this->getRawSelfPubKey();
  }
  std::ostringstream os;
  namespace t = ndn::security::transform;
  t::bufferSource(m_publicKey, m_publicKeyLen) >> t::base64Encode(false) >> t::streamSink(os);
  return os.str();
}

uint8_t*
ECDHState::deriveSecret(const uint8_t* peerkey, size_t peerKeySize)
{
  auto privECKey = EVP_PKEY_get1_EC_KEY(context->privkey);
  if (privECKey == nullptr) {
    context.reset();
    NDN_THROW(std::runtime_error("Could not get key when calling EVP_PKEY_get1_EC_KEY()"));
  }
  auto group = EC_KEY_get0_group(privECKey);
  auto peerPoint = EC_POINT_new(group);
  int result = EC_POINT_oct2point(group, peerPoint, peerkey, peerKeySize, nullptr);
  if (result == 0) {
    EC_POINT_free(peerPoint);
    EC_KEY_free(privECKey);
    context.reset();
    NDN_THROW(std::runtime_error("Cannot convert peer's key into a EC point when calling EC_POINT_oct2point()"));
  }
  result = ECDH_compute_key(m_sharedSecret, 256, peerPoint, privECKey, nullptr);
  if (result == -1) {
    EC_POINT_free(peerPoint);
    EC_KEY_free(privECKey);
    context.reset();
    NDN_THROW(std::runtime_error("Cannot generate ECDH secret when calling ECDH_compute_key()"));
  }
  m_sharedSecretLen = static_cast<size_t>(result);
  EC_POINT_free(peerPoint);
  EC_KEY_free(privECKey);
  return m_sharedSecret;
}

uint8_t*
ECDHState::deriveSecret(const std::string& peerKeyStr)
{
  namespace t = ndn::security::transform;
  OBufferStream os;
  t::bufferSource(peerKeyStr) >> t::base64Decode(false) >> t::streamSink(os);
  auto result = os.buf();
  return this->deriveSecret(result->data(), result->size());
}

void
hmac_sha256(const uint8_t* data, size_t data_length,
            const uint8_t* key, size_t key_length,
            uint8_t* result)
{
  auto ret = HMAC(EVP_sha256(), key, key_length, (unsigned char*)data, data_length,
                  (unsigned char*)result, nullptr);
  if (ret == nullptr) {
    NDN_THROW(std::runtime_error("Error computing HMAC when calling HMAC()"));
  }
}

int
hkdf(const uint8_t* secret, size_t secret_len, const uint8_t* salt,
     size_t salt_len, uint8_t* output, size_t output_len,
     const uint8_t* info, size_t info_len)
{
  EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
  if (EVP_PKEY_derive_init(pctx) <= 0) {
    EVP_PKEY_CTX_free(pctx);
    NDN_THROW(std::runtime_error("HKDF: Cannot init ctx when calling EVP_PKEY_derive_init()."));
  }
  if (EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256()) <= 0) {
    EVP_PKEY_CTX_free(pctx);
    NDN_THROW(std::runtime_error("HKDF: Cannot set md when calling EVP_PKEY_CTX_set_hkdf_md()."));
  }
  if (EVP_PKEY_CTX_set1_hkdf_salt(pctx, salt, salt_len) <= 0) {
    EVP_PKEY_CTX_free(pctx);
    NDN_THROW(std::runtime_error("HKDF: Cannot set salt when calling EVP_PKEY_CTX_set1_hkdf_salt()."));
  }
  if (EVP_PKEY_CTX_set1_hkdf_key(pctx, secret, secret_len) <= 0) {
    EVP_PKEY_CTX_free(pctx);
    NDN_THROW(std::runtime_error("HKDF: Cannot set secret when calling EVP_PKEY_CTX_set1_hkdf_key()."));
  }
  if (EVP_PKEY_CTX_add1_hkdf_info(pctx, info, info_len) <= 0) {
    EVP_PKEY_CTX_free(pctx);
    NDN_THROW(std::runtime_error("HKDF: Cannot set info when calling EVP_PKEY_CTX_add1_hkdf_info()."));
  }
  size_t outLen = output_len;
  if (EVP_PKEY_derive(pctx, output, &outLen) <= 0) {
    EVP_PKEY_CTX_free(pctx);
    NDN_THROW(std::runtime_error("HKDF: Cannot derive result when calling EVP_PKEY_derive()."));
  }
  EVP_PKEY_CTX_free(pctx);
  return (int)outLen;
}

int
aes_gcm_128_encrypt(const uint8_t* plaintext, size_t plaintext_len, const uint8_t* associated, size_t associated_len,
                    const uint8_t* key, const uint8_t* iv, uint8_t* ciphertext, uint8_t* tag)
{
  EVP_CIPHER_CTX* ctx;
  int len;
  int ciphertext_len;
  if (!(ctx = EVP_CIPHER_CTX_new())) {
    NDN_THROW(std::runtime_error("Cannot create and initialise the context when calling EVP_CIPHER_CTX_new()"));
  }
  if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), nullptr, nullptr, nullptr)) {
    EVP_CIPHER_CTX_free(ctx);
    NDN_THROW(std::runtime_error("Cannot initialise the encryption operation when calling EVP_EncryptInit_ex()"));
  }
  if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr)) {
    EVP_CIPHER_CTX_free(ctx);
    NDN_THROW(std::runtime_error("Cannot set IV length when calling EVP_CIPHER_CTX_ctrl()"));
  }
  if (1 != EVP_EncryptInit_ex(ctx, nullptr, nullptr, key, iv)) {
    EVP_CIPHER_CTX_free(ctx);
    NDN_THROW(std::runtime_error("Cannot initialize key and IV when calling EVP_EncryptInit_ex()"));
  }
  if (1 != EVP_EncryptUpdate(ctx, nullptr, &len, associated, associated_len)) {
    EVP_CIPHER_CTX_free(ctx);
    NDN_THROW(std::runtime_error("Cannot set associated authentication data when calling EVP_EncryptUpdate()"));
  }
  if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len)) {
    EVP_CIPHER_CTX_free(ctx);
    NDN_THROW(std::runtime_error("Cannot encrypt when calling EVP_EncryptUpdate()"));
  }
  ciphertext_len = len;
  if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) {
    EVP_CIPHER_CTX_free(ctx);
    NDN_THROW(std::runtime_error("Cannot finalise the encryption when calling EVP_EncryptFinal_ex()"));
  }
  ciphertext_len += len;
  if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag)) {
    EVP_CIPHER_CTX_free(ctx);
    NDN_THROW(std::runtime_error("Cannot get tag when calling EVP_CIPHER_CTX_ctrl()"));
  }
  EVP_CIPHER_CTX_free(ctx);
  return ciphertext_len;
}

int
aes_gcm_128_decrypt(const uint8_t* ciphertext, size_t ciphertext_len, const uint8_t* associated, size_t associated_len,
                    const uint8_t* tag, const uint8_t* key, const uint8_t* iv, uint8_t* plaintext)
{
  EVP_CIPHER_CTX* ctx;
  int len;
  int plaintext_len;
  int ret;
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
  if (!EVP_DecryptUpdate(ctx, nullptr, &len, associated, associated_len)) {
    EVP_CIPHER_CTX_free(ctx);
    NDN_THROW(std::runtime_error("Cannot set associated authentication data when calling EVP_EncryptUpdate()"));
  }
  if (!EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)) {
    EVP_CIPHER_CTX_free(ctx);
    NDN_THROW(std::runtime_error("Cannot decrypt when calling EVP_DecryptUpdate()"));
  }
  plaintext_len = len;
  if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, (void*)tag)) {
    EVP_CIPHER_CTX_free(ctx);
    NDN_THROW(std::runtime_error("Cannot set tag value when calling EVP_CIPHER_CTX_ctrl"));
  }
  // Finalise the decryption. A positive return value indicates success,
  // anything else is a failure - the plaintext is not trustworthy.
  ret = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);
  // Clean up
  EVP_CIPHER_CTX_free(ctx);
  if (ret > 0) {
    // Success
    plaintext_len += len;
    return plaintext_len;
  }
  else {
    // Verify failed
    return -1;
  }
}

Block
encodeBlockWithAesGcm128(uint32_t tlv_type, const uint8_t* key, const uint8_t* payload, size_t payloadSize,
                         const uint8_t* associatedData, size_t associatedDataSize, uint32_t& counter)
{
  Buffer iv(12);
  random::generateSecureBytes(iv.data(), iv.size());
  if (tlv_type == ndn::tlv::ApplicationParameters) {
    // requester
    iv[0] &= ~(1UL << 7);
  }
  else {
    // CA
    iv[0] |= 1UL << 7;
  }
  uint32_t temp = counter;
  boost::endian::native_to_big_inplace(temp);
  std::memcpy(&iv[8], reinterpret_cast<const uint8_t*>(&temp), 4);
  counter += std::ceil(payloadSize / 8);

  Buffer encryptedPayload(payloadSize);
  uint8_t tag[16];
  size_t encryptedPayloadLen = aes_gcm_128_encrypt(payload, payloadSize, associatedData, associatedDataSize,
                                                   key, iv.data(), encryptedPayload.data(), tag);
  auto content = makeEmptyBlock(tlv_type);
  content.push_back(makeBinaryBlock(tlv::InitializationVector, iv.data(), iv.size()));
  content.push_back(makeBinaryBlock(tlv::AuthenticationTag, tag, 16));
  content.push_back(makeBinaryBlock(tlv::EncryptedPayload, encryptedPayload.data(), encryptedPayloadLen));
  content.encode();
  return content;
}

Buffer
decodeBlockWithAesGcm128(const Block& block, const uint8_t* key, const uint8_t* associatedData, size_t associatedDataSize)
{
  block.parse();
  Buffer result(block.get(tlv::EncryptedPayload).value_size());
  int resultLen = aes_gcm_128_decrypt(block.get(tlv::EncryptedPayload).value(),
                                      block.get(tlv::EncryptedPayload).value_size(),
                                      associatedData, associatedDataSize, block.get(tlv::AuthenticationTag).value(),
                                      key, block.get(tlv::InitializationVector).value(), result.data());
  if (resultLen == -1 || resultLen != (int)block.get(tlv::EncryptedPayload).value_size()) {
    return Buffer();
  }
  return result;
}

} // namespace ndncert
} // namespace ndn
