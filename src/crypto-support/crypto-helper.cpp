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

#include "crypto-helper.hpp"
#include <openssl/err.h>
#include <openssl/hmac.h>
#include <openssl/pem.h>
#include <ndn-cxx/encoding/buffer-stream.hpp>
#include <ndn-cxx/security/transform/base64-decode.hpp>
#include <ndn-cxx/security/transform/base64-encode.hpp>
#include <ndn-cxx/security/transform/buffer-source.hpp>
#include <ndn-cxx/security/transform/private-key.hpp>
#include <ndn-cxx/security/transform/signer-filter.hpp>
#include <ndn-cxx/security/transform/step-source.hpp>
#include <ndn-cxx/security/transform/stream-sink.hpp>

namespace ndn {
namespace ndncert {

const size_t HASH_SIZE = 32;

_LOG_INIT(crypto-support);

ECDHState::ECDHState()
{
  OpenSSL_add_all_algorithms();
  context = std::make_unique<ECDH_CTX>();
  context->EC_NID = NID_X9_62_prime256v1;

  // Create the context for parameter generation
  if (nullptr == (context->ctx_params = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr))) {
    handleErrors("Could not create context contexts.");
    return;
  }

  // Initialise the parameter generation
  if (EVP_PKEY_paramgen_init(context->ctx_params) != 1) {
    handleErrors("Could not initialize parameter generation.");
    return;
  }

  // We're going to use the ANSI X9.62 Prime 256v1 curve
  if (1 != EVP_PKEY_CTX_set_ec_paramgen_curve_nid(context->ctx_params, context->EC_NID)) {
    handleErrors("Likely unknown elliptical curve ID specified.");
    return;
  }

  // Create the parameter object params
  if (!EVP_PKEY_paramgen(context->ctx_params, &context->params)) {
    // the generated key is written to context->params
    handleErrors("Could not create parameter object parameters.");
    return;
  }

  // Create the context for the key generation
  if (nullptr == (context->ctx_keygen = EVP_PKEY_CTX_new(context->params, nullptr))) {
    //The EVP_PKEY_CTX_new() function allocates public key algorithm context using
    //the algorithm specified in pkey and ENGINE e (in this case nullptr).
    handleErrors("Could not create the context for the key generation");
    return;
  }

  // initializes a public key algorithm context
  if (1 != EVP_PKEY_keygen_init(context->ctx_keygen)) {
    handleErrors("Could not init context for key generation.");
    return;
  }
  if (1 != EVP_PKEY_keygen(context->ctx_keygen, &context->privkey)) {
    //performs a key generation operation, the generated key is written to context->privkey.
    handleErrors("Could not generate DHE keys in final step");
    return;
  }
}

ECDHState::~ECDHState()
{
  // Contexts
  if (context->ctx_params != nullptr) {
    EVP_PKEY_CTX_free(context->ctx_params);
  }
  if (context->ctx_keygen != nullptr) {
    EVP_PKEY_CTX_free(context->ctx_keygen);
  }

  // Keys
  if (context->privkey != nullptr) {
    EVP_PKEY_free(context->privkey);
  }
  if (context->peerkey != nullptr) {
    EVP_PKEY_free(context->peerkey);
  }
  if (context->params != nullptr) {
    EVP_PKEY_free(context->params);
  }
}

uint8_t*
ECDHState::getRawSelfPubKey()
{
  auto privECKey = EVP_PKEY_get1_EC_KEY(context->privkey);

  if (privECKey == nullptr) {
    handleErrors("Could not get referenced key when calling EVP_PKEY_get1_EC_KEY().");
    return nullptr;
  }

  auto ecPoint = EC_KEY_get0_public_key(privECKey);
  const EC_GROUP* group = EC_KEY_get0_group(privECKey);
  context->publicKeyLen = EC_POINT_point2oct(group, ecPoint, POINT_CONVERSION_COMPRESSED,
                                             context->publicKey, 256, nullptr);
  EC_KEY_free(privECKey);
  if (context->publicKeyLen == 0) {
    handleErrors("Could not convert EC_POINTS to octet string when calling EC_POINT_point2oct.");
    return nullptr;
  }

  return context->publicKey;
}

std::string
ECDHState::getBase64PubKey()
{
  namespace t = ndn::security::transform;

  if (context->publicKeyLen == 0) {
    this->getRawSelfPubKey();
  }

  std::ostringstream os;
  t::bufferSource(context->publicKey, context->publicKeyLen) >> t::base64Encode(false) >> t::streamSink(os);
  return os.str();
}

uint8_t*
ECDHState::deriveSecret(const uint8_t* peerkey, int peerKeySize)
{
  auto privECKey = EVP_PKEY_get1_EC_KEY(context->privkey);

  if (privECKey == nullptr) {
    handleErrors("Could not get referenced key when calling EVP_PKEY_get1_EC_KEY()");
    return nullptr;
  }

  auto group = EC_KEY_get0_group(privECKey);
  auto peerPoint = EC_POINT_new(group);
  int result = EC_POINT_oct2point(group, peerPoint, peerkey, peerKeySize, nullptr);
  if (result == 0) {
    EC_POINT_free(peerPoint);
    EC_KEY_free(privECKey);
    handleErrors("Cannot convert peer's key into a EC point when calling EC_POINT_oct2point()");
  }

  if (-1 == (context->sharedSecretLen = ECDH_compute_key(context->sharedSecret, 256,
                                                         peerPoint, privECKey, nullptr))) {
    EC_POINT_free(peerPoint);
    EC_KEY_free(privECKey);
    handleErrors("Cannot generate ECDH secret when calling ECDH_compute_key()");
  }
  EC_POINT_free(peerPoint);
  EC_KEY_free(privECKey);
  return context->sharedSecret;
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

int
ndn_compute_hmac_sha256(const uint8_t* data, const unsigned data_length,
                        const uint8_t* key, const unsigned key_length,
                        uint8_t* result)
{
  HMAC(EVP_sha256(), key, key_length,
       (unsigned char*)data, data_length,
       (unsigned char*)result, nullptr);
  return 0;
}

// avoid dependency on OpenSSL >= 1.1
int
hkdf(const uint8_t* secret, int secretLen, const uint8_t* salt,
     int saltLen, uint8_t* okm, int okm_len,
     const uint8_t* info, int info_len)
{
  namespace t = ndn::security::transform;

  // hkdf generate prk
  uint8_t prk[HASH_SIZE];
  if (saltLen == 0) {
    uint8_t realSalt[HASH_SIZE] = {0};
    ndn_compute_hmac_sha256(secret, secretLen, realSalt, HASH_SIZE, prk);
  }
  else {
    ndn_compute_hmac_sha256(secret, secretLen, salt, saltLen, prk);
  }

  // hkdf expand
  uint8_t prev[HASH_SIZE] = {0};
  int done_len = 0, dig_len = HASH_SIZE, n = okm_len / dig_len;
  if (okm_len % dig_len)
    n++;
  if (n > 255 || okm == nullptr)
    return 0;

  for (int i = 1; i <= n; i++) {
    size_t copy_len;
    const uint8_t ctr = i;

    t::StepSource source;
    t::PrivateKey privKey;
    privKey.loadRaw(KeyType::HMAC, prk, dig_len);
    OBufferStream os;
    source >> t::signerFilter(DigestAlgorithm::SHA256, privKey) >> t::streamSink(os);

    if (i > 1) {
      source.write(prev, dig_len);
    }
    source.write(info, info_len);
    source.write(&ctr, 1);
    source.end();

    auto result = os.buf();
    memcpy(prev, result->data(), dig_len);
    copy_len = (done_len + dig_len > okm_len) ? okm_len - done_len : dig_len;
    memcpy(okm + done_len, prev, copy_len);
    done_len += copy_len;
  }
  return done_len;
}

int
aes_gcm_128_encrypt(const uint8_t* plaintext, size_t plaintext_len, const uint8_t* associated, size_t associated_len,
                    const uint8_t* key, const uint8_t* iv, uint8_t* ciphertext, uint8_t* tag)
{
  EVP_CIPHER_CTX* ctx;
  int len;
  int ciphertext_len;

  // Create and initialise the context
  if (!(ctx = EVP_CIPHER_CTX_new())) {
    handleErrors("Cannot create and initialise the context when calling EVP_CIPHER_CTX_new()");
  }

  // Initialise the encryption operation.
  if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), nullptr, nullptr, nullptr)) {
    handleErrors("Cannot initialise the encryption operation when calling EVP_EncryptInit_ex()");
  }

  // Set IV length if default 12 bytes (96 bits) is not appropriate
  if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr)) {
    handleErrors("Cannot set IV length when calling EVP_CIPHER_CTX_ctrl()");
  }

  // Initialise key and IV
  if (1 != EVP_EncryptInit_ex(ctx, nullptr, nullptr, key, iv)) {
    handleErrors("Cannot initialize key and IV when calling EVP_EncryptInit_ex()");
  }

  // Provide any AAD data. This can be called zero or more times as required
  if (1 != EVP_EncryptUpdate(ctx, nullptr, &len, associated, associated_len)) {
    handleErrors("Cannot set associated authentication data when calling EVP_EncryptUpdate()");
  }

  // Provide the message to be encrypted, and obtain the encrypted output.
  // EVP_EncryptUpdate can be called multiple times if necessary
  if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len)) {
    handleErrors("Cannot encrypt when calling EVP_EncryptUpdate()");
  }
  ciphertext_len = len;

  // Finalise the encryption. Normally ciphertext bytes may be written at
  // this stage, but this does not occur in GCM mode
  if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) {
    handleErrors("Cannot finalise the encryption when calling EVP_EncryptFinal_ex()");
  }
  ciphertext_len += len;

  // Get the tag
  if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag)) {
    handleErrors("Cannot get tag when calling EVP_CIPHER_CTX_ctrl()");
  }

  // Clean up
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

  // Create and initialise the context
  if (!(ctx = EVP_CIPHER_CTX_new())) {
    handleErrors("Cannot create and initialise the context when calling EVP_CIPHER_CTX_new()");
  }

  // Initialise the decryption operation.
  if (!EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), nullptr, nullptr, nullptr)) {
    handleErrors("Cannot initialise the decryption operation when calling EVP_DecryptInit_ex()");
  }

  // Set IV length. Not necessary if this is 12 bytes (96 bits)
  if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr)) {
    handleErrors("Cannot set IV length when calling EVP_CIPHER_CTX_ctrl");
  }

  // Initialise key and IV
  if (!EVP_DecryptInit_ex(ctx, nullptr, nullptr, key, iv)) {
    handleErrors("Cannot initialise key and IV when calling EVP_DecryptInit_ex()");
  }

  // Provide any AAD data. This can be called zero or more times as required
  if (!EVP_DecryptUpdate(ctx, nullptr, &len, associated, associated_len)) {
    handleErrors("Cannot set associated authentication data when calling EVP_EncryptUpdate()");
  }

  // Provide the message to be decrypted, and obtain the plaintext output.
  // EVP_DecryptUpdate can be called multiple times if necessary
  if (!EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)) {
    handleErrors("Cannot decrypt when calling EVP_DecryptUpdate()");
  }
  plaintext_len = len;

  // Set expected tag value. Works in OpenSSL 1.0.1d and later
  if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, (void*)tag)) {
    handleErrors("Cannot set tag value when calling EVP_CIPHER_CTX_ctrl");
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

void
handleErrors(const std::string& errorInfo)
{
  _LOG_DEBUG("Error in CRYPTO SUPPORT " << errorInfo);
  BOOST_THROW_EXCEPTION(CryptoError("Error in CRYPTO SUPPORT: " + errorInfo));
}

}  // namespace ndncert
}  // namespace ndn
