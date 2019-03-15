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

#include "crypto-helper.hpp"
#include "../logging.hpp"
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/kdf.h>
#include <ndn-cxx/security/transform/block-cipher.hpp>
#include <ndn-cxx/security/transform/base64-decode.hpp>
#include <ndn-cxx/security/transform/base64-encode.hpp>
#include <ndn-cxx/security/transform/buffer-source.hpp>
#include <ndn-cxx/security/transform/step-source.hpp>
#include <ndn-cxx/security/transform/stream-sink.hpp>
#include <ndn-cxx/util/random.hpp>
#include <ndn-cxx/encoding/buffer-stream.hpp>

namespace ndn {
namespace ndncert {

_LOG_INIT(crypto-support);

ECDHState::ECDHState()
{
  OpenSSL_add_all_algorithms();
  context = (ECDH_CTX_T*)calloc(1, sizeof(ECDH_CTX_T));
  context->EC_NID = NID_X9_62_prime256v1;

  // Create the context for parameter generation
  if (nullptr == (context->ctx_params = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr))) {
    handleErrors("Could not create context contexts.");
    return;
  }

  // Initialise the parameter generation
  if(1 != EVP_PKEY_paramgen_init(context->ctx_params)) {
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
    handleErrors("Could not create parameter object parameters.");
    return;
  }

  // Create the context for the key generation
  if (nullptr == (context->ctx_keygen = EVP_PKEY_CTX_new(context->params, nullptr))) {
    handleErrors("Could not create the context for the key generation");
    return;
  }

  // Generate the key
  if (1 != EVP_PKEY_keygen_init(context->ctx_keygen)){
    handleErrors("Could not init context for key generation.");
    return;
  }
  if (1 != EVP_PKEY_keygen(context->ctx_keygen, &context->privkey)) {
    handleErrors("Could not generate DHE keys in final step");
    return;
  }
}

ECDHState::~ECDHState()
{
  // Contexts
  if(context->ctx_params != nullptr){
    EVP_PKEY_CTX_free(context->ctx_params);
  }
  if(context->ctx_keygen != nullptr){
    EVP_PKEY_CTX_free(context->ctx_keygen);
  }

  // Keys
  if(context->privkey != nullptr){
    EVP_PKEY_free(context->privkey);
  }
  if(context->peerkey != nullptr){
    EVP_PKEY_free(context->peerkey);
  }
  if(context->params != nullptr){
    EVP_PKEY_free(context->params);
  }

  // Itself
  free(context);
}

uint8_t*
ECDHState::getRawSelfPubKey()
{
  auto privECKey = EVP_PKEY_get1_EC_KEY(context->privkey);
  auto ecPoint = EC_KEY_get0_public_key(privECKey);
  const EC_GROUP* group = EC_KEY_get0_group(privECKey);
  context->publicKeyLen = EC_POINT_point2oct(group, ecPoint, POINT_CONVERSION_COMPRESSED,
                                             context->publicKey, 256, nullptr);
  return context->publicKey;
}

std::string
ECDHState::getBase64PubKey()
{
  if (context->publicKeyLen == 0) {
    this->getRawSelfPubKey();
  }
  std::stringstream os;
  security::transform::bufferSource(context->publicKey, context->publicKeyLen)
    >> security::transform::base64Encode() >> security::transform::streamSink(os);
  return os.str();
}

uint8_t*
ECDHState::deriveSecret(const uint8_t* peerkey, int peerKeySize)
{
  auto privECKey = EVP_PKEY_get1_EC_KEY(context->privkey);
  auto group = EC_KEY_get0_group(privECKey);
  auto peerPoint = EC_POINT_new(group);
  EC_POINT_oct2point(group, peerPoint, peerkey, peerKeySize, nullptr);

  if (0 == (context->sharedSecretLen = ECDH_compute_key(context->sharedSecret, 256,
                                                        peerPoint, privECKey, nullptr)))
    handleErrors("Cannot generate ECDH secret with ECDH_comput_key");
  return context->sharedSecret;
}

uint8_t*
ECDHState::deriveSecret(const std::string& peerKeyStr)
{
  namespace t = ndn::security::transform;
  OBufferStream os;
  security::transform::bufferSource(peerKeyStr)
    >> security::transform::base64Decode() >> security::transform::streamSink(os);
  ConstBufferPtr result = os.buf();
  return this->deriveSecret(result->data(), result->size());
}

int
hkdf(const uint8_t* secret, int secretLen, const uint8_t* salt,
     int saltLen, uint8_t* result, int resultMaxLen)
{
  EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
  // unsigned char out[32];
  // size_t outlen = sizeof(out);

  if (EVP_PKEY_derive_init(pctx) <= 0) handleErrors("HKDF: Cannot init ctx");
  if (EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256()) <= 0) handleErrors("HKDF: Cannot set md");
  if (EVP_PKEY_CTX_set1_hkdf_salt(pctx, salt, saltLen) <= 0) handleErrors("HKDF: Cannot set salt");
  if (EVP_PKEY_CTX_set1_hkdf_key(pctx, secret, secretLen) <= 0) handleErrors("HKDF: Cannot set secret");
  if (EVP_PKEY_CTX_add1_hkdf_info(pctx, "label", 6) <= 0) handleErrors("HKDF: Cannot set info");
  size_t outLen = resultMaxLen;
  if (EVP_PKEY_derive(pctx, result, &outLen) <= 0) handleErrors("HKDF: Cannot derive result");
  return (int)outLen;
}

Buffer
aes_cbc_decrypt(const uint8_t* key, size_t keyLen,
                const uint8_t* payload, size_t payloadLen,
                const uint8_t* iv, size_t ivLen)
{
  OBufferStream os;
  security::transform::bufferSource(payload, payloadLen)
    >> security::transform::blockCipher(BlockCipherAlgorithm::AES_CBC,
                                        CipherOperator::DECRYPT,
                                        key, keyLen, iv, ivLen)
    >> security::transform::streamSink(os);

  auto result = os.buf();
  return *result;
}

Buffer
aes_cbc_encrypt(const uint8_t* key, size_t keyLen,
                const uint8_t* payload, size_t payloadLen,
                const uint8_t* iv, size_t ivLen)
{
  OBufferStream os;
  security::transform::bufferSource(payload, payloadLen)
    >> security::transform::blockCipher(BlockCipherAlgorithm::AES_CBC,
                                        CipherOperator::ENCRYPT,
                                        key, keyLen, iv, ivLen)
    >> security::transform::streamSink(os);

  auto result = os.buf();
  return *result;
}

Buffer
aes_generateIV(int ivLength)
{
  if (ivLength == 0) {
    handleErrors("IV length cannot be zero");
  }

  Buffer iv;
  iv.resize(ivLength);
  random::generateSecureBytes(iv.data(), iv.size());
  return iv;
}

void
handleErrors(const std::string& errorInfo)
{
  _LOG_DEBUG("Error in CRYPTO SUPPORT " << errorInfo);
  return;
}

} // namespace ndncert
} // namespace ndn
