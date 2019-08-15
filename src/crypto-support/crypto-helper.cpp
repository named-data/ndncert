/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
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

#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/hmac.h>

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
  if (1 != EVP_PKEY_keygen_init(context->ctx_keygen)){
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
  t::bufferSource(context->publicKey, context->publicKeyLen)
    >> t::base64Encode()
    >> t::streamSink(os);
  return os.str();
}

uint8_t*
ECDHState::deriveSecret(const uint8_t* peerkey, int peerKeySize)
{
  auto privECKey = EVP_PKEY_get1_EC_KEY(context->privkey);

  if (privECKey == nullptr) {
    handleErrors("Could not get referenced key when calling EVP_PKEY_get1_EC_KEY().");
    return nullptr;
  }

  auto group = EC_KEY_get0_group(privECKey);
  auto peerPoint = EC_POINT_new(group);
  EC_POINT_oct2point(group, peerPoint, peerkey, peerKeySize, nullptr);

  if (0 == (context->sharedSecretLen = ECDH_compute_key(context->sharedSecret, 256,
                                                        peerPoint, privECKey, nullptr))) {
    EC_POINT_free(peerPoint);
    EC_KEY_free(privECKey);
    handleErrors("Cannot generate ECDH secret with ECDH_compute_key");
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
  t::bufferSource(peerKeyStr) >> t::base64Decode() >> t::streamSink(os);
  auto result = os.buf();

  return this->deriveSecret(result->data(), result->size());
}

int
ndn_compute_hmac_sha256(const uint8_t *data, const unsigned data_length,
                        const uint8_t *key, const unsigned key_length,
                        uint8_t *prk)
{
  HMAC(EVP_sha256(), key, key_length,
       (unsigned char*)data, data_length,
       (unsigned char*)prk, nullptr);
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
    source >> t::signerFilter(DigestAlgorithm::SHA256, privKey)
           >> t::streamSink(os);

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

void
handleErrors(const std::string& errorInfo)
{
  _LOG_DEBUG("Error in CRYPTO SUPPORT " << errorInfo);
  BOOST_THROW_EXCEPTION(CryptoError("Error in CRYPTO SUPPORT: " + errorInfo));
}

} // namespace ndncert
} // namespace ndn
