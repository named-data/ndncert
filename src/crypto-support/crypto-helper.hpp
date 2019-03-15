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

#ifndef NDNCERT_CRYPTO_SUPPORT_CRYPTO_HELPER_HPP
#define NDNCERT_CRYPTO_SUPPORT_CRYPTO_HELPER_HPP

#include "certificate-request.hpp"
#include <openssl/evp.h>
#include <openssl/ec.h>

static const int INFO_LEN = 10;
static const uint8_t INFO[] = {0xf0,0xf1,0xf2,0xf3,0xf4,0xf5,0xf6,0xf7,0xf8,0xf9};

namespace ndn {
namespace ndncert {

struct ECDH_CTX{
  int EC_NID;
  EVP_PKEY_CTX *ctx_params;
  EVP_PKEY_CTX *ctx_keygen;
  EVP_PKEY *privkey;
  EVP_PKEY *peerkey;
  EVP_PKEY *params;
  uint8_t publicKey[256];
  int publicKeyLen;
  uint8_t sharedSecret[256];
  int sharedSecretLen;
};

class ECDHState
{
public:
  ECDHState();
  ~ECDHState();

  std::string
  getBase64PubKey();

  uint8_t*
  deriveSecret(const std::string& peerKeyStr);
  //unique_ptr<ECDH_CTX_T> context;
  unique_ptr<ECDH_CTX> context;

PUBLIC_WITH_TESTS_ELSE_PRIVATE:
  uint8_t*
  deriveSecret(const uint8_t* peerkey, int peerKeySize);

  uint8_t*
  getRawSelfPubKey();
};

int
hkdf(const uint8_t* secret, int secretLen, const uint8_t* salt,
     int saltLen, uint8_t* okm, int okm_len,
     const uint8_t* info=INFO, int info_len=INFO_LEN);

int ndn_compute_hmac_sha256 (const uint8_t *data, const unsigned  data_length,
                                    const uint8_t *key, const unsigned key_length,
                                    uint8_t *prk);

void
handleErrors(const std::string& errorInfo);

class CryptoError : public std::runtime_error
{
public:
  using std::runtime_error::runtime_error;
};

} // namespace ndncert
} // namespace ndn

#endif // NDNCERT_CRYPTO_SUPPORT_CRYPTO_HELPER_HPP
