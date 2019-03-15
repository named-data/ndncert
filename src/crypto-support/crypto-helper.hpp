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

namespace ndn {
namespace ndncert {

typedef struct ECDH_CTX{
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
} ECDH_CTX_T;

class ECDHState
{
public:
  ECDHState();
  ~ECDHState();

  std::string
  getBase64PubKey();

  uint8_t*
  deriveSecret(const std::string& peerKeyStr);

  ECDH_CTX_T* context;

PUBLIC_WITH_TESTS_ELSE_PRIVATE:
  uint8_t*
  deriveSecret(const uint8_t* peerkey, int peerKeySize);

  uint8_t*
  getRawSelfPubKey();
};

int
hkdf(const uint8_t* secret, int secretLen, const uint8_t* salt,
     int saltLen, uint8_t* result, int resultMaxLen);

Buffer
aes_cbc_decrypt(const uint8_t* key, size_t keyLen,
                const uint8_t* payload, size_t payloadLen,
                const uint8_t* iv, size_t ivLen);

Buffer
aes_cbc_encrypt(const uint8_t* key, size_t keyLen,
                const uint8_t* payload, size_t payloadLen,
                const uint8_t* iv, size_t ivLen);

Buffer
aes_generateIV(int ivLength = 16);

void
handleErrors(const std::string& errorInfo);

} // namespace ndncert
} // namespace ndn

#endif // NDNCERT_CRYPTO_SUPPORT_CRYPTO_HELPER_HPP
