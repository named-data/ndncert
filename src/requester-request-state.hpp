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

#ifndef NDNCERT_REQUESTER_REQUEST_STATE_HPP
#define NDNCERT_REQUESTER_REQUEST_STATE_HPP

#include "detail/ca-request-state.hpp"
#include "detail/crypto-helpers.hpp"
#include "detail/profile-storage.hpp"

namespace ndn {
namespace ndncert {
namespace requester {

struct RequestState {
  explicit
  RequestState(security::KeyChain& keyChain, const CaProfile& profile, RequestType requestType);

  /**
   * @brief The CA profile for this request.
   */
  CaProfile caProfile;
  /**
   * @brief The local keychain to generate and install identities, keys and certificates
   */
  security::KeyChain& keyChain;
  /**
   * @brief The type of request. Either NEW, RENEW, or REVOKE.
   */
  RequestType type;
  /**
   * @brief The identity name for the requesting certificate.
   */
  Name identityName;
  /**
   * @brief The keypair for the request.
   */
  security::Key keyPair;
  /**
   * @brief The CA-generated request ID for the request.
   */
  RequestId requestId;
  /**
   * @brief The current status of the request.
   */
  Status status = Status::BEFORE_CHALLENGE;
  /**
   * @brief The type of challenge chosen.
   */
  std::string challengeType;
  /**
   * @brief The status of the current challenge.
   */
  std::string challengeStatus;
  /**
   * @brief The remaining number of tries left for the challenge
   */
  int remainingTries = 0;
  /**
   * @brief The time this challenge will remain fresh
   */
  time::system_clock::TimePoint freshBefore;
  /**
   * @brief the name of the certificate being issued.
   */
  Name issuedCertName;
  /**
   * @brief ecdh state.
   */
  ECDHState ecdh;
  /**
   * @brief AES key derived from the ecdh shared secret.
   */
  std::array<uint8_t, 16> aesKey = {};
  /**
   * @brief The counter of AES blocks that have been encrypted.
   */
  uint32_t aesBlockCounter = 0;
  /**
   * @brief State about how identity/key is generated.
   */
  bool isNewlyCreatedIdentity = false;
  bool isNewlyCreatedKey = false;
  /**
   * @brief Store Nonce for signature
   */
  std::array<uint8_t, 16> nonce = {};
};

} // namespace requester
} // namespace ndncert
} // namespace ndn

#endif // NDNCERT_REQUESTER_REQUEST_STATE_HPP
