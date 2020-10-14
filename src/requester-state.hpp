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

#ifndef NDNCERT_REQUESTER_STATE_HPP
#define NDNCERT_REQUESTER_STATE_HPP

#include "protocol-detail/ndncert-common.hpp"
#include "protocol-detail/crypto-helper.hpp"
#include "configuration.hpp"

namespace ndn {
namespace ndncert {

struct RequesterState {
  explicit
  RequesterState(security::KeyChain& keyChain, const CaProfile& caItem, RequestType requestType);

  /**
   * The CA profile for this request.
   */
  CaProfile m_caItem;
  /**
   * The local keychain to generate and install identities, keys and certificates
   */
  security::KeyChain& m_keyChain;
  /**
   * The type of request. Either NEW, RENEW, or REVOKE.
   */
  RequestType m_type;

  /**
   * The identity name for the requesting certificate.
   */
  Name m_identityName;
  /**
   * The keypair for the request.
   */
  security::Key m_keyPair;
  /**
   * The CA-generated request ID for the request.
   */
  std::string m_requestId;
  /**
   * The current status of the request.
   */
  Status m_status = Status::NOT_STARTED;

  /**
   * The type of challenge chosen.
   */
  std::string m_challengeType;
  /**
   * The status of the current challenge.
   */
  std::string m_challengeStatus;
  /**
   * The remaining number of tries left for the challenge
   */
  int m_remainingTries = 0;
  /**
   * The time this challenge will remain fresh
   */
  time::system_clock::TimePoint m_freshBefore;
  /**
   * the name of the certificate being issued.
   */
  Name m_issuedCertName;
  /**
   * ecdh state.
   */
  ECDHState m_ecdh;
  /**
   * AES key derived from the ecdh shared secret.
   */
  uint8_t m_aesKey[16] = {0};
  /**
   * State about how identity/key is generated.
   */
  bool m_isNewlyCreatedIdentity = false;
  bool m_isNewlyCreatedKey = false;
};

} // namespace ndncert
} // namespace ndn

#endif // NDNCERT_REQUESTER_STATE_HPP
