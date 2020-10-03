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

#ifndef NDNCERT_CLIENT_MODULE_HPP
#define NDNCERT_CLIENT_MODULE_HPP

#include "configuration.hpp"
#include "request-state.hpp"
#include "crypto-support/crypto-helper.hpp"

namespace ndn {
namespace ndncert {

// TODO
// For each RequesterState, create a validator instance and initialize it with CA's cert
// The validator instance should be in CaProfile

struct RequesterState {
  explicit
  RequesterState(security::v2::KeyChain& keyChain, const CaProfile& caItem, RequestType requestType);

  CaProfile m_caItem;
  security::v2::KeyChain& m_keyChain;
  RequestType m_type;

  Name m_identityName;
  security::Key m_keyPair;
  std::string m_requestId;
  Status m_status = Status::NOT_STARTED;
  std::string m_challengeType;
  std::string m_challengeStatus;
  int m_remainingTries = 0;
  time::system_clock::TimePoint m_freshBefore;
  Name m_issuedCertName;

  ECDHState m_ecdh;
  uint8_t m_aesKey[16] = {0};

  bool m_isCertInstalled = false;
  bool m_isNewlyCreatedIdentity = false;
  bool m_isNewlyCreatedKey = false;
};

class Requester : noncopyable
{
public:
  // INFO related helpers
  static shared_ptr<Interest>
  genCaProfileInterest(const Name& caName);

  /**
   * Will first verify the signature of the packet using the key provided inside the profile.
   * The application should be cautious whether to add CaProfile into the RequesterCaCache.
   */
  static boost::optional<CaProfile>
  onCaProfileResponse(const Data& reply);

  // PROBE related helpers
  static shared_ptr<Interest>
  genProbeInterest(const CaProfile& ca, std::vector<std::tuple<std::string, std::string>>&& probeInfo);

  static void
  onProbeResponse(const Data& reply, const CaProfile& ca,
                  std::vector<Name>& identityNames, std::vector<Name>& otherCas);

  // NEW/REVOKE/RENEW related helpers
  static shared_ptr<Interest>
  genNewInterest(RequesterState& state, const Name& identityName,
                      const time::system_clock::TimePoint& notBefore,
                      const time::system_clock::TimePoint& notAfter);

  static shared_ptr<Interest>
  genRevokeInterest(RequesterState& state, const security::v2::Certificate& certificate);

  static std::list<std::string>
  onNewRenewRevokeResponse(RequesterState& state, const Data& reply);

  // CHALLENGE helpers
  static std::vector<std::tuple<std::string, std::string>>
  selectOrContinueChallenge(RequesterState& state, const std::string& challengeSelected);

  static shared_ptr<Interest>
  genChallengeInterest(const RequesterState& state,
                       std::vector<std::tuple<std::string, std::string>>&& parameters);

  static void
  onChallengeResponse(RequesterState& state, const Data& reply);

  static shared_ptr<Interest>
  genCertFetchInterest(const RequesterState& state);

  static shared_ptr<security::v2::Certificate>
  onCertFetchResponse(const Data& reply);

  static void
  endSession(RequesterState& state);

private:
  static void
  processIfError(const Data& data);
};

} // namespace ndncert
} // namespace ndn

#endif // NDNCERT_CLIENT_MODULE_HPP
