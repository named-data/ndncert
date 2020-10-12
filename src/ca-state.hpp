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

#ifndef NDNCERT_CA_STATE_HPP
#define NDNCERT_CA_STATE_HPP

#include "ndncert-common.hpp"

namespace ndn {
namespace ndncert {

// NDNCERT Request status enumeration
enum class Status : uint16_t {
  BEFORE_CHALLENGE = 0,
  CHALLENGE = 1,
  PENDING = 2,
  SUCCESS = 3,
  FAILURE = 4,
  NOT_STARTED = 5,
  ENDED = 6
};

// Convert request status to string
std::string
statusToString(Status status);

/**
 * @brief The state maintained by the Challenge modules
 */
struct ChallengeState {
  ChallengeState(const std::string& challengeStatus, const time::system_clock::TimePoint& challengeTp,
                 size_t remainingTries, time::seconds remainingTime,
                 JsonSection&& challengeSecrets);
  std::string m_challengeStatus;
  time::system_clock::TimePoint m_timestamp;
  size_t m_remainingTries;
  time::seconds m_remainingTime;
  JsonSection m_secrets;
};

/**
 * @brief Represents a certificate request instance kept by the CA.
 *
 * ChallengeModule should take use of ChallengeState to keep state.
 */
class CaState {

public:
  CaState();
  CaState(const Name& caName, const std::string& requestId, RequestType requestType, Status status,
          const security::Certificate& cert, Block m_encryptionKey);
  CaState(const Name& caName, const std::string& requestId, RequestType requestType, Status status,
          const security::Certificate& cert, const std::string& challengeType,
          const std::string& challengeStatus, const time::system_clock::TimePoint& challengeTp,
          size_t remainingTries, time::seconds remainingTime, JsonSection&& challengeSecrets,
          Block m_encryptionKey);

public:
  Name m_caPrefix;
  std::string m_requestId;
  RequestType m_requestType;
  Status m_status;
  security::Certificate m_cert;
  Block m_encryptionKey;

  std::string m_challengeType;
  boost::optional<ChallengeState> m_challengeState;
};

std::ostream&
operator<<(std::ostream& os, const CaState& request);

} // namespace ndncert
} // namespace ndn

#endif // NDNCERT_CA_STATE_HPP
