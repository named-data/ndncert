/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2017-2021, Regents of the University of California.
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

#ifndef NDNCERT_DETAIL_CA_REQUEST_STATE_HPP
#define NDNCERT_DETAIL_CA_REQUEST_STATE_HPP

#include "detail/ndncert-common.hpp"

#include <array>

namespace ndncert {

typedef std::array<uint8_t, 8> RequestId;

enum class Status : uint16_t {
  BEFORE_CHALLENGE = 0,
  CHALLENGE = 1,
  PENDING = 2,
  SUCCESS = 3,
  FAILURE = 4
};

/**
 * @brief Convert request status to string.
 */
std::string
statusToString(Status status);

/**
 * @brief Convert request status to string.
 */
Status
statusFromBlock(const Block& block);

namespace ca {

/**
 * @brief The state maintained by the Challenge module.
 */
struct ChallengeState
{
  ChallengeState(const std::string& challengeStatus, const time::system_clock::TimePoint& challengeTp,
                 size_t remainingTries, time::seconds remainingTime,
                 JsonSection&& challengeSecrets);
  /**
   * @brief The status of the challenge.
   */
  std::string challengeStatus;
  /**
   * @brief The timestamp of the last update of the challenge state.
   */
  time::system_clock::TimePoint timestamp;
  /**
   * @brief Remaining tries of the challenge.
   */
  size_t remainingTries;
  /**
   * @brief Remaining time of the challenge.
   */
  time::seconds remainingTime;
  /**
   * @brief The secret for the challenge.
   */
  JsonSection secrets;
};

/**
 * @brief Represents a certificate request instance kept by the CA.
 *
 * ChallengeModule should take use of RequestState.ChallengeState to keep the challenge state.
 */
struct RequestState
{
  /**
   * @brief The CA that the request is under.
   */
  Name caPrefix;
  /**
   * @brief The ID of the request.
   */
  RequestId requestId;
  /**
   * @brief The type of the request.
   */
  RequestType requestType = RequestType::NOTINITIALIZED;
  /**
   * @brief The status of the request.
   */
  Status status = Status::BEFORE_CHALLENGE;
  /**
   * @brief The self-signed certificate in the request.
   */
  Certificate cert;
  /**
   * @brief The encryption key for the requester.
   */
  std::array<uint8_t, 16> encryptionKey = {};
  /**
   * @brief The last Initialization Vector used by the AES encryption.
   */
  std::vector<uint8_t> encryptionIv;
  /**
   * @brief The last Initialization Vector used by the other side's AES encryption.
   */
  std::vector<uint8_t> decryptionIv;
  /**
   * @brief The challenge type.
   */
  std::string challengeType;
  /**
   * @brief The challenge state.
   */
  optional<ChallengeState> challengeState;
};

std::ostream&
operator<<(std::ostream& os, const RequestState& request);

} // namespace ca
} // namespace ndncert

#endif // NDNCERT_DETAIL_CA_REQUEST_STATE_HPP
