/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2017-2022, Regents of the University of California.
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

#ifndef NDNCERT_CHALLENGE_EMAIL_HPP
#define NDNCERT_CHALLENGE_EMAIL_HPP

#include "challenge-module.hpp"

namespace ndncert {

/**
 * @brief Provide email-based challenge.
 *
 * The main process of this challenge module is:
 *   1. Requester provides its email address.
 *   2. The challenge module will send a verification code to this email address.
 *   3. Requester provides the verification code to challenge module.
 *
 * There are several challenge status in EMAIL challenge:
 *   NEED_CODE: When email address is provided and the verification code has been sent out.
 *   WRONG_CODE: Wrong code but still within secret lifetime and within max try times.
 *
 * Failure info when application fails:
 *   FAILURE_MAXRETRY: When run out retry times.
 *   FAILURE_TIMEOUT: When the secret lifetime expires.
 *
 * @sa https://github.com/named-data/ndncert/wiki/NDNCERT-Protocol-0.3-Challenges
 */
class ChallengeEmail : public ChallengeModule
{
public:
  ChallengeEmail(const std::string& scriptPath = "ndncert-send-email-challenge",
                 const size_t& maxAttemptTimes = 3,
                 const time::seconds secretLifetime = time::seconds(300));

  // For CA
  std::tuple<ErrorCode, std::string>
  handleChallengeRequest(const Block& params, ca::RequestState& request) override;

  // For Client
  std::multimap<std::string, std::string>
  getRequestedParameterList(Status status, const std::string& challengeStatus) override;

  Block
  genChallengeRequestTLV(Status status, const std::string& challengeStatus,
                         const std::multimap<std::string, std::string>& params) override;

  // challenge status
  static const std::string NEED_CODE;
  static const std::string WRONG_CODE;
  // challenge parameters
  static const std::string PARAMETER_KEY_EMAIL;
  static const std::string PARAMETER_KEY_CODE;

NDNCERT_PUBLIC_WITH_TESTS_ELSE_PRIVATE:
  static bool
  isValidEmailAddress(const std::string& emailAddress);

  void
  sendEmail(const std::string& emailAddress, const std::string& secret,
            const ca::RequestState& request) const;

private:
  std::string m_sendEmailScript;
};

} // namespace ndncert

#endif // NDNCERT_CHALLENGE_EMAIL_HPP
