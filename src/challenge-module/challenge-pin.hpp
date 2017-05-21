/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/**
 * Copyright (c) 2017, Regents of the University of California.
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

#ifndef NDNCERT_CHALLENGE_PIN_HPP
#define NDNCERT_CHALLENGE_PIN_HPP

#include "../challenge-module.hpp"
#include <ndn-cxx/util/time.hpp>

namespace ndn {
namespace ndncert {

/**
 * @brief Provide PIN code based challenge
 *
 * @sa https://github.com/named-data/ndncert/wiki/NDN-Certificate-Management-Protocol
 *
 * The main process of this challenge module is:
 *   1. End entity provides empty string. The first POLL is only for selection.
 *   2. The challenge module will generate a PIN code in ChallengeDefinedField.
 *   3. End entity provides the verification code from some way to challenge module.
 *
 * There are four specific status defined in this challenge:
 *   NEED_CODE: When selection is made.
 *   WRONG_CODE: Get wrong verification code but still with secret lifetime and max retry times.
 *
 * Failure info when application fails:
 *   FAILURE_TIMEOUT: When secret is out-dated.
 *   FAILURE_MAXRETRY: When requester tries too many times.
 */
class ChallengePin : public ChallengeModule
{
public:
  ChallengePin(const size_t& maxAttemptTimes = 3,
               const time::seconds& secretLifetime = time::seconds(3600));

PUBLIC_WITH_TESTS_ELSE_PROTECTED:
  JsonSection
  processSelectInterest(const Interest& interest, CertificateRequest& request) override;

  JsonSection
  processValidateInterest(const Interest& interest, CertificateRequest& request) override;

  std::list<std::string>
  getSelectRequirements() override;

  std::list<std::string>
  getValidateRequirements(const std::string& status) override;

  JsonSection
  doGenSelectParamsJson(const std::string& status,
                        const std::list<std::string>& paramList) override;

  JsonSection
  doGenValidateParamsJson(const std::string& status,
                          const std::list<std::string>& paramList) override;

PUBLIC_WITH_TESTS_ELSE_PRIVATE:
  static std::tuple<time::system_clock::TimePoint, std::string, int>
  parseStoredSecrets(const JsonSection& storedSecret);

  static JsonSection
  generateStoredSecrets(const time::system_clock::TimePoint& tp, const std::string& secretCode,
                        int attempTimes);

PUBLIC_WITH_TESTS_ELSE_PRIVATE:
  static const std::string NEED_CODE;
  static const std::string WRONG_CODE;

  static const std::string FAILURE_TIMEOUT;
  static const std::string FAILURE_MAXRETRY;

  static const std::string JSON_CODE_TP;
  static const std::string JSON_PIN_CODE;
  static const std::string JSON_ATTEMPT_TIMES;

private:
  time::seconds m_secretLifetime;
  int m_maxAttemptTimes;
};

} // namespace ndncert
} // namespace ndn

#endif // NDNCERT_CHALLENGE_PIN_HPP
