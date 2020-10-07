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

#include "identity-challenge/challenge-module.hpp"
#include <ndn-cxx/util/random.hpp>

namespace ndn {
namespace ndncert {

ChallengeModule::ChallengeModule(const std::string& challengeType,
                                 size_t maxAttemptTimes,
                                 time::seconds secretLifetime)
  : CHALLENGE_TYPE(challengeType)
  , m_maxAttemptTimes(maxAttemptTimes)
  , m_secretLifetime(secretLifetime)
{
}

bool
ChallengeModule::isChallengeSupported(const std::string& challengeType)
{
  ChallengeFactory& factory = getFactory();
  auto i = factory.find(challengeType);
  return i == factory.end() ? false : true;
}

unique_ptr<ChallengeModule>
ChallengeModule::createChallengeModule(const std::string& challengeType)
{
  ChallengeFactory& factory = getFactory();
  auto i = factory.find(challengeType);
  return i == factory.end() ? nullptr : i->second();
}

ChallengeModule::ChallengeFactory&
ChallengeModule::getFactory()
{
  static ChallengeModule::ChallengeFactory factory;
  return factory;
}

std::string
ChallengeModule::generateSecretCode()
{
  uint32_t securityCode = 0;
  do {
    securityCode = random::generateSecureWord32();
  }
  while (securityCode >= 4294000000);
  securityCode /= 4294;
  std::string result = std::to_string(securityCode);
  while (result.length() < 6) {
    result = "0" + result;
  }
  return result;
}

std::tuple<ErrorCode, std::string>
ChallengeModule::returnWithError(CaState& request, ErrorCode errorCode, std::string&& errorInfo)
{
  request.m_status = Status::FAILURE;
  request.m_challengeType = "";
  request.m_challengeState = boost::none;
  return std::make_tuple(errorCode, std::move(errorInfo));
}

std::tuple<ErrorCode, std::string>
ChallengeModule::returnWithNewChallengeStatus(CaState& request, const std::string& challengeStatus,
                                              JsonSection&& challengeSecret, size_t remainingTries, time::seconds remainingTime)
{
  request.m_status = Status::CHALLENGE;
  request.m_challengeType = CHALLENGE_TYPE;
  request.m_challengeState = ChallengeState(challengeStatus, time::system_clock::now(), remainingTries, remainingTime, std::move(challengeSecret));
  return std::make_tuple(ErrorCode::NO_ERROR, "");
}

std::tuple<ErrorCode, std::string>
ChallengeModule::returnWithSuccess(CaState& request)
{
  request.m_status = Status::PENDING;
  request.m_challengeType = CHALLENGE_TYPE;
  request.m_challengeState = boost::none;
  return std::make_tuple(ErrorCode::NO_ERROR, "");
}

} // namespace ndncert
} // namespace ndn
