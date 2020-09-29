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

#include "challenge-module.hpp"
#include <ndn-cxx/util/random.hpp>

namespace ndn {
namespace ndncert {

ChallengeModule::ChallengeModule(const std::string& uniqueType)
  : CHALLENGE_TYPE(uniqueType)
{
}

ChallengeModule::~ChallengeModule() = default;

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

std::tuple<Error, std::string>
ChallengeModule::returnWithError(CertificateRequest& request, Error errorCode, std::string&& errorInfo)
{
  request.m_status = Status::FAILURE;
  request.m_challengeType = "";
  request.m_challengeStatus = "";
  request.m_challengeSecrets = JsonSection();
  request.m_challengeTp = "";
  request.m_remainingTime = 0;
  request.m_remainingTries = 0;
  return std::make_tuple(errorCode, std::move(errorInfo));
}

std::tuple<Error, std::string>
ChallengeModule::returnWithNewChallengeStatus(CertificateRequest& request, const std::string& challengeStatus,
                                              JsonSection&& challengeSecret, size_t remainingTries, size_t remainingTime)
{
  request.m_status = Status::CHALLENGE;
  request.m_challengeType = CHALLENGE_TYPE;
  request.m_challengeStatus = std::move(challengeStatus);
  request.m_challengeSecrets = std::move(challengeSecret);
  request.m_challengeTp = time::toIsoString(time::system_clock::now());
  request.m_remainingTime = remainingTries;
  request.m_remainingTries = remainingTime;
  return std::make_tuple(Error::NO_ERROR, "");
}

std::tuple<Error, std::string>
ChallengeModule::returnWithSuccess(CertificateRequest& request)
{
  request.m_status = Status::PENDING;
  request.m_challengeType = CHALLENGE_TYPE;
  request.m_challengeStatus = "";
  request.m_challengeSecrets = JsonSection();
  request.m_challengeTp = "";
  request.m_remainingTime = 0;
  request.m_remainingTries = 0;
  return std::make_tuple(Error::NO_ERROR, "");
}

} // namespace ndncert
} // namespace ndn
