/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2017-2024, Regents of the University of California.
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

#ifndef NDNCERT_CHALLENGE_MODULE_HPP
#define NDNCERT_CHALLENGE_MODULE_HPP

#include "detail/ca-request-state.hpp"

#include <map>
#include <tuple>

namespace ndncert {

class ChallengeModule : boost::noncopyable
{
public:
  ChallengeModule(const std::string& challengeType, size_t maxAttemptTimes, time::seconds secretLifetime);

  virtual
  ~ChallengeModule() = default;

  // For CA
  virtual std::tuple<ErrorCode, std::string>
  handleChallengeRequest(const Block& params, ca::RequestState& request) = 0;

  // For Client
  virtual std::multimap<std::string, std::string>
  getRequestedParameterList(Status status, const std::string& challengeStatus) = 0;

  virtual Block
  genChallengeRequestTLV(Status status, const std::string& challengeStatus,
                         const std::multimap<std::string, std::string>& params) = 0;

public: // factory
  template<class ChallengeType>
  static void
  registerChallengeModule(const std::string& type)
  {
    auto& factory = getFactory();
    BOOST_ASSERT(factory.count(type) == 0);
    factory[type] = [] { return std::make_unique<ChallengeType>(); };
  }

  static bool
  isChallengeSupported(const std::string& challengeType);

  static std::unique_ptr<ChallengeModule>
  createChallengeModule(const std::string& challengeType);

protected: // helpers used by concrete challenge modules
  static std::string
  generateSecretCode();

  static std::tuple<ErrorCode, std::string>
  returnWithError(ca::RequestState& request, ErrorCode errorCode, std::string errorInfo);

  std::tuple<ErrorCode, std::string>
  returnWithNewChallengeStatus(ca::RequestState& request, const std::string& challengeStatus,
                               JsonSection challengeSecret, size_t remainingTries, time::seconds remainingTime);

  std::tuple<ErrorCode, std::string>
  returnWithSuccess(ca::RequestState& request);

public:
  const std::string CHALLENGE_TYPE;

protected:
  const size_t m_maxAttemptTimes;
  const time::seconds m_secretLifetime;

private:
  using CreateFunc = std::function<std::unique_ptr<ChallengeModule>()>;
  using ChallengeFactory = std::map<std::string, CreateFunc>;

  static ChallengeFactory&
  getFactory();
};

} // namespace ndncert

#define NDNCERT_REGISTER_CHALLENGE(C, T)                            \
static class NdnCert##C##ChallengeRegistrationClass                 \
{                                                                   \
public:                                                             \
  NdnCert##C##ChallengeRegistrationClass()                          \
  {                                                                 \
    ::ndncert::ChallengeModule::registerChallengeModule<C>(T);      \
  }                                                                 \
} g_NdnCert##C##ChallengeRegistrationVariable

#endif // NDNCERT_CHALLENGE_MODULE_HPP
