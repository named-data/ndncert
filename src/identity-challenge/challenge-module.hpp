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

#ifndef NDNCERT_CHALLENGE_MODULE_HPP
#define NDNCERT_CHALLENGE_MODULE_HPP

#include "detail/ca-request-state.hpp"

namespace ndn {
namespace ndncert {

class ChallengeModule : noncopyable
{
public:
  explicit
  ChallengeModule(const std::string& challengeType, size_t maxAttemptTimes, time::seconds secretLifetime);

  virtual ~ChallengeModule() = default;

  template <class ChallengeType>
  static void
  registerChallengeModule(const std::string& typeName)
  {
    ChallengeFactory& factory = getFactory();
    BOOST_ASSERT(factory.count(typeName) == 0);
    factory[typeName] = [] { return std::make_unique<ChallengeType>(); };
  }

  static bool
  isChallengeSupported(const std::string& challengeType);

  static unique_ptr<ChallengeModule>
  createChallengeModule(const std::string& challengeType);

  // For CA
  virtual std::tuple<ErrorCode, std::string>
  handleChallengeRequest(const Block& params, ca::RequestState& request) = 0;

  // For Client
  virtual std::multimap<std::string, std::string>
  getRequestedParameterList(Status status, const std::string& challengeStatus) = 0;

  virtual Block
  genChallengeRequestTLV(Status status, const std::string& challengeStatus,
                         std::multimap<std::string, std::string>&& params) = 0;

  // helpers
  static std::string
  generateSecretCode();

protected:
  // used by challenge modules
  std::tuple<ErrorCode, std::string>
  returnWithError(ca::RequestState& request, ErrorCode errorCode, std::string&& errorInfo);

  std::tuple<ErrorCode, std::string>
  returnWithNewChallengeStatus(ca::RequestState& request, const std::string& challengeStatus,
                               JsonSection&& challengeSecret, size_t remainingTries, time::seconds remainingTime);

  std::tuple<ErrorCode, std::string>
  returnWithSuccess(ca::RequestState& request);

public:
  const std::string CHALLENGE_TYPE;
  const size_t m_maxAttemptTimes;
  const time::seconds m_secretLifetime;

private:
  typedef function<unique_ptr<ChallengeModule>()> ChallengeCreateFunc;
  typedef std::map<std::string, ChallengeCreateFunc> ChallengeFactory;

  static ChallengeFactory&
  getFactory();
};

#define NDNCERT_REGISTER_CHALLENGE(C, T)                              \
  static class NdnCert##C##ChallengeRegistrationClass {               \
  public:                                                             \
    NdnCert##C##ChallengeRegistrationClass()                          \
    {                                                                 \
      ::ndn::ndncert::ChallengeModule::registerChallengeModule<C>(T); \
    }                                                                 \
  } g_NdnCert##C##ChallengeRegistrationVariable

} // namespace ndncert
} // namespace ndn

#endif // NDNCERT_CHALLENGE_MODULE_HPP
