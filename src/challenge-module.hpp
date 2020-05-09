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

#ifndef NDNCERT_CHALLENGE_MODULE_HPP
#define NDNCERT_CHALLENGE_MODULE_HPP

#include "ndncert-common.hpp"
#include "certificate-request.hpp"

namespace ndn {
namespace ndncert {

class ChallengeModule : noncopyable
{
public:
  /**
   * @brief Error that can be thrown from ChallengeModule
   *
   * ChallengeModule should throw Error to notice CA there's an Error. In this case, CA will
   * generate an Error JSON file back to end entity.
   */
  class Error : public std::runtime_error
  {
  public:
    using std::runtime_error::runtime_error;
  };

public:
  explicit
  ChallengeModule(const std::string& uniqueType);

  virtual
  ~ChallengeModule();

  template<class ChallengeType>
  static void
  registerChallengeModule(const std::string& typeName)
  {
    ChallengeFactory& factory = getFactory();
    BOOST_ASSERT(factory.count(typeName) == 0);
    factory[typeName] = [] { return make_unique<ChallengeType>(); };
  }

  static bool
  supportChallenge(const std::string& challengeType);

  static unique_ptr<ChallengeModule>
  createChallengeModule(const std::string& challengeType);

  // For CA
  virtual void
  handleChallengeRequest(const Block& params, CertificateRequest& request) = 0;

  // For Client
  virtual JsonSection
  getRequirementForChallenge(int status, const std::string& challengeStatus) = 0;

  virtual JsonSection
  genChallengeRequestJson(int status, const std::string& challengeStatus, const JsonSection& params) = 0;

  virtual Block
  genChallengeRequestTLV(int status, const std::string& challengeStatus, const JsonSection& params) = 0;

  // helpers
  static std::string
  generateSecretCode();

protected:

  void
  updateRequestOnChallengeEnd(CertificateRequest& request);

public:
  const std::string CHALLENGE_TYPE;

private:
  typedef function<unique_ptr<ChallengeModule> ()> ChallengeCreateFunc;
  typedef std::map<std::string, ChallengeCreateFunc> ChallengeFactory;

  static ChallengeFactory&
  getFactory();
};

#define NDNCERT_REGISTER_CHALLENGE(C, T)                           \
static class NdnCert ## C ## ChallengeRegistrationClass            \
{                                                                  \
public:                                                            \
  NdnCert ## C ## ChallengeRegistrationClass()                     \
  {                                                                \
    ::ndn::ndncert::ChallengeModule::registerChallengeModule<C>(T);\
  }                                                                \
} g_NdnCert ## C ## ChallengeRegistrationVariable

} // namespace ndncert
} // namespace ndn

#endif // NDNCERT_CHALLENGE_MODULE_HPP
