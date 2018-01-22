/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/**
 * Copyright (c) 2017-2018, Regents of the University of California.
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
#include "json-helper.hpp"

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

  static unique_ptr<ChallengeModule>
  createChallengeModule(const std::string& ChallengeType);

  // For CA
  /**
   * @brief Handle the challenge related interest and update certificate request.
   * @note Should be used by CA Module
   * @note Signature of interest should already be validated by CA Module
   *
   * When CA receives a SELECT or a VALIDATE or a STATUS interest, CA should invoke the function
   * to enable selected challenge to go on the verification process.
   *
   * @param interest The request interest packet
   * @param request The CertificateRequest instance
   * @return the JSON file as the response data content
   */
  JsonSection
  handleChallengeRequest(const Interest& interest, CertificateRequest& request);

  // For Client
  /**
   * @brief Get requirements for requester before sending SELECT interest.
   * @note Should be used by Client Module
   *
   * Before requester sends a USE interest, client should invoke the function to
   * get input instruction and expose the instruction to requester.
   *
   * Every item in the return list requires a input from requester. The item itself is
   * an instruction for requester.
   *
   * @return the input instruction for requester
   */
  std::list<std::string>
  getRequirementForSelect();

  /**
   * @brief Get requirements for requester before sending VALIDATE interest.
   * @note Should be used by Client Module
   *
   * Before requester sends a POLL interest, client should invoke the function to
   * get input instruction and expose the instruction to requester.
   *
   * Every item in the return list requires a input from requester. The item itself is
   * an instruction for requester.
   *
   * @param status of the challenge
   * @return the input instruction for requester
   */
  std::list<std::string>
  getRequirementForValidate(const std::string& status);

  /**
   * @brief Generate ChallengeInfo part for SELECT interest.
   * @note Should be used by Client Module
   *
   * After requester provides required information, client should invoke the function to
   * generate the ChallengeInfo part of the interest.
   *
   * @param status of the challenge
   * @param paramList contains all the input from requester
   * @return the JSON file of ChallengeInfo
   */
  JsonSection
  genSelectParamsJson(const std::string& status, const std::list<std::string>& paramList);

  /**
   * @brief Generate ChallengeInfo part for VALIDATE interest.
   * @note Should be used by Client Module
   *
   * After requester provides required information, client should invoke the function to
   * generate the ChallengeInfo part of the interest.
   *
   * @param status of the challenge
   * @param paramList contains all the input from requester
   * @return the JSON file of ChallengeInfo
   */
  JsonSection
  genValidateParamsJson(const std::string& status, const std::list<std::string>& paramList);

PUBLIC_WITH_TESTS_ELSE_PROTECTED:
  // For CA
  virtual JsonSection
  processSelectInterest(const Interest& interest, CertificateRequest& request) = 0;

  virtual JsonSection
  processValidateInterest(const Interest& interest, CertificateRequest& request) = 0;

  virtual JsonSection
  processStatusInterest(const Interest& interest, const CertificateRequest& request);

  // For Client
  virtual std::list<std::string>
  getSelectRequirements() = 0;

  virtual std::list<std::string>
  getValidateRequirements(const std::string& status) = 0;

  virtual JsonSection
  doGenSelectParamsJson(const std::string& status, const std::list<std::string>& paramList) = 0;

  virtual JsonSection
  doGenValidateParamsJson(const std::string& status, const std::list<std::string>& paramList) = 0;

  // Helpers
  static JsonSection
  getJsonFromNameComponent(const Name& name, int pos);

  static Name
  genDownloadName(const Name& caName, const std::string& requestId);

  static std::string
  generateSecretCode();

public:
  const std::string CHALLENGE_TYPE;
  static const std::string WAIT_SELECTION;
  static const std::string SUCCESS;
  static const std::string PENDING;
  static const std::string FAILURE;

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
