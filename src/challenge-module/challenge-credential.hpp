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

#ifndef NDNCERT_CHALLENGE_CREDENTIAL_HPP
#define NDNCERT_CHALLENGE_CREDENTIAL_HPP

#include "../challenge-module.hpp"

namespace ndn {
namespace ndncert {

/**
 * @brief Provide Credential based challenge
 *
 * Credential here means the certificate issued by a trust anchor. Once the requester
 * could proof his/her possession of an existing certificate from other certificate, th
 * requester could finish the challenge.
 *
 * The requester needs to provide the proof of the possession of a certificate issued by
 * a trust anchor. The challenge require the requester to pass the BASE64 certificate and
 * a BASE64 self-signed certificate whose key is the same as the key in certificate.
 *
 * The main process of this challenge module is:
 *   1. Requester provides a certificate signed by that trusted certificate as credential.
 *   2. The challenge module will verify the signature of the credential.
 *
 * There are several challenge status in EMAIL challenge:
 *   FAILURE_INVALID_SIG: When the credential cannot be validated.
 */
class ChallengeCredential : public ChallengeModule
{
public:
  ChallengeCredential(const std::string& configPath = "");

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
  void
  parseConfigFile();

PUBLIC_WITH_TESTS_ELSE_PRIVATE:
  static const std::string FAILURE_INVALID_CREDENTIAL;
  static const std::string FAILURE_INVALID_FORMAT;
  static const std::string JSON_CREDENTIAL_CERT;
  static const std::string JSON_CREDENTIAL_SELF;

PUBLIC_WITH_TESTS_ELSE_PRIVATE:
  std::list<security::v2::Certificate> m_trustAnchors;
  std::string m_configFile;
};

} // namespace ndncert
} // namespace ndn

#endif // NDNCERT_CHALLENGE_CREDENTIAL_HPP
