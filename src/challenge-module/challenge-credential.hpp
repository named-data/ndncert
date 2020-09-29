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

#ifndef NDNCERT_CHALLENGE_CREDENTIAL_HPP
#define NDNCERT_CHALLENGE_CREDENTIAL_HPP

#include "../challenge-module.hpp"

namespace ndn {
namespace ndncert {

/**
 * @brief Provide Credential based challenge
 *
 * Credential here means the certificate issued by a trust anchor. Once the requester
 * could proof his/her possession of an existing certificate from other certificate issuer,
 * the requester could finish the challenge.
 *
 * The requester needs to provide the proof of the possession of a certificate issued by
 * a trust anchor. The challenge require the requester to pass the BASE64 certificate and
 * a BASE64 Data packet signed by the credential pub key and whose content is the request id.
 *
 * The main process of this challenge module is:
 *   1. Requester provides a certificate signed by that trusted certificate as credential.
 *   2. The challenge module will verify the signature of the credential.
 *   3. The content of the signed Data is the request id
 *
 * Failure info when application fails:
 *   FAILURE_INVALID_CREDENTIAL: When the cert issued from trust anchor or self-signed cert
 *     cannot be validated.
 *   FAILURE_INVALID_FORMAT: When the credential format is wrong.
 */
class ChallengeCredential : public ChallengeModule
{
public:
  ChallengeCredential(const std::string& configPath = "");

  // For CA
  std::tuple<Error, std::string>
  handleChallengeRequest(const Block& params, CertificateRequest& request) override;

  // For Client
  std::vector<std::tuple<std::string, std::string>>
  getRequestedParameterList(Status status, const std::string& challengeStatus) override;

  Block
  genChallengeRequestTLV(Status status, const std::string& challengeStatus,
                         std::vector<std::tuple<std::string, std::string>>&& params) override;

PUBLIC_WITH_TESTS_ELSE_PRIVATE:
  void
  parseConfigFile();

PUBLIC_WITH_TESTS_ELSE_PRIVATE:
  // parameters
  static const std::string PARAMETER_KEY_CREDENTIAL_CERT;
  static const std::string PARAMETER_KEY_PROOF_OF_PRIVATE_KEY;

  std::list<security::v2::Certificate> m_trustAnchors;
  std::string m_configFile;
};

} // namespace ndncert
} // namespace ndn

#endif // NDNCERT_CHALLENGE_CREDENTIAL_HPP
