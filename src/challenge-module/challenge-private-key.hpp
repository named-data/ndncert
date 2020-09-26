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

#ifndef NDNCERT_CHALLENGE_PRIVATE_KEY_HPP
#define NDNCERT_CHALLENGE_PRIVATE_KEY_HPP

#include "../challenge-module.hpp"

namespace ndn {
namespace ndncert {

/**
 * @brief Private Key based challenge (for renewal and revocation)
 *
 * Once the requester could proof his/her possession of the private key corresponds to
 * the current CA's previous issued certificate, the requester could finish the challenge.
 *
 * The requester needs to provide the proof of the possession the private for the certificate
 * for the previous cerificate. The challenge require the requester to a BASE64 Data packet
 * signed by the credential pub key and whose content is the request id.
 *
 * The main process of this challenge module is:
 *   1. The requester sign a Data packet which content is the request id.
 *   2. The challenge module will verify the signature of the credential.
 *
 * Failure info when application fails:
 *   FAILURE_INVALID_CREDENTIAL: When the signature cannot be validated.
 *   FAILURE_INVALID_FORMAT: When the credential format is wrong.
 */
class ChallengePrivateKey : public ChallengeModule
{
public:
  ChallengePrivateKey();

  // For CA
  void
  handleChallengeRequest(const Block& params, CertificateRequest& request) override;

  // For Client
  JsonSection
  getRequirementForChallenge(int status, const std::string& challengeStatus) override;

  JsonSection
  genChallengeRequestJson(int status, const std::string& challengeStatus, const JsonSection& params) override;

  Block
  genChallengeRequestTLV(int status, const std::string& challengeStatus, const JsonSection& params) override;

PUBLIC_WITH_TESTS_ELSE_PRIVATE:
  static const std::string FAILURE_INVALID_REQUEST_TYPE;
  static const std::string FAILURE_INVALID_CREDENTIAL;
  static const std::string FAILURE_INVALID_FORMAT_SELF_SIGNED;
  static const std::string JSON_PROOF_OF_PRIVATE_KEY;
};

} // namespace ndncert
} // namespace ndn

#endif // NDNCERT_CHALLENGE_PRIVATE_KEY_HPP
