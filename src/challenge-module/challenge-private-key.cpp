/*
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

#include "challenge-private-key.hpp"

#include <iostream>
#include <ndn-cxx/security/verification-helpers.hpp>
#include <ndn-cxx/util/io.hpp>

#include "../logging.hpp"

namespace ndn {
namespace ndncert {

_LOG_INIT(ndncert.ChallengePrivateKey);

NDNCERT_REGISTER_CHALLENGE(ChallengePrivateKey, "Private");

const std::string ChallengePrivateKey::FAILURE_INVALID_REQUEST_TYPE = "failure-invalid-request-type";
const std::string ChallengePrivateKey::FAILURE_INVALID_FORMAT_SELF_SIGNED = "failure-cannot-parse-self-signed";
const std::string ChallengePrivateKey::FAILURE_INVALID_CREDENTIAL = "failure-invalid-credential";
const std::string ChallengePrivateKey::JSON_PROOF_OF_PRIVATE_KEY = "proof-of-private-key";

ChallengePrivateKey::ChallengePrivateKey()
    : ChallengeModule("PrivateKey")
{
}

// For CA
void
ChallengePrivateKey::handleChallengeRequest(const Block& params, CertificateRequest& request)
{
  if (request.m_requestType == REQUEST_TYPE_NEW) {
      _LOG_TRACE("Cannot use this private key challenge for new certificate request");
      request.m_status = STATUS_FAILURE;
      request.m_challengeStatus = FAILURE_INVALID_REQUEST_TYPE;
      updateRequestOnChallengeEnd(request);
  }
  params.parse();
  shared_ptr<security::v2::Certificate> selfSigned;
  auto& elements = params.elements();
  for (size_t i = 0; i < elements.size(); i++) {
    if (elements[i].type() == tlv_parameter_key) {
      if (readString(elements[i]) == JSON_PROOF_OF_PRIVATE_KEY) {
        std::istringstream ss(readString(params.elements()[i + 1]));
        selfSigned = io::load<security::v2::Certificate>(ss);
        if (selfSigned == nullptr) {
          _LOG_ERROR("Cannot load credential parameter: cert");
          request.m_status = STATUS_FAILURE;
          request.m_challengeStatus = FAILURE_INVALID_FORMAT_SELF_SIGNED;
          updateRequestOnChallengeEnd(request);
          return;
        }
      }
      else {
        continue;
      }
    }
  }

  // verify the credential and the self-signed cert
  if (security::verifySignature(*selfSigned, request.m_cert) &&
    readString(selfSigned->getContent()) == request.m_requestId) {
    request.m_status = STATUS_PENDING;
    request.m_challengeStatus = CHALLENGE_STATUS_SUCCESS;
    updateRequestOnChallengeEnd(request);
    return;
  }

  _LOG_TRACE("Cannot verify the credential + self-signed Data + data content");
  request.m_status = STATUS_FAILURE;
  request.m_challengeStatus = FAILURE_INVALID_CREDENTIAL;
  updateRequestOnChallengeEnd(request);
}

// For Client
JsonSection
ChallengePrivateKey::getRequirementForChallenge(int status, const std::string& challengeStatus)
{
  JsonSection result;
  if (status == STATUS_BEFORE_CHALLENGE && challengeStatus == "") {
    result.put(JSON_PROOF_OF_PRIVATE_KEY, "Please_copy_key_signed_request_id_data_here");
  }
  else {
    _LOG_ERROR("Client's status and challenge status are wrong");
  }
  return result;
}

JsonSection
ChallengePrivateKey::genChallengeRequestJson(int status, const std::string& challengeStatus, const JsonSection& params)
{
  JsonSection result;
  if (status == STATUS_BEFORE_CHALLENGE && challengeStatus == "") {
    result.put(JSON_PROOF_OF_PRIVATE_KEY, params.get(JSON_PROOF_OF_PRIVATE_KEY, ""));
  }
  else {
    _LOG_ERROR("Client's status and challenge status are wrong");
  }
  return result;
}

Block
ChallengePrivateKey::genChallengeRequestTLV(int status, const std::string& challengeStatus, const JsonSection& params)
{
  Block request = makeEmptyBlock(tlv_encrypted_payload);
  if (status == STATUS_BEFORE_CHALLENGE && challengeStatus == "") {
    request.push_back(makeStringBlock(tlv_selected_challenge, CHALLENGE_TYPE));
    request.push_back(makeStringBlock(tlv_parameter_key, JSON_PROOF_OF_PRIVATE_KEY));
    request.push_back(makeStringBlock(tlv_parameter_value, params.get(JSON_PROOF_OF_PRIVATE_KEY, "")));
  }
  else {
    _LOG_ERROR("Client's status and challenge status are wrong");
  }
  request.encode();
  return request;
}
}  // namespace ndncert
}  // namespace ndn
