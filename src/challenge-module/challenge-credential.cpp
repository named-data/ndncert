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

#include "challenge-credential.hpp"
#include "../logging.hpp"
#include <ndn-cxx/security/verification-helpers.hpp>
#include <ndn-cxx/util/io.hpp>

namespace ndn {
namespace ndncert {

_LOG_INIT(ndncert.ChallengeCredential);

NDNCERT_REGISTER_CHALLENGE(ChallengeCredential, "Credential");

const std::string ChallengeCredential::FAILURE_INVALID_FORMAT_CREDENTIAL = "failure-cannot-parse-credential";
const std::string ChallengeCredential::FAILURE_INVALID_FORMAT_SELF_SIGNED = "failure-cannot-parse-self-signed";
const std::string ChallengeCredential::FAILURE_INVALID_CREDENTIAL = "failure-invalid-credential";
const std::string ChallengeCredential::JSON_CREDENTIAL_CERT = "issued-cert";
const std::string ChallengeCredential::JSON_CREDENTIAL_SELF = "self-signed";

ChallengeCredential::ChallengeCredential(const std::string& configPath)
  : ChallengeModule("Credential")
{
  if (configPath.empty()) {
    m_configFile = std::string(SYSCONFDIR) + "/ndncert/challenge-credential.conf";
  }
  else {
    m_configFile = configPath;
  }
}

void
ChallengeCredential::parseConfigFile()
{
  JsonSection config;
  try {
    boost::property_tree::read_json(m_configFile, config);
  }
  catch (const boost::property_tree::info_parser_error& error) {
    BOOST_THROW_EXCEPTION(Error("Failed to parse configuration file " + m_configFile +
                                " " + error.message() + " line " + std::to_string(error.line())));
  }

  if (config.begin() == config.end()) {
    BOOST_THROW_EXCEPTION(Error("Error processing configuration file: " + m_configFile + " no data"));
  }

  m_trustAnchors.clear();
  auto anchorList = config.get_child("anchor-list");
  auto it = anchorList.begin();
  for (; it != anchorList.end(); it++) {
    std::istringstream ss(it->second.get("certificate", ""));
    auto cert = io::load<security::v2::Certificate>(ss);
    if (cert == nullptr) {
      _LOG_ERROR("Cannot load the certificate from config file");
      continue;
    }
    m_trustAnchors.push_back(*cert);
  }
}

// For CA
void
ChallengeCredential::handleChallengeRequest(const Block& params, CertificateRequest& request)
{
  if (m_trustAnchors.empty()) {
    parseConfigFile();
  }
  // load credential parameter
  // TODO: instead of string, should pass certificate byte value directly
  std::istringstream ss1(readString(params.elements().at(1)));
  auto cert = io::load<security::v2::Certificate>(ss1);
  if (cert == nullptr) {
    _LOG_ERROR("Cannot load credential parameter: cert");
    request.m_status = STATUS_FAILURE;
    request.m_challengeStatus = FAILURE_INVALID_FORMAT_CREDENTIAL;
    updateRequestOnChallengeEnd(request);
    return;
  }
  ss1.str("");
  ss1.clear();

  // load self-signed data
  std::istringstream ss2(readString(params.elements().at(3)));
  auto self = io::load<Data>(ss2);
  if (self == nullptr) {
    _LOG_TRACE("Cannot load credential parameter: self-signed cert");
    request.m_status = STATUS_FAILURE;
    request.m_challengeStatus = FAILURE_INVALID_FORMAT_SELF_SIGNED;
    updateRequestOnChallengeEnd(request);
    return;
  }
  ss2.str("");
  ss2.clear();

  // verify the credential and the self-signed cert
  Name signingKeyName = cert->getSignatureInfo().getKeyLocator().getName();
  for (auto anchor : m_trustAnchors) {
    if (anchor.getKeyName() == signingKeyName) {
      if (security::verifySignature(*cert, anchor) && security::verifySignature(*self, *cert)
          && readString(self->getContent()) == request.m_requestId) {
        request.m_status = STATUS_PENDING;
        request.m_challengeStatus = CHALLENGE_STATUS_SUCCESS;
        updateRequestOnChallengeEnd(request);
        return;
      }
    }
  }

  _LOG_TRACE("Cannot verify the credential + self-signed Data + data content");
  request.m_status = STATUS_FAILURE;
  request.m_challengeStatus = FAILURE_INVALID_CREDENTIAL;
  updateRequestOnChallengeEnd(request);
  return;
}

// For Client
JsonSection
ChallengeCredential::getRequirementForChallenge(int status, const std::string& challengeStatus)
{
  JsonSection result;
  if (status == STATUS_BEFORE_CHALLENGE && challengeStatus == "") {
    result.put(JSON_CREDENTIAL_CERT, "Please_copy_anchor_signed_cert_here");
    result.put(JSON_CREDENTIAL_SELF, "Please_copy_key_signed_request_id_data_here");
  }
  else {
    _LOG_ERROR("Client's status and challenge status are wrong");
  }
  return result;
}

JsonSection
ChallengeCredential::genChallengeRequestJson(int status, const std::string& challengeStatus, const JsonSection& params)
{
  JsonSection result;
  if (status == STATUS_BEFORE_CHALLENGE && challengeStatus == "") {
    result.put(JSON_CREDENTIAL_CERT, params.get(JSON_CREDENTIAL_CERT, ""));
    result.put(JSON_CREDENTIAL_SELF, params.get(JSON_CREDENTIAL_SELF, ""));
  }
  else {
    _LOG_ERROR("Client's status and challenge status are wrong");
  }
  return result;
}

Block
ChallengeCredential::genChallengeRequestTLV(int status, const std::string& challengeStatus, const JsonSection& params)
{
  Block request = makeEmptyBlock(tlv_encrypted_payload);
  if (status == STATUS_BEFORE_CHALLENGE && challengeStatus == "") {
    request.push_back(makeStringBlock(tlv_selected_challenge, CHALLENGE_TYPE));
    request.push_back(makeStringBlock(tlv_parameter_key, JSON_CREDENTIAL_CERT));
    request.push_back(makeStringBlock(tlv_parameter_value, params.get(JSON_CREDENTIAL_CERT,"")));
    request.push_back(makeStringBlock(tlv_parameter_key, JSON_CREDENTIAL_SELF));
    request.push_back(makeStringBlock(tlv_parameter_value, params.get(JSON_CREDENTIAL_SELF,"")));
  }
  else {
    _LOG_ERROR("Client's status and challenge status are wrong");
  }
  request.parse();
  return request;
}


} // namespace ndncert
} // namespace ndn
