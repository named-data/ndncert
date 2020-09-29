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

#include <iostream>
#include <ndn-cxx/security/verification-helpers.hpp>
#include <ndn-cxx/util/io.hpp>

#include "../logging.hpp"

namespace ndn {
namespace ndncert {

_LOG_INIT(ndncert.challenge.credential);
NDNCERT_REGISTER_CHALLENGE(ChallengeCredential, "Credential");

const std::string ChallengeCredential::PARAMETER_KEY_CREDENTIAL_CERT = "issued-cert";
const std::string ChallengeCredential::PARAMETER_KEY_PROOF_OF_PRIVATE_KEY = "proof-of-private-key";

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
    BOOST_THROW_EXCEPTION(std::runtime_error("Failed to parse configuration file " + m_configFile +
                                             " " + error.message() + " line " + std::to_string(error.line())));
  }

  if (config.begin() == config.end()) {
    BOOST_THROW_EXCEPTION(std::runtime_error("Error processing configuration file: " + m_configFile + " no data"));
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
std::tuple<Error, std::string>
ChallengeCredential::handleChallengeRequest(const Block& params, CertificateRequest& request)
{
  params.parse();
  if (m_trustAnchors.empty()) {
    parseConfigFile();
  }
  shared_ptr<security::v2::Certificate> selfSigned, credential;
  auto& elements = params.elements();
  for (size_t i = 0; i < elements.size(); i++) {
    if (elements[i].type() == tlv_parameter_key) {
      if (readString(elements[i]) == PARAMETER_KEY_CREDENTIAL_CERT) {
        std::istringstream ss(readString(params.elements()[i + 1]));
        credential = io::load<security::v2::Certificate>(ss);
        if (credential == nullptr) {
          _LOG_ERROR("Cannot load challenge parameter: credential");
          return returnWithError(request, Error::INVALID_PARAMETER, "Cannot challenge credential: credential.");
        }
      }
      else if (readString(elements[i]) == PARAMETER_KEY_PROOF_OF_PRIVATE_KEY) {
        std::istringstream ss(readString(params.elements()[i + 1]));
        selfSigned = io::load<security::v2::Certificate>(ss);
        if (selfSigned == nullptr) {
          _LOG_ERROR("Cannot load challenge parameter: proof of private key");
          return returnWithError(request, Error::INVALID_PARAMETER, "Cannot load challenge parameter: proof of private key.");
        }
      }
      else {
        continue;
      }
    }
  }

  // verify the credential and the self-signed cert
  Name signingKeyName = credential->getSignature().getKeyLocator().getName();
  for (auto anchor : m_trustAnchors) {
    if (anchor.getKeyName() == signingKeyName) {
      if (security::verifySignature(*selfSigned, anchor) &&
          security::verifySignature(*selfSigned, *credential) &&
          readString(selfSigned->getContent()) == request.m_requestId) {
        return returnWithSuccess(request);
      }
    }
  }

  _LOG_TRACE("Cannot verify the proof of private key against credential");
  return returnWithError(request, Error::INVALID_PARAMETER, "Cannot verify the proof of private key against credential.");
}

// For Client
std::vector<std::tuple<std::string, std::string>>
ChallengeCredential::getRequestedParameterList(Status status, const std::string& challengeStatus)
{
  std::vector<std::tuple<std::string, std::string>> result;
  if (status == Status::BEFORE_CHALLENGE) {
    result.push_back(std::make_tuple(PARAMETER_KEY_CREDENTIAL_CERT, "Please provide the certificate issued by a trusted CA."));
    result.push_back(std::make_tuple(PARAMETER_KEY_PROOF_OF_PRIVATE_KEY, "Please sign a Data packet with request ID as the content."));
  }
  else {
    BOOST_THROW_EXCEPTION(std::runtime_error("Unexpected status or challenge status."));
  }
  return result;
}

Block
ChallengeCredential::genChallengeRequestTLV(Status status, const std::string& challengeStatus,
                                            std::vector<std::tuple<std::string, std::string>>&& params)
{
  Block request = makeEmptyBlock(tlv_encrypted_payload);
  if (status == Status::BEFORE_CHALLENGE) {
    if (params.size() != 2) {
      BOOST_THROW_EXCEPTION(std::runtime_error("Wrong parameter provided."));
    }
    request.push_back(makeStringBlock(tlv_selected_challenge, CHALLENGE_TYPE));
    for (const auto& item : params) {
      if (std::get<0>(item) == PARAMETER_KEY_CREDENTIAL_CERT) {
        request.push_back(makeStringBlock(tlv_parameter_key, PARAMETER_KEY_CREDENTIAL_CERT));
        request.push_back(makeStringBlock(tlv_parameter_value, std::get<1>(item)));
      }
      else if (std::get<0>(item) == PARAMETER_KEY_PROOF_OF_PRIVATE_KEY) {
        request.push_back(makeStringBlock(tlv_parameter_key, PARAMETER_KEY_PROOF_OF_PRIVATE_KEY));
        request.push_back(makeStringBlock(tlv_parameter_value, std::get<1>(item)));
      }
      else {
        BOOST_THROW_EXCEPTION(std::runtime_error("Wrong parameter provided."));
      }
    }
  }
  else {
    BOOST_THROW_EXCEPTION(std::runtime_error("Unexpected status or challenge status."));
  }
  request.encode();
  return request;
}
}  // namespace ndncert
}  // namespace ndn
