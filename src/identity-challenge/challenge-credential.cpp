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
#include <ndn-cxx/security/signing-helpers.hpp>
#include <ndn-cxx/security/transform/public-key.hpp>
#include <ndn-cxx/util/io.hpp>

namespace ndn {
namespace ndncert {

NDN_LOG_INIT(ndncert.challenge.credential);
NDNCERT_REGISTER_CHALLENGE(ChallengeCredential, "Credential");

const std::string ChallengeCredential::PARAMETER_KEY_CREDENTIAL_CERT = "issued-cert";
const std::string ChallengeCredential::PARAMETER_KEY_PROOF_OF_PRIVATE_KEY = "proof-of-private-key";

ChallengeCredential::ChallengeCredential(const std::string& configPath)
    : ChallengeModule("Credential", 1, time::seconds(1))
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
    NDN_THROW(std::runtime_error("Failed to parse configuration file " + m_configFile +
                                             " " + error.message() + " line " + std::to_string(error.line())));
  }

  if (config.begin() == config.end()) {
    NDN_THROW(std::runtime_error("Error processing configuration file: " + m_configFile + " no data"));
  }

  m_trustAnchors.clear();
  auto anchorList = config.get_child("anchor-list");
  auto it = anchorList.begin();
  for (; it != anchorList.end(); it++) {
    std::istringstream ss(it->second.get("certificate", ""));
    auto cert = io::load<security::Certificate>(ss);
    if (cert == nullptr) {
      NDN_LOG_ERROR("Cannot load the certificate from config file");
      continue;
    }
    m_trustAnchors.push_back(*cert);
  }
}

// For CA
std::tuple<ErrorCode, std::string>
ChallengeCredential::handleChallengeRequest(const Block& params, CaState& request)
{
  params.parse();
  if (m_trustAnchors.empty()) {
    parseConfigFile();
  }
  security::Certificate credential;
  const uint8_t* signature;
  size_t signatureLen;
  const auto& elements = params.elements();
  for (size_t i = 0; i < elements.size(); i++) {
    if (elements[i].type() == tlv::ParameterKey) {
      if (readString(elements[i]) == PARAMETER_KEY_CREDENTIAL_CERT) {
        try {
          credential.wireDecode(elements[i + 1].blockFromValue());
        }
        catch (const std::exception& e) {
          NDN_LOG_ERROR("Cannot load challenge parameter: credential " << e.what());
          return returnWithError(request, ErrorCode::INVALID_PARAMETER, "Cannot challenge credential: credential." + std::string(e.what()));
        }
      }
      else if (readString(elements[i]) == PARAMETER_KEY_PROOF_OF_PRIVATE_KEY) {
        signature = elements[i + 1].value();
        signatureLen = elements[i + 1].value_size();
      }
    }
  }

  // verify the credential and the self-signed cert
  Name signingKeyName = credential.getSignatureInfo().getKeyLocator().getName();
  security::transform::PublicKey key;
  const auto& pubKeyBuffer = credential.getPublicKey();
  key.loadPkcs8(pubKeyBuffer.data(), pubKeyBuffer.size());
  for (auto anchor : m_trustAnchors) {
    if (anchor.getKeyName() == signingKeyName) {
      if (security::verifySignature(credential, anchor) &&
          security::verifySignature((uint8_t*)request.m_requestId.c_str(), request.m_requestId.size(), signature, signatureLen, key)) {
        return returnWithSuccess(request);
      }
    }
  }

  NDN_LOG_TRACE("Cannot verify the proof of private key against credential");
  return returnWithError(request, ErrorCode::INVALID_PARAMETER, "Cannot verify the proof of private key against credential.");
}

// For Client
std::vector<std::tuple<std::string, std::string>>
ChallengeCredential::getRequestedParameterList(Status status, const std::string& challengeStatus)
{
  std::vector<std::tuple<std::string, std::string>> result;
  if (status == Status::BEFORE_CHALLENGE) {
    result.push_back(std::make_tuple(PARAMETER_KEY_CREDENTIAL_CERT, "Please provide the certificate issued by a trusted CA."));
    result.push_back(std::make_tuple(PARAMETER_KEY_PROOF_OF_PRIVATE_KEY, "Please sign a Data packet with request ID as the content."));
    return result;
  }
  NDN_THROW(std::runtime_error("Unexpected status or challenge status."));
}

Block
ChallengeCredential::genChallengeRequestTLV(Status status, const std::string& challengeStatus,
                                            std::vector<std::tuple<std::string, std::string>>&& params)
{
  Block request = makeEmptyBlock(tlv::EncryptedPayload);
  if (status == Status::BEFORE_CHALLENGE) {
    if (params.size() != 2) {
      NDN_THROW(std::runtime_error("Wrong parameter provided."));
    }
    request.push_back(makeStringBlock(tlv::SelectedChallenge, CHALLENGE_TYPE));
    for (const auto& item : params) {
      if (std::get<0>(item) == PARAMETER_KEY_CREDENTIAL_CERT) {
        request.push_back(makeStringBlock(tlv::ParameterKey, PARAMETER_KEY_CREDENTIAL_CERT));
        Block valueBlock = makeEmptyBlock(tlv::ParameterValue);
        auto& certTlvStr = std::get<1>(item);
        valueBlock.push_back(Block((uint8_t*)certTlvStr.c_str(), certTlvStr.size()));
        request.push_back(valueBlock);
      }
      else if (std::get<0>(item) == PARAMETER_KEY_PROOF_OF_PRIVATE_KEY) {
        request.push_back(makeStringBlock(tlv::ParameterKey, PARAMETER_KEY_PROOF_OF_PRIVATE_KEY));
        auto& sigTlvStr = std::get<1>(item);
        Block valueBlock = makeBinaryBlock(tlv::ParameterValue, (uint8_t*)sigTlvStr.c_str(), sigTlvStr.size());
        request.push_back(valueBlock);
      }
      else {
        NDN_THROW(std::runtime_error("Wrong parameter provided."));
      }
    }
  }
  else {
    NDN_THROW(std::runtime_error("Unexpected status or challenge status."));
  }
  request.encode();
  return request;
}

void
ChallengeCredential::fulfillParameters(std::vector<std::tuple<std::string, std::string>>& params,
                                       KeyChain& keyChain, const Name& issuedCertName, const std::string& requestId)
{
  auto& pib = keyChain.getPib();
  auto id = pib.getIdentity(security::extractIdentityFromCertName(issuedCertName));
  auto issuedCert = id.getKey(security::extractKeyNameFromCertName(issuedCertName)).getCertificate(issuedCertName);
  auto issuedCertTlv = issuedCert.wireEncode();
  auto signatureTlv = keyChain.sign((uint8_t*)requestId.c_str(), requestId.length(), security::signingByCertificate(issuedCertName));
  for (auto& item : params) {
    if (std::get<0>(item) == PARAMETER_KEY_CREDENTIAL_CERT) {
      std::get<1>(item) = std::string((char*)issuedCertTlv.wire(), issuedCertTlv.size());
    }
    else if (std::get<0>(item) == PARAMETER_KEY_PROOF_OF_PRIVATE_KEY) {
      std::get<1>(item) = std::string((char*)signatureTlv.value(), signatureTlv.value_size());
    }
  }
  return;
}

} // namespace ndncert
} // namespace ndn
