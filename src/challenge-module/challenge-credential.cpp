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

#include "challenge-credential.hpp"
#include "../logging.hpp"
#include <ndn-cxx/security/verification-helpers.hpp>
#include <ndn-cxx/util/io.hpp>

namespace ndn {
namespace ndncert {

_LOG_INIT(ndncert.ChallengeCredential);

NDNCERT_REGISTER_CHALLENGE(ChallengeCredential, "Credential");

const std::string ChallengeCredential::FAILURE_INVALID_FORMAT = "failure-invalid-format";
const std::string ChallengeCredential::FAILURE_INVALID_CREDENTIAL = "failure-invalid-credential";

const std::string ChallengeCredential::JSON_CREDENTIAL_CERT = "issued-cert";
const std::string ChallengeCredential::JSON_CREDENTIAL_SELF = "self-signed";

ChallengeCredential::ChallengeCredential(const std::string& configPath)
  : ChallengeModule("Credential")
{
  if (configPath == "") {
    m_configFile = std::string(SYSCONFDIR) + "/ndncert/challenge-credential.conf";
  }
  else
    m_configFile = configPath;
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
    std::istringstream ss(it->second.get<std::string>("certificate"));
    security::v2::Certificate cert = *(io::load<security::v2::Certificate>(ss));
    m_trustAnchors.push_back(cert);
  }
}

JsonSection
ChallengeCredential::processSelectInterest(const Interest& interest, CertificateRequest& request)
{
  if (m_trustAnchors.empty()) {
    parseConfigFile();
  }

  // interest format: /caName/CA/_SELECT/{"request-id":"id"}/CREDENTIAL/{"credential":"..."}/<signature>
  request.setChallengeType(CHALLENGE_TYPE);
  JsonSection credentialJson = getJsonFromNameComponent(interest.getName(), request.getCaName().size() + 4);

  // load credential parameters
  std::istringstream ss1(credentialJson.get<std::string>(JSON_CREDENTIAL_CERT));
  security::v2::Certificate cert;
  try {
    cert = *(io::load<security::v2::Certificate>(ss1));
  }
  catch (const std::exception& e) {
    _LOG_TRACE("Cannot load credential parameter: cert" << e.what());
    request.setStatus(FAILURE_INVALID_FORMAT);
    return genFailureJson(request.getRequestId(), CHALLENGE_TYPE, FAILURE, FAILURE_INVALID_FORMAT);
  }
  ss1.str("");
  ss1.clear();

  std::istringstream ss2(credentialJson.get<std::string>(JSON_CREDENTIAL_SELF));
  security::v2::Certificate self;
  try {
    self = *(io::load<security::v2::Certificate>(ss2));
  }
  catch (const std::exception& e) {
    _LOG_TRACE("Cannot load credential parameter: self-signed cert" << e.what());
    request.setStatus(FAILURE_INVALID_FORMAT);
    return genFailureJson(request.getRequestId(), CHALLENGE_TYPE, FAILURE, FAILURE_INVALID_FORMAT);
  }
  ss2.str("");
  ss2.clear();

  // verify two parameters
  Name signingKeyName = cert.getSignature().getKeyLocator().getName();
  for (auto anchor : m_trustAnchors) {
    if (anchor.getKeyName() == signingKeyName) {
      if (security::verifySignature(cert, anchor) && security::verifySignature(self, cert)) {
        request.setStatus(SUCCESS);
        return genResponseChallengeJson(request.getRequestId(), CHALLENGE_TYPE, SUCCESS);
      }
    }
  }

  request.setStatus(FAILURE_INVALID_CREDENTIAL);
  return genResponseChallengeJson(request.getRequestId(), CHALLENGE_TYPE, FAILURE_INVALID_CREDENTIAL);
}

JsonSection
ChallengeCredential::processValidateInterest(const Interest& interest, CertificateRequest& request)
{
  // there is no validate request here, do nothing
  return genFailureJson(request.getRequestId(), CHALLENGE_TYPE, FAILURE, FAILURE_INVALID_FORMAT);
}

std::list<std::string>
ChallengeCredential::getSelectRequirements()
{
  std::list<std::string> result;
  result.push_back("Please input the bytes of a certificate issued by the trusted CA");
  result.push_back("Please input the bytes of a self-signed certificate for the corresponding key");
  return result;
}

std::list<std::string>
ChallengeCredential::getValidateRequirements(const std::string& status)
{
  // there is no validate request here, do nothing
  std::list<std::string> result;
  return result;
}

JsonSection
ChallengeCredential::doGenSelectParamsJson(const std::string& status,
                                           const std::list<std::string>& paramList)
{
  JsonSection result;
  BOOST_ASSERT(status == WAIT_SELECTION);
  BOOST_ASSERT(paramList.size() == 2);
  result.put(JSON_CREDENTIAL_CERT, paramList.front());
  result.put(JSON_CREDENTIAL_SELF, paramList.back());
  return result;
}

JsonSection
ChallengeCredential::doGenValidateParamsJson(const std::string& status,
                                             const std::list<std::string>& paramList)
{
  JsonSection result;
  BOOST_ASSERT(paramList.size() == 0);
  return result;
}

} // namespace ndncert
} // namespace ndn
