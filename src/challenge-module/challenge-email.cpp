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

#include "challenge-email.hpp"
#include "../ca-module.hpp"
#include "../logging.hpp"
#include <regex>

namespace ndn {
namespace ndncert {

_LOG_INIT(ndncert.ChallengeEmail);

NDNCERT_REGISTER_CHALLENGE(ChallengeEmail, "email");

const std::string ChallengeEmail::NEED_CODE = "need-code";
const std::string ChallengeEmail::WRONG_CODE = "wrong-code";
const std::string ChallengeEmail::FAILURE_INVALID_EMAIL = "failure-invalid-email";
const std::string ChallengeEmail::JSON_EMAIL = "email";
const std::string ChallengeEmail::JSON_CODE = "code";

ChallengeEmail::ChallengeEmail(const std::string& scriptPath,
                               const size_t& maxAttemptTimes,
                               const time::seconds secretLifetime)
  : ChallengeModule("email")
  , m_sendEmailScript(scriptPath)
  , m_maxAttemptTimes(maxAttemptTimes)
  , m_secretLifetime(secretLifetime)
{
}

// For CA
void
ChallengeEmail::handleChallengeRequest(const JsonSection& params, CertificateRequest& request)
{
  if (request.m_challengeStatus == "") {
    // for the first time, init the challenge
    std::string emailAddress = params.get<std::string>(JSON_EMAIL);
    if (!isValidEmailAddress(emailAddress)) {
      request.m_status = STATUS_FAILURE;
      request.m_challengeStatus = FAILURE_INVALID_EMAIL;
      return;
    }
    // check whether this email is the same as the one used in PROBE
    if (request.m_probeToken != nullptr) {
      const auto& content = request.m_probeToken->getContent();
      const auto& json = CaModule::jsonFromBlock(content);
      const auto& expectedEmail = json.get("email", "");
      Name expectedPrefix(json.get(JSON_CA_NAME, ""));
      if (expectedEmail != emailAddress || !expectedPrefix.isPrefixOf(request.m_cert.getName())) {
        _LOG_ERROR("Cannot match with the PROBE token. Input email: " << emailAddress
                   << " Email in Token: " << expectedEmail
                   << " Requested Cert Name: " << request.m_cert.getName()
                   << " Identity Name got from Token: " << expectedPrefix);
        return;
      }
    }
    request.m_status = STATUS_CHALLENGE;
    request.m_challengeStatus = NEED_CODE;
    request.m_challengeType = CHALLENGE_TYPE;
    std::string emailCode = generateSecretCode();
    JsonSection secretJson;
    secretJson.add(JSON_CODE, emailCode);
    request.m_challengeSecrets = secretJson;
    request.m_challengeTp = time::toIsoString(time::system_clock::now());
    request.m_remainingTime = m_secretLifetime.count();
    request.m_remainingTries = m_maxAttemptTimes;
    // send out the email
    sendEmail(emailAddress, emailCode, request);
    _LOG_TRACE("Secret for request " << request.m_requestId << " : " << emailCode);
    return;
  }
  else if (request.m_challengeStatus == NEED_CODE || request.m_challengeStatus == WRONG_CODE) {
    _LOG_TRACE("Challenge Interest arrives. Challenge Status: " << request.m_challengeStatus);
    // the incoming interest should bring the pin code
    std::string givenCode = params.get<std::string>(JSON_CODE);
    const auto realCode = request.m_challengeSecrets.get<std::string>(JSON_CODE);
    if (time::system_clock::now() - time::fromIsoString(request.m_challengeTp) >= m_secretLifetime) {
      // secret expires
      request.m_status = STATUS_FAILURE;
      request.m_challengeStatus = CHALLENGE_STATUS_FAILURE_TIMEOUT;
      updateRequestOnChallengeEnd(request);
      _LOG_TRACE("Secret expired. Challenge failed.");
      return;
    }
    else if (givenCode == realCode) {
      // the code is correct
      request.m_status = STATUS_PENDING;
      request.m_challengeStatus = CHALLENGE_STATUS_SUCCESS;
      updateRequestOnChallengeEnd(request);
      _LOG_TRACE("Secret code matched. Challenge succeeded.");
      return;
    }
    else {
      // check rest attempt times
      if (request.m_remainingTries > 1) {
        request.m_challengeStatus = WRONG_CODE;
        request.m_remainingTries = request.m_remainingTries - 1;
        auto remainTime = m_secretLifetime - (time::system_clock::now() - time::fromIsoString(request.m_challengeTp));
        request.m_remainingTime = remainTime.count();
        _LOG_TRACE("Secret code didn't match. Remaining Tries - 1.");
        return;
      }
      else {
        // run out times
        request.m_status = STATUS_FAILURE;
        request.m_challengeStatus = CHALLENGE_STATUS_FAILURE_MAXRETRY;
        updateRequestOnChallengeEnd(request);
        _LOG_TRACE("Secret code didn't match. Ran out tires. Challenge failed.");
        return;
      }
    }
  }
  else {
    _LOG_ERROR("The challenge status is wrong");
    request.m_status = STATUS_FAILURE;
    return;
  }
}

// For Client
JsonSection
ChallengeEmail::getRequirementForChallenge(int status, const std::string& challengeStatus)
{
  JsonSection result;
  if (status == STATUS_BEFORE_CHALLENGE && challengeStatus == "") {
    result.put(JSON_EMAIL, "Please_input_your_email_address");
  }
  else if (status == STATUS_CHALLENGE && challengeStatus == NEED_CODE) {
    result.put(JSON_CODE, "Please_input_your_verification_code");
  }
  else if (status == STATUS_CHALLENGE && challengeStatus == WRONG_CODE) {
    result.put(JSON_CODE, "Incorrect_code_please_try_again");
  }
  else {
    _LOG_ERROR("CA's status and challenge status are wrong");
  }
  return result;
}

JsonSection
ChallengeEmail::genChallengeRequestJson(int status, const std::string& challengeStatus, const JsonSection& params)
{
  JsonSection result;
  if (status == STATUS_BEFORE_CHALLENGE && challengeStatus == "") {
    result.put(JSON_CLIENT_SELECTED_CHALLENGE, CHALLENGE_TYPE);
    result.put(JSON_EMAIL, params.get<std::string>(JSON_EMAIL, ""));
  }
  else if (status == STATUS_CHALLENGE && challengeStatus == NEED_CODE) {
    result.put(JSON_CLIENT_SELECTED_CHALLENGE, CHALLENGE_TYPE);
    result.put(JSON_CODE, params.get<std::string>(JSON_CODE, ""));
  }
  else if (status == STATUS_CHALLENGE && challengeStatus == WRONG_CODE) {
    result.put(JSON_CLIENT_SELECTED_CHALLENGE, CHALLENGE_TYPE);
    result.put(JSON_CODE, params.get<std::string>(JSON_CODE, ""));
  }
  else {
    _LOG_ERROR("Client's status and challenge status are wrong");
  }
  return result;
}

bool
ChallengeEmail::isValidEmailAddress(const std::string& emailAddress)
{
  const std::string pattern = R"_REGEX_((^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+.[a-zA-Z0-9\-\.]+$))_REGEX_";
  static const std::regex emailPattern(pattern);
  return std::regex_match(emailAddress, emailPattern);
}

void
ChallengeEmail::sendEmail(const std::string& emailAddress, const std::string& secret,
                          const CertificateRequest& request) const
{
  std::string command = m_sendEmailScript;
  command += " \"" + emailAddress + "\" \"" + secret + "\" \""
    + request.m_caName.toUri() + "\" \"" + request.m_cert.getName().toUri()  + "\"";
  int result = system(command.c_str());
  if (result == -1) {
    _LOG_TRACE("EmailSending Script " + m_sendEmailScript + " fails.");
  }
  _LOG_TRACE("EmailSending Script " + m_sendEmailScript +
             " was executed successfully with return value" + std::to_string(result) + ".");
  return;
}

} // namespace ndncert
} // namespace ndn
