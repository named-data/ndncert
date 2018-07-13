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

#include "challenge-email.hpp"
#include "../logging.hpp"
#include <regex>

namespace ndn {
namespace ndncert {

_LOG_INIT(ndncert.ChallengeEmail);

NDNCERT_REGISTER_CHALLENGE(ChallengeEmail, "Email");

const std::string ChallengeEmail::NEED_CODE = "need-code";
const std::string ChallengeEmail::WRONG_CODE = "wrong-code";

const std::string ChallengeEmail::FAILURE_INVALID_EMAIL = "failure-invalid-email";
const std::string ChallengeEmail::FAILURE_TIMEOUT = "timeout";
const std::string ChallengeEmail::FAILURE_MAXRETRY = "max-retry";

const std::string ChallengeEmail::JSON_EMAIL = "email";
const std::string ChallengeEmail::JSON_CODE_TP = "code-timepoint";
const std::string ChallengeEmail::JSON_CODE = "code";
const std::string ChallengeEmail::JSON_ATTEMPT_TIMES = "attempt-times";

ChallengeEmail::ChallengeEmail(const std::string& scriptPath,
                               const size_t& maxAttemptTimes,
                               const time::seconds secretLifetime)
  : ChallengeModule("Email")
  , m_sendEmailScript(scriptPath)
  , m_maxAttemptTimes(maxAttemptTimes)
  , m_secretLifetime(secretLifetime)
{
}

JsonSection
ChallengeEmail::processSelectInterest(const Interest& interest, CertificateRequest& request)
{
  // interest format: /caName/CA/_SELECT/{"request-id":"id"}/EMAIL/{"Email":"email"}/<signature>
  JsonSection emailJson = getJsonFromNameComponent(interest.getName(),
                                                   request.getCaName().size() + 4);
  std::string emailAddress = emailJson.get<std::string>(JSON_EMAIL);
  if (!isValidEmailAddress(emailAddress)) {
    request.setStatus(FAILURE_INVALID_EMAIL);
    request.setChallengeType(CHALLENGE_TYPE);
    return genFailureJson(request.getRequestId(), CHALLENGE_TYPE, FAILURE, FAILURE_INVALID_EMAIL);
  }

  std::string emailCode = generateSecretCode();
  sendEmail(emailAddress, emailCode, request.getCaName().toUri());

  request.setStatus(NEED_CODE);
  request.setChallengeType(CHALLENGE_TYPE);
  request.setChallengeSecrets(generateStoredSecrets(time::system_clock::now(),
                                                    emailCode, m_maxAttemptTimes));
  return genResponseChallengeJson(request.getRequestId(), CHALLENGE_TYPE, NEED_CODE);
}

JsonSection
ChallengeEmail::processValidateInterest(const Interest& interest, CertificateRequest& request)
{
  // interest format: /caName/CA/_VALIDATION/{"request-id":"id"}/EMAIL/{"code":"code"}/<signature>
  JsonSection infoJson = getJsonFromNameComponent(interest.getName(), request.getCaName().size() + 4);
  std::string givenCode = infoJson.get<std::string>(JSON_CODE);

  const auto parsedSecret = parseStoredSecrets(request.getChallengeSecrets());
  if (time::system_clock::now() - std::get<0>(parsedSecret) >= m_secretLifetime) {
    // secret expires
    request.setStatus(FAILURE_TIMEOUT);
    request.setChallengeSecrets(JsonSection());
    return genFailureJson(request.getRequestId(), CHALLENGE_TYPE, FAILURE, FAILURE_TIMEOUT);
  }
  else if (givenCode == std::get<1>(parsedSecret)) {
    request.setStatus(SUCCESS);
    request.setChallengeSecrets(JsonSection());
    Name downloadName = genDownloadName(request.getCaName(), request.getRequestId());
    return genResponseChallengeJson(request.getRequestId(), CHALLENGE_TYPE, SUCCESS, downloadName);
  }
  else {
    // check rest attempt times
    if (std::get<2>(parsedSecret) > 1) {
      int restAttemptTimes = std::get<2>(parsedSecret) - 1;
      request.setStatus(WRONG_CODE);
      request.setChallengeSecrets(generateStoredSecrets(std::get<0>(parsedSecret),
                                                        std::get<1>(parsedSecret),
                                                        restAttemptTimes));
      return genResponseChallengeJson(request.getRequestId(), CHALLENGE_TYPE, WRONG_CODE);
    }
    else {
      // run out times
      request.setStatus(FAILURE_MAXRETRY);
      request.setChallengeSecrets(JsonSection());
      return genFailureJson(request.getRequestId(), CHALLENGE_TYPE, FAILURE, FAILURE_MAXRETRY);
    }
  }
}

std::list<std::string>
ChallengeEmail::getSelectRequirements()
{
  std::list<std::string> result;
  result.push_back("Please input your email address:");
  return result;
}

std::list<std::string>
ChallengeEmail::getValidateRequirements(const std::string& status)
{
  std::list<std::string> result;
  if (status == NEED_CODE) {
    result.push_back("Please input your verification code:");
  }
  else if (status == WRONG_CODE) {
    result.push_back("Incorrect PIN code, please try again and input your verification code:");
  }
  return result;
}

JsonSection
ChallengeEmail::doGenSelectParamsJson(const std::string& status,
                                      const std::list<std::string>& paramList)
{
  JsonSection result;
  BOOST_ASSERT(status == WAIT_SELECTION);
  BOOST_ASSERT(paramList.size() == 1);
  result.put(JSON_EMAIL, paramList.front());
  return result;
}

JsonSection
ChallengeEmail::doGenValidateParamsJson(const std::string& status,
                                        const std::list<std::string>& paramList)
{
  JsonSection result;
  BOOST_ASSERT(paramList.size() == 1);
  result.put(JSON_CODE, paramList.front());
  return result;
}

std::tuple<time::system_clock::TimePoint, std::string, int>
ChallengeEmail::parseStoredSecrets(const JsonSection& storedSecrets)
{
  auto tp = time::fromIsoString(storedSecrets.get<std::string>(JSON_CODE_TP));
  std::string rightCode= storedSecrets.get<std::string>(JSON_CODE);
  int attemptTimes = std::stoi(storedSecrets.get<std::string>(JSON_ATTEMPT_TIMES));

  return std::make_tuple(tp, rightCode, attemptTimes);
}

JsonSection
ChallengeEmail::generateStoredSecrets(const time::system_clock::TimePoint& tp,
                                    const std::string& secretCode, int attempTimes)
{
  JsonSection json;
  json.put(JSON_CODE_TP, time::toIsoString(tp));
  json.put(JSON_CODE, secretCode);
  json.put(JSON_ATTEMPT_TIMES, std::to_string(attempTimes));
  return json;
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
                          const std::string& caName) const
{
  std::string command = m_sendEmailScript;
  command += " \"" + emailAddress + "\" \"" + secret + "\" \"" + caName + "\"";
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
