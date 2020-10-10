/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
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

#include "challenge-email.hpp"
#include <regex>

namespace ndn {
namespace ndncert {

_LOG_INIT(ndncert.challenge.email);
NDNCERT_REGISTER_CHALLENGE(ChallengeEmail, "email");

const std::string ChallengeEmail::NEED_CODE = "need-code";
const std::string ChallengeEmail::WRONG_CODE = "wrong-code";
const std::string ChallengeEmail::INVALID_EMAIL = "invalid-email";
const std::string ChallengeEmail::PARAMETER_KEY_EMAIL = "email";
const std::string ChallengeEmail::PARAMETER_KEY_CODE = "code";

ChallengeEmail::ChallengeEmail(const std::string& scriptPath,
                               const size_t& maxAttemptTimes,
                               const time::seconds secretLifetime)
    : ChallengeModule("email", maxAttemptTimes, secretLifetime)
    , m_sendEmailScript(scriptPath)
{
}

// For CA
std::tuple<ErrorCode, std::string>
ChallengeEmail::handleChallengeRequest(const Block& params, CaState& request)
{
  params.parse();
  auto currentTime = time::system_clock::now();
  if (request.m_status == Status::BEFORE_CHALLENGE) {
    // for the first time, init the challenge
    std::string emailAddress = readString(params.get(tlv_parameter_value));
    if (!isValidEmailAddress(emailAddress)) {
      return returnWithNewChallengeStatus(request, INVALID_EMAIL, JsonSection(), m_maxAttemptTimes - 1, m_secretLifetime);
    }
    auto lastComponentRequested = readString(request.m_cert.getIdentity().get(-1));
    if (lastComponentRequested != emailAddress) {
      _LOG_TRACE("Email and requested name do not match. Email " << emailAddress << "requested last component " << lastComponentRequested);
    }
    std::string emailCode = generateSecretCode();
    JsonSection secretJson;
    secretJson.add(PARAMETER_KEY_CODE, emailCode);
    // send out the email
    sendEmail(emailAddress, emailCode, request);
    _LOG_TRACE("Secret for request " << request.m_requestId << " : " << emailCode);
    return returnWithNewChallengeStatus(request, NEED_CODE, std::move(secretJson), m_maxAttemptTimes, m_secretLifetime);
  }
  if (request.m_challengeState) {
    if (request.m_challengeState->m_challengeStatus == NEED_CODE ||
        request.m_challengeState->m_challengeStatus == WRONG_CODE) {
      _LOG_TRACE("Challenge Interest arrives. Challenge Status: " << request.m_challengeState->m_challengeStatus);
      // the incoming interest should bring the pin code
      std::string givenCode = readString(params.get(tlv_parameter_value));
      auto secret = request.m_challengeState->m_secrets;
      // check if run out of time
      if (currentTime - request.m_challengeState->m_timestamp >= m_secretLifetime) {
        return returnWithError(request, ErrorCode::OUT_OF_TIME, "Secret expired.");
      }
      // check if provided secret is correct
      if (givenCode == secret.get<std::string>(PARAMETER_KEY_CODE)) {
        // the code is correct
        _LOG_TRACE("Correct secret code. Challenge succeeded.");
        return returnWithSuccess(request);
      }
      // otherwise, check remaining attempt times
      if (request.m_challengeState->m_remainingTries > 1) {
        auto remainTime = m_secretLifetime - (currentTime - request.m_challengeState->m_timestamp);
        _LOG_TRACE("Wrong secret code provided. Remaining Tries - 1.");
        return returnWithNewChallengeStatus(request, WRONG_CODE, std::move(secret),
                                            request.m_challengeState->m_remainingTries - 1,
                                            time::duration_cast<time::seconds>(remainTime));
      }
      else {
        // run out times
        _LOG_TRACE("Wrong secret code provided. Ran out tires. Challenge failed.");
        return returnWithError(request, ErrorCode::OUT_OF_TRIES, "Ran out tires.");
      }
    }
  }
  return returnWithError(request, ErrorCode::INVALID_PARAMETER, "Unexpected status or challenge status");
}

// For Client
std::vector<std::tuple<std::string, std::string>>
ChallengeEmail::getRequestedParameterList(Status status, const std::string& challengeStatus)
{
  std::vector<std::tuple<std::string, std::string>> result;
  if (status == Status::BEFORE_CHALLENGE && challengeStatus == "") {
    result.push_back(std::make_tuple(PARAMETER_KEY_EMAIL, "Please input your email address"));
  }
  else if (status == Status::CHALLENGE && challengeStatus == NEED_CODE) {
    result.push_back(std::make_tuple(PARAMETER_KEY_CODE, "Please input your verification code"));
  }
  else if (status == Status::CHALLENGE && challengeStatus == WRONG_CODE) {
    result.push_back(std::make_tuple(PARAMETER_KEY_CODE, "Incorrect code, please try again"));
  }
  else {
    BOOST_THROW_EXCEPTION(std::runtime_error("Unexpected status or challenge status."));
  }
  return result;
}

Block
ChallengeEmail::genChallengeRequestTLV(Status status, const std::string& challengeStatus, std::vector<std::tuple<std::string, std::string>>&& params)
{
  Block request = makeEmptyBlock(tlv_encrypted_payload);
  if (status == Status::BEFORE_CHALLENGE) {
    if (params.size() != 1 || std::get<0>(params[0]) != PARAMETER_KEY_EMAIL) {
      BOOST_THROW_EXCEPTION(std::runtime_error("Wrong parameter provided."));
    }
    request.push_back(makeStringBlock(tlv_selected_challenge, CHALLENGE_TYPE));
    request.push_back(makeStringBlock(tlv_parameter_key, PARAMETER_KEY_EMAIL));
    request.push_back(makeStringBlock(tlv_parameter_value, std::get<1>(params[0])));
  }
  else if (status == Status::CHALLENGE && (challengeStatus == NEED_CODE || challengeStatus == WRONG_CODE)) {
    if (params.size() != 1 || std::get<0>(params[0]) != PARAMETER_KEY_CODE) {
      BOOST_THROW_EXCEPTION(std::runtime_error("Wrong parameter provided."));
    }
    request.push_back(makeStringBlock(tlv_selected_challenge, CHALLENGE_TYPE));
    request.push_back(makeStringBlock(tlv_parameter_key, PARAMETER_KEY_CODE));
    request.push_back(makeStringBlock(tlv_parameter_value, std::get<1>(params[0])));
  }
  else {
    BOOST_THROW_EXCEPTION(std::runtime_error("Unexpected status or challenge status."));
  }
  request.encode();
  return request;
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
                          const CaState& request) const
{
  std::string command = m_sendEmailScript;
  command += " \"" + emailAddress + "\" \"" + secret + "\" \"" + request.m_caPrefix.toUri() + "\" \"" + request.m_cert.getName().toUri() + "\"";
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
