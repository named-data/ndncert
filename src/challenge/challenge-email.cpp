/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2017-2024, Regents of the University of California.
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

#include <ndn-cxx/util/logger.hpp>

#include <regex>
#include <boost/process.hpp>

namespace ndncert {

NDN_LOG_INIT(ndncert.challenge.email);
NDNCERT_REGISTER_CHALLENGE(ChallengeEmail, "email");

const std::string ChallengeEmail::NEED_CODE = "need-code";
const std::string ChallengeEmail::WRONG_CODE = "wrong-code";
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
ChallengeEmail::handleChallengeRequest(const Block& params, ca::RequestState& request)
{
  params.parse();
  auto currentTime = time::system_clock::now();

  if (request.status == Status::BEFORE_CHALLENGE) {
    // for the first time, init the challenge
    std::string emailAddress = readString(params.get(tlv::ParameterValue));
    auto lastComponentRequested = readString(request.cert.getIdentity().get(-1));
    if (lastComponentRequested != emailAddress) {
      NDN_LOG_TRACE("Email and requested name do not match: email=" << emailAddress
                    << " requested=" << lastComponentRequested);
    }
    std::string emailCode = generateSecretCode();
    JsonSection secretJson;
    secretJson.add(PARAMETER_KEY_CODE, emailCode);
    // send out the email
    sendEmail(emailAddress, emailCode, request);
    NDN_LOG_TRACE("Secret for request " << ndn::toHex(request.requestId) << " is " << emailCode);
    return returnWithNewChallengeStatus(request, NEED_CODE, std::move(secretJson),
                                        m_maxAttemptTimes, m_secretLifetime);
  }

  if (request.challengeState) {
    if (request.challengeState->challengeStatus == NEED_CODE ||
        request.challengeState->challengeStatus == WRONG_CODE) {
      NDN_LOG_TRACE("Challenge status: " << request.challengeState->challengeStatus);
      // the incoming interest should bring the pin code
      std::string givenCode = readString(params.get(tlv::ParameterValue));
      auto secret = request.challengeState->secrets;
      // check if run out of time
      if (currentTime - request.challengeState->timestamp >= m_secretLifetime) {
        NDN_LOG_TRACE("Secret expired");
        return returnWithError(request, ErrorCode::OUT_OF_TIME, "Secret expired.");
      }
      // check if provided secret is correct
      if (givenCode == secret.get<std::string>(PARAMETER_KEY_CODE)) {
        // the code is correct
        NDN_LOG_TRACE("Secret is correct, challenge succeeded");
        return returnWithSuccess(request);
      }
      // otherwise, check remaining attempt times
      if (request.challengeState->remainingTries > 1) {
        auto remainTime = m_secretLifetime - (currentTime - request.challengeState->timestamp);
        NDN_LOG_TRACE("Wrong secret, remaining tries = " << request.challengeState->remainingTries - 1);
        return returnWithNewChallengeStatus(request, WRONG_CODE, std::move(secret),
                                            request.challengeState->remainingTries - 1,
                                            time::duration_cast<time::seconds>(remainTime));
      }
      else {
        NDN_LOG_TRACE("Wrong secret, no tries remaining");
        return returnWithError(request, ErrorCode::OUT_OF_TRIES, "Ran out of tries.");
      }
    }
  }

  return returnWithError(request, ErrorCode::INVALID_PARAMETER, "Unexpected challenge status.");
}

// For Client
std::multimap<std::string, std::string>
ChallengeEmail::getRequestedParameterList(Status status, const std::string& challengeStatus)
{
  std::multimap<std::string, std::string> result;
  if (status == Status::BEFORE_CHALLENGE && challengeStatus.empty()) {
    result.emplace(PARAMETER_KEY_EMAIL, "Please input your email address");
  }
  else if (status == Status::CHALLENGE && challengeStatus == NEED_CODE) {
    result.emplace(PARAMETER_KEY_CODE, "Please input your verification code");
  }
  else if (status == Status::CHALLENGE && challengeStatus == WRONG_CODE) {
    result.emplace(PARAMETER_KEY_CODE, "Incorrect code, please try again");
  }
  else {
    NDN_THROW(std::runtime_error("Unexpected challenge status"));
  }
  return result;
}

Block
ChallengeEmail::genChallengeRequestTLV(Status status, const std::string& challengeStatus,
                                       const std::multimap<std::string, std::string>& params)
{
  Block request(tlv::EncryptedPayload);
  if (status == Status::BEFORE_CHALLENGE) {
    if (params.size() != 1 || params.find(PARAMETER_KEY_EMAIL) == params.end()) {
      NDN_THROW(std::runtime_error("Wrong parameter provided"));
    }
    request.push_back(ndn::makeStringBlock(tlv::SelectedChallenge, CHALLENGE_TYPE));
    request.push_back(ndn::makeStringBlock(tlv::ParameterKey, PARAMETER_KEY_EMAIL));
    request.push_back(ndn::makeStringBlock(tlv::ParameterValue, params.find(PARAMETER_KEY_EMAIL)->second));
  }
  else if (status == Status::CHALLENGE && (challengeStatus == NEED_CODE || challengeStatus == WRONG_CODE)) {
    if (params.size() != 1 || params.find(PARAMETER_KEY_CODE) == params.end()) {
      NDN_THROW(std::runtime_error("Wrong parameter provided"));
    }
    request.push_back(ndn::makeStringBlock(tlv::SelectedChallenge, CHALLENGE_TYPE));
    request.push_back(ndn::makeStringBlock(tlv::ParameterKey, PARAMETER_KEY_CODE));
    request.push_back(ndn::makeStringBlock(tlv::ParameterValue, params.find(PARAMETER_KEY_CODE)->second));
  }
  else {
    NDN_THROW(std::runtime_error("Unexpected challenge status"));
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
                          const ca::RequestState& request) const
{
  std::string command = m_sendEmailScript;
  command += " \"" + emailAddress + "\" \"" + secret + "\" \"" +
             request.caPrefix.toUri() + "\" \"" +
             request.cert.getName().toUri() + "\"";
  boost::process::child child(command);
  child.wait();
  if (child.exit_code() != 0) {
    NDN_LOG_ERROR("Email sending script " + m_sendEmailScript + " failed");
  }
  else {
    NDN_LOG_TRACE("Email sending script " + m_sendEmailScript + " succeeded");
  }
}

} // namespace ndncert
