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

#include "challenge-pin.hpp"
#include "logging.hpp"
#include <ndn-cxx/util/random.hpp>

namespace ndn {
namespace ndncert {

_LOG_INIT(ndncert.challenge-pin);

NDNCERT_REGISTER_CHALLENGE(ChallengePin, "pin");

const std::string ChallengePin::NEED_CODE = "need-code";
const std::string ChallengePin::WRONG_CODE = "wrong-code";
const std::string ChallengePin::JSON_PIN_CODE = "pin-code";

ChallengePin::ChallengePin(const size_t& maxAttemptTimes, const time::seconds& secretLifetime)
  : ChallengeModule("pin")
  , m_secretLifetime(secretLifetime)
  , m_maxAttemptTimes(maxAttemptTimes)
{
}

// For CA
void
ChallengePin::handleChallengeRequest(const JsonSection& params, CertificateRequest& request)
{
  auto currentTime = time::system_clock::now();
  if (request.m_challengeStatus == "") {
    _LOG_TRACE("Challenge Interest arrives. Init the challenge");
    // for the first time, init the challenge
    request.m_status = STATUS_CHALLENGE;
    request.m_challengeStatus = NEED_CODE;
    request.m_challengeType = CHALLENGE_TYPE;
    std::string secretCode = generateSecretCode();
    JsonSection secretJson;
    secretJson.add(JSON_PIN_CODE, secretCode);
    request.m_challengeSecrets = secretJson;
    request.m_challengeTp = time::toIsoString(currentTime);
    request.m_remainingTime = m_secretLifetime.count();
    request.m_remainingTries = m_maxAttemptTimes;
    _LOG_TRACE("Secret for request " << request.m_requestId << " : " << secretCode);
    return;
  }
  else if (request.m_challengeStatus == NEED_CODE || request.m_challengeStatus == WRONG_CODE) {
    _LOG_TRACE("Challenge Interest arrives. Challenge Status: " << request.m_challengeStatus);
    // the incoming interest should bring the pin code
    std::string givenCode = params.get(JSON_PIN_CODE, "");
    const auto realCode = request.m_challengeSecrets.get<std::string>(JSON_PIN_CODE);
    if (currentTime - time::fromIsoString(request.m_challengeTp) >= m_secretLifetime) {
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
      _LOG_TRACE("PIN code matched. Challenge succeeded.");
      return;
    }
    else {
      // check rest attempt times
      if (request.m_remainingTries > 1) {
        request.m_challengeStatus = WRONG_CODE;
        request.m_remainingTries = request.m_remainingTries - 1;
        auto remainTime = m_secretLifetime - (currentTime - time::fromIsoString(request.m_challengeTp));
        request.m_remainingTime = remainTime.count();
        _LOG_TRACE("PIN code didn't match. Remaining Tries - 1.");
        return;
      }
      else {
        // run out times
        request.m_status = STATUS_FAILURE;
        request.m_challengeStatus = CHALLENGE_STATUS_FAILURE_MAXRETRY;
        updateRequestOnChallengeEnd(request);
        _LOG_TRACE("PIN code didn't match. Ran out tires. Challenge failed.");
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
ChallengePin::getRequirementForChallenge(int status, const std::string& challengeStatus)
{
  JsonSection result;
  if (status == STATUS_BEFORE_CHALLENGE && challengeStatus == "") {
    // do nothing
  }
  else if (status == STATUS_CHALLENGE && challengeStatus == NEED_CODE) {
    result.put(JSON_PIN_CODE, "Please_input_your_verification_code");
  }
  else if (status == STATUS_CHALLENGE && challengeStatus == WRONG_CODE) {
    result.put(JSON_PIN_CODE, "Incorrect_PIN_code_please_try_again");
  }
  else {
    _LOG_ERROR("Client's status and challenge status are wrong");
  }
  return result;
}

JsonSection
ChallengePin::genChallengeRequestJson(int status, const std::string& challengeStatus, const JsonSection& params)
{
  JsonSection result;
  if (status == STATUS_BEFORE_CHALLENGE && challengeStatus == "") {
    // do nothing
    result.put(JSON_CLIENT_SELECTED_CHALLENGE, CHALLENGE_TYPE);
  }
  else if (status == STATUS_CHALLENGE && challengeStatus == NEED_CODE) {
    result.put(JSON_CLIENT_SELECTED_CHALLENGE, CHALLENGE_TYPE);
    result.put(JSON_PIN_CODE, params.get(JSON_PIN_CODE, ""));
  }
  else if (status == STATUS_CHALLENGE && challengeStatus == WRONG_CODE) {
    result.put(JSON_CLIENT_SELECTED_CHALLENGE, CHALLENGE_TYPE);
    result.put(JSON_PIN_CODE, params.get(JSON_PIN_CODE, ""));
  }
  else {
    _LOG_ERROR("Client's status and challenge status are wrong");
  }
  return result;
}

} // namespace ndncert
} // namespace ndn
