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

#include "challenge-pin.hpp"

#include <ndn-cxx/util/logger.hpp>
#include <ndn-cxx/util/random.hpp>

namespace ndncert {

NDN_LOG_INIT(ndncert.challenge.pin);
NDNCERT_REGISTER_CHALLENGE(ChallengePin, "pin");

const std::string ChallengePin::NEED_CODE = "need-code";
const std::string ChallengePin::WRONG_CODE = "wrong-code";
const std::string ChallengePin::PARAMETER_KEY_CODE = "code";

ChallengePin::ChallengePin(const size_t& maxAttemptTimes, const time::seconds& secretLifetime)
  : ChallengeModule("pin", maxAttemptTimes, secretLifetime)
{
}

// For CA
std::tuple<ErrorCode, std::string>
ChallengePin::handleChallengeRequest(const Block& params, ca::RequestState& request)
{
  params.parse();
  auto currentTime = time::system_clock::now();

  if (request.status == Status::BEFORE_CHALLENGE) {
    NDN_LOG_TRACE("Begin challenge");
    // for the first time, init the challenge
    std::string secretCode = generateSecretCode();
    JsonSection secretJson;
    secretJson.add(PARAMETER_KEY_CODE, secretCode);
    NDN_LOG_TRACE("Secret for request " << ndn::toHex(request.requestId) << " is " << secretCode);
    return returnWithNewChallengeStatus(request, NEED_CODE, std::move(secretJson), m_maxAttemptTimes,
                                        m_secretLifetime);
  }

  if (request.challengeState) {
    if (request.challengeState->challengeStatus == NEED_CODE ||
        request.challengeState->challengeStatus == WRONG_CODE) {
      NDN_LOG_TRACE("Challenge status: " << request.challengeState->challengeStatus);
      // the incoming interest should bring the pin code
      std::string givenCode = readString(params.get(tlv::ParameterValue));
      auto secret = request.challengeState->secrets;
      if (currentTime - request.challengeState->timestamp >= m_secretLifetime) {
        NDN_LOG_TRACE("Secret expired");
        return returnWithError(request, ErrorCode::OUT_OF_TIME, "Secret expired.");
      }
      if (givenCode == secret.get<std::string>(PARAMETER_KEY_CODE)) {
        NDN_LOG_TRACE("PIN is correct, challenge succeeded");
        return returnWithSuccess(request);
      }
      // check rest attempt times
      if (request.challengeState->remainingTries > 1) {
        auto remainTime = m_secretLifetime - (currentTime - request.challengeState->timestamp);
        NDN_LOG_TRACE("Wrong PIN, remaining tries = " << request.challengeState->remainingTries - 1);
        return returnWithNewChallengeStatus(request, WRONG_CODE, std::move(secret),
                                            request.challengeState->remainingTries - 1,
                                            time::duration_cast<time::seconds>(remainTime));
      }
      else {
        NDN_LOG_TRACE("Wrong PIN, no tries remaining");
        return returnWithError(request, ErrorCode::OUT_OF_TRIES, "Ran out of tries.");
      }
    }
  }

  return returnWithError(request, ErrorCode::INVALID_PARAMETER, "Unexpected challenge status.");
}

// For Client
std::multimap<std::string, std::string>
ChallengePin::getRequestedParameterList(Status status, const std::string& challengeStatus)
{
  std::multimap<std::string, std::string> result;
  if (status == Status::BEFORE_CHALLENGE) {
    // do nothing
  }
  else if (status == Status::CHALLENGE && challengeStatus == NEED_CODE) {
    result.emplace(PARAMETER_KEY_CODE, "Please input your PIN code");
  }
  else if (status == Status::CHALLENGE && challengeStatus == WRONG_CODE) {
    result.emplace(PARAMETER_KEY_CODE, "Incorrect PIN code, please try again");
  }
  else {
    NDN_THROW(std::runtime_error("Unexpected challenge status"));
  }
  return result;
}

Block
ChallengePin::genChallengeRequestTLV(Status status, const std::string& challengeStatus,
                                     const std::multimap<std::string, std::string>& params)
{
  Block request(tlv::EncryptedPayload);
  if (status == Status::BEFORE_CHALLENGE) {
    request.push_back(ndn::makeStringBlock(tlv::SelectedChallenge, CHALLENGE_TYPE));
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

} // namespace ndncert
