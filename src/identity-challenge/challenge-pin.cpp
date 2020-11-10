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

#include "challenge-pin.hpp"
#include <ndn-cxx/util/random.hpp>

namespace ndn {
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
  if (request.m_status == Status::BEFORE_CHALLENGE) {
    NDN_LOG_TRACE("Challenge Interest arrives. Init the challenge");
    // for the first time, init the challenge
    std::string secretCode = generateSecretCode();
    JsonSection secretJson;
    secretJson.add(PARAMETER_KEY_CODE, secretCode);
    NDN_LOG_TRACE("Secret for request " << toHex(request.m_requestId.data(), request.m_requestId.size()) << " : " << secretCode);
    return returnWithNewChallengeStatus(request, NEED_CODE, std::move(secretJson), m_maxAttemptTimes, m_secretLifetime);
  }
  if (request.m_challengeState) {
    if (request.m_challengeState->m_challengeStatus == NEED_CODE ||
        request.m_challengeState->m_challengeStatus == WRONG_CODE) {
      NDN_LOG_TRACE("Challenge Interest arrives. Challenge Status: " << request.m_challengeState->m_challengeStatus);
      // the incoming interest should bring the pin code
      std::string givenCode = readString(params.get(tlv::ParameterValue));
      auto secret = request.m_challengeState->m_secrets;
      if (currentTime - request.m_challengeState->m_timestamp >= m_secretLifetime) {
        return returnWithError(request, ErrorCode::OUT_OF_TIME, "Secret expired.");
      }
      if (givenCode == secret.get<std::string>(PARAMETER_KEY_CODE)) {
        NDN_LOG_TRACE("Correct PIN code. Challenge succeeded.");
        return returnWithSuccess(request);
      }
      // check rest attempt times
      if (request.m_challengeState->m_remainingTries > 1) {
        auto remainTime = m_secretLifetime - (currentTime - request.m_challengeState->m_timestamp);
        NDN_LOG_TRACE("Wrong PIN code provided. Remaining Tries - 1.");
        return returnWithNewChallengeStatus(request, WRONG_CODE, std::move(secret),
                                            request.m_challengeState->m_remainingTries - 1,
                                            time::duration_cast<time::seconds>(remainTime));
      }
      else {
        // run out times
        NDN_LOG_TRACE("Wrong PIN code provided. Ran out tires. Challenge failed.");
        return returnWithError(request, ErrorCode::OUT_OF_TRIES, "Ran out tires.");
      }
    }
  }
  return returnWithError(request, ErrorCode::INVALID_PARAMETER, "Unexpected status or challenge status");
}

// For Client
std::vector<std::tuple<std::string, std::string>>
ChallengePin::getRequestedParameterList(Status status, const std::string& challengeStatus)
{
  std::vector<std::tuple<std::string, std::string>> result;
  if (status == Status::BEFORE_CHALLENGE) {
    // do nothing
  }
  else if (status == Status::CHALLENGE && challengeStatus == NEED_CODE) {
    result.push_back(std::make_tuple(PARAMETER_KEY_CODE, "Please input your PIN code"));
  }
  else if (status == Status::CHALLENGE && challengeStatus == WRONG_CODE) {
    result.push_back(std::make_tuple(PARAMETER_KEY_CODE, "Incorrect PIN code, please try again"));
  }
  else {
    NDN_THROW(std::runtime_error("Unexpected status or challenge status."));
  }
  return result;
}

Block
ChallengePin::genChallengeRequestTLV(Status status, const std::string& challengeStatus,
                                     std::vector<std::tuple<std::string, std::string>>&& params)
{
  Block request(tlv::EncryptedPayload);
  if (status == Status::BEFORE_CHALLENGE) {
    request.push_back(makeStringBlock(tlv::SelectedChallenge, CHALLENGE_TYPE));
  }
  else if (status == Status::CHALLENGE && (challengeStatus == NEED_CODE || challengeStatus == WRONG_CODE)) {
    if (params.size() != 1 || std::get<0>(params[0]) != PARAMETER_KEY_CODE) {
      NDN_THROW(std::runtime_error("Wrong parameter provided."));
    }
    request.push_back(makeStringBlock(tlv::SelectedChallenge, CHALLENGE_TYPE));
    request.push_back(makeStringBlock(tlv::ParameterKey, PARAMETER_KEY_CODE));
    request.push_back(makeStringBlock(tlv::ParameterValue, std::get<1>(params[0])));
  }
  else {
    NDN_THROW(std::runtime_error("Unexpected status or challenge status."));
  }
  request.encode();
  return request;
}
} // namespace ndncert
} // namespace ndn
