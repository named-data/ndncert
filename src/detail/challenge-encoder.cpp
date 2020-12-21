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

#include "detail/challenge-encoder.hpp"

namespace ndn {
namespace ndncert {

Block
challengetlv::encodeDataContent(ca::RequestState& request, const Name& issuedCertName)
{
  Block response(tlv::EncryptedPayload);
  response.push_back(makeNonNegativeIntegerBlock(tlv::Status, static_cast<uint64_t>(request.status)));
  if (request.challengeState) {
    response.push_back(makeStringBlock(tlv::ChallengeStatus, request.challengeState->challengeStatus));
    response.push_back(
        makeNonNegativeIntegerBlock(tlv::RemainingTries, request.challengeState->remainingTries));
    response.push_back(
        makeNonNegativeIntegerBlock(tlv::RemainingTime, request.challengeState->remainingTime.count()));
    if (request.challengeState->challengeStatus == "need-proof") {
      response.push_back(
              makeStringBlock(tlv::ParameterKey, "nonce")
              );
      auto nonce = fromHex(request.challengeState->secrets.get("nonce", ""));
      response.push_back(
              makeBinaryBlock(tlv::ParameterValue, nonce->data(), 16)
            );
    }
  }
  if (!issuedCertName.empty()) {
    response.push_back(makeNestedBlock(tlv::IssuedCertName, issuedCertName));
  }
  response.encode();
  return encodeBlockWithAesGcm128(ndn::tlv::Content, request.encryptionKey.data(),
                                  response.value(), response.value_size(),
                                  request.requestId.data(), request.requestId.size(), request.aesBlockCounter);
}

void
challengetlv::decodeDataContent(const Block& contentBlock, requester::RequestState& state)
{
  auto result = decodeBlockWithAesGcm128(contentBlock, state.aesKey.data(),
                                         state.requestId.data(), state.requestId.size());
  auto data = makeBinaryBlock(tlv::EncryptedPayload, result.data(), result.size());
  data.parse();
  state.status = statusFromBlock(data.get(tlv::Status));
  if (data.find(tlv::ChallengeStatus) != data.elements_end()) {
    state.challengeStatus = readString(data.get(tlv::ChallengeStatus));
  }
  if (data.find(tlv::RemainingTries) != data.elements_end()) {
    state.remainingTries = readNonNegativeInteger(data.get(tlv::RemainingTries));
  }
  if (data.find(tlv::RemainingTime) != data.elements_end()) {
    state.freshBefore = time::system_clock::now() + time::seconds(readNonNegativeInteger(data.get(tlv::RemainingTime)));
  }
  if (data.find(tlv::IssuedCertName) != data.elements_end()) {
    Block issuedCertNameBlock = data.get(tlv::IssuedCertName);
    state.issuedCertName = Name(issuedCertNameBlock.blockFromValue());
  }
  if (data.find(tlv::ParameterKey) != data.elements_end() && readString(data.get(tlv::ParameterKey)) == "nonce") {
    if (data.find(tlv::ParameterKey) == data.elements_end()) {
        NDN_THROW(std::runtime_error("Parameter Key found, but no value found"));
    }
    Block nonceBlock = data.get(tlv::ParameterValue);
    if (nonceBlock.value_size() != 16) {
        NDN_THROW(std::runtime_error("Wrong nonce length"));
    }
    memcpy(state.nonce.data(), nonceBlock.value(), 16);
  }
}

} // namespace ndncert
} // namespace ndn
