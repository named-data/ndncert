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
ChallengeEncoder::encodeDataContent(ca::RequestState& request, optional<Name> issuedCertName)
{
  Block response = makeEmptyBlock(tlv::EncryptedPayload);
  response.push_back(makeNonNegativeIntegerBlock(tlv::Status, static_cast<size_t>(request.m_status)));
  if (request.m_challengeState) {
    response.push_back(makeStringBlock(tlv::ChallengeStatus, request.m_challengeState->m_challengeStatus));
    response.push_back(
        makeNonNegativeIntegerBlock(tlv::RemainingTries, request.m_challengeState->m_remainingTries));
    response.push_back(
        makeNonNegativeIntegerBlock(tlv::RemainingTime, request.m_challengeState->m_remainingTime.count()));
  }
  if (issuedCertName.has_value()) {
    response.push_back(makeNestedBlock(tlv::IssuedCertName, *issuedCertName));
  }
  response.encode();
  return encodeBlockWithAesGcm128(ndn::tlv::Content, request.m_encryptionKey.value(),
                                  response.value(), response.value_size(),
                                  request.m_requestId.data(), request.m_requestId.size(), request.m_aesBlockCounter);
}

void
ChallengeEncoder::decodeDataContent(const Block& contentBlock, requester::RequestContext& state)
{
  auto result = decodeBlockWithAesGcm128(contentBlock, state.m_aesKey,
                                         state.m_requestId.data(), state.m_requestId.size());
  auto data = makeBinaryBlock(tlv::EncryptedPayload, result.data(), result.size());
  data.parse();
  state.m_status = static_cast<Status>(readNonNegativeInteger(data.get(tlv::Status)));
  if (data.find(tlv::ChallengeStatus) != data.elements_end()) {
    state.m_challengeStatus = readString(data.get(tlv::ChallengeStatus));
  }
  if (data.find(tlv::RemainingTries) != data.elements_end()) {
    state.m_remainingTries = readNonNegativeInteger(data.get(tlv::RemainingTries));
  }
  if (data.find(tlv::RemainingTime) != data.elements_end()) {
    state.m_freshBefore = time::system_clock::now() + time::seconds(readNonNegativeInteger(data.get(tlv::RemainingTime)));
  }
  if (data.find(tlv::IssuedCertName) != data.elements_end()) {
    Block issuedCertNameBlock = data.get(tlv::IssuedCertName);
    state.m_issuedCertName = Name(issuedCertNameBlock.blockFromValue());
  }
}

} // namespace ndncert
} // namespace ndn
