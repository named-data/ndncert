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

#include "challenge.hpp"

namespace ndn {
namespace ndncert {

Block
CHALLENGE::encodeDataPayload(const RequestState& request)
{
  Block response = makeEmptyBlock(tlv_encrypted_payload);
  response.push_back(makeNonNegativeIntegerBlock(tlv_status, static_cast<size_t>(request.m_status)));
  response.push_back(makeStringBlock(tlv_challenge_status, request.m_challengeState->m_challengeStatus));
  response.push_back(makeNonNegativeIntegerBlock(tlv_remaining_tries, request.m_challengeState->m_remainingTries));
  response.push_back(makeNonNegativeIntegerBlock(tlv_remaining_time, request.m_challengeState->m_remainingTime.count()));
  response.encode();
  return response;
}

} // namespace ndncert
} // namespace ndn



