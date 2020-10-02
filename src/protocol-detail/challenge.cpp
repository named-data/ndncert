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

CHALLENGE::DecodedData
CHALLENGE::decodeDataPayload(const Block& data){
    data.parse();
    Status status = static_cast<Status>(readNonNegativeInteger(data.get(tlv_status)));
    std::string challengeStatus = readString(data.get(tlv_challenge_status));
    size_t remainingTries = readNonNegativeInteger(data.get(tlv_remaining_tries));
    time::seconds remainingTime = time::seconds(readNonNegativeInteger(data.get(tlv_remaining_time)));

    if (data.find(tlv_issued_cert_name) != data.elements_end()) {
        Block issuedCertNameBlock = data.get(tlv_issued_cert_name);
        issuedCertNameBlock.parse();
        return DecodedData{status, challengeStatus, remainingTries, remainingTime, Name(issuedCertNameBlock.get(tlv::Name))};
    }

    return DecodedData{status, challengeStatus, remainingTries, remainingTime, nullopt};
}

} // namespace ndncert
} // namespace ndn



