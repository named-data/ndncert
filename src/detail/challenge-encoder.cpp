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

#include "detail/challenge-encoder.hpp"

namespace ndncert::challengetlv {

Block
encodeDataContent(ca::RequestState& request, const Name& issuedCertName, const Name& forwardingHint)
{
  Block response(tlv::EncryptedPayload);
  response.push_back(ndn::makeNonNegativeIntegerBlock(tlv::Status, static_cast<uint64_t>(request.status)));
  if (request.challengeState) {
    response.push_back(ndn::makeStringBlock(tlv::ChallengeStatus, request.challengeState->challengeStatus));
    response.push_back(ndn::makeNonNegativeIntegerBlock(tlv::RemainingTries,
                                                        request.challengeState->remainingTries));
    response.push_back(ndn::makeNonNegativeIntegerBlock(tlv::RemainingTime,
                                                        request.challengeState->remainingTime.count()));
    if (request.challengeState->challengeStatus == "need-proof") {
      response.push_back(ndn::makeStringBlock(tlv::ParameterKey, "nonce"));
      auto nonce = ndn::fromHex(request.challengeState->secrets.get("nonce", ""));
      response.push_back(ndn::makeBinaryBlock(tlv::ParameterValue, *nonce));
    }
    else if (request.challengeState->challengeStatus == "need-record") {
      // Include DNS record information for DNS challenges
      std::string recordName = request.challengeState->secrets.get("record-name", "");
      std::string expectedValue = request.challengeState->secrets.get("expected-value", "");
      
      if (!recordName.empty()) {
        response.push_back(ndn::makeStringBlock(tlv::ParameterKey, "record-name"));
        response.push_back(ndn::makeStringBlock(tlv::ParameterValue, recordName));
      }
      if (!expectedValue.empty()) {
        response.push_back(ndn::makeStringBlock(tlv::ParameterKey, "expected-value"));
        response.push_back(ndn::makeStringBlock(tlv::ParameterValue, expectedValue));
      }
    }
  }
  if (!issuedCertName.empty()) {
    response.push_back(makeNestedBlock(tlv::IssuedCertName, issuedCertName));
    response.push_back(makeNestedBlock(ndn::tlv::ForwardingHint, forwardingHint));
  }
  response.encode();

  return encodeBlockWithAesGcm128(ndn::tlv::Content, request.encryptionKey.data(),
                                  response.value(), response.value_size(),
                                  request.requestId.data(), request.requestId.size(),
                                  request.encryptionIv);
}

void
decodeDataContent(const Block& contentBlock, requester::Request& state)
{
  auto result = decodeBlockWithAesGcm128(contentBlock, state.m_aesKey.data(),
                                         state.m_requestId.data(), state.m_requestId.size(),
                                         state.m_decryptionIv, state.m_encryptionIv);
  auto data = ndn::makeBinaryBlock(tlv::EncryptedPayload, result);
  data.parse();

  int numStatus = 0;
  std::string currentParameterKey;
  for (const auto &item : data.elements()) {
    if (currentParameterKey.empty()) {
      switch (item.type()) {
        case tlv::Status:
          state.m_status = statusFromBlock(data.get(tlv::Status));
          numStatus++;
          break;
        case tlv::ChallengeStatus:
          state.m_challengeStatus = readString(item);
          break;
        case tlv::RemainingTries:
          state.m_remainingTries = readNonNegativeInteger(item);
          break;
        case tlv::RemainingTime:
          state.m_freshBefore = time::system_clock::now() +
                                time::seconds(readNonNegativeInteger(item));
          break;
        case tlv::IssuedCertName:
          state.m_issuedCertName = Name(item.blockFromValue());
          break;
        case ndn::tlv::ForwardingHint:
          state.m_forwardingHint = Name(item.blockFromValue());
          break;
        case tlv::ParameterKey:
          currentParameterKey = readString(item);
          break;
        default:
          if (ndn::tlv::isCriticalType(item.type())) {
            NDN_THROW(std::runtime_error("Unrecognized TLV Type: " + std::to_string(item.type())));
          }
          else {
            //ignore
          }
          break;
      }
    }
    else {
      if (item.type() == tlv::ParameterValue) {
        if (currentParameterKey == "nonce") {
          if (item.value_size() != 16) {
            NDN_THROW(std::runtime_error("Wrong nonce length"));
          }
          memcpy(state.m_nonce.data(), item.value(), 16);
        }
        else if (currentParameterKey == "record-name") {
          state.m_dnsRecordName = readString(item);
        }
        else if (currentParameterKey == "expected-value") {
          state.m_dnsExpectedValue = readString(item);
        }
        else {
          NDN_THROW(std::runtime_error("Unknown Parameter: " + currentParameterKey));
        }
        currentParameterKey.clear(); // Reset for next parameter
      }
      else {
        NDN_THROW(std::runtime_error("Parameter Key found, but no value found"));
      }
    }
  }
  if (numStatus != 1) {
    NDN_THROW(std::runtime_error("number of status block is not equal to 1; there are " +
                                 std::to_string(numStatus) + " status blocks"));
  }
}

} // namespace ndncert::challengetlv
