/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2017-2022, Regents of the University of California.
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

#include "detail/request-encoder.hpp"

#include <ndn-cxx/security/transform/base64-encode.hpp>
#include <ndn-cxx/security/transform/buffer-source.hpp>
#include <ndn-cxx/security/transform/stream-sink.hpp>

namespace ndncert {

Block
requesttlv::encodeApplicationParameters(RequestType requestType,
                                        const std::vector<uint8_t>& ecdhPub,
                                        const Certificate& certRequest)
{
  Block request(ndn::tlv::ApplicationParameters);
  request.push_back(ndn::makeBinaryBlock(tlv::EcdhPub, ecdhPub));
  if (requestType == RequestType::NEW || requestType == RequestType::RENEW) {
    request.push_back(makeNestedBlock(tlv::CertRequest, certRequest));
  }
  else if (requestType == RequestType::REVOKE) {
    request.push_back(makeNestedBlock(tlv::CertToRevoke, certRequest));
  }
  request.encode();
  return request;
}

void
requesttlv::decodeApplicationParameters(const Block& payload, RequestType requestType,
                                        std::vector<uint8_t>& ecdhPub,
                                        std::shared_ptr<Certificate>& clientCert)
{
  payload.parse();

  int ecdhPubCount = 0;
  Block requestPayload;
  int requestPayloadCount = 0;
  for (const auto &item : payload.elements()) {
    if (item.type() == tlv::EcdhPub) {
      ecdhPub.resize(item.value_size());
      std::memcpy(ecdhPub.data(), item.value(), item.value_size());
      ecdhPubCount++;
    }
    else if ((requestType == RequestType::NEW && item.type() == tlv::CertRequest) ||
               (requestType == RequestType::REVOKE && item.type() == tlv::CertToRevoke)) {
      requestPayload = item;
      requestPayloadCount++;
      requestPayload.parse();
      clientCert = std::make_shared<Certificate>(requestPayload.get(ndn::tlv::Data));
    }
    else if (ndn::tlv::isCriticalType(item.type())) {
      NDN_THROW(std::runtime_error("Unrecognized TLV Type: " + std::to_string(item.type())));
    }
    else {
      //ignore
    }
  }

  if (ecdhPubCount != 1 || requestPayloadCount != 1) {
    NDN_THROW(std::runtime_error("Error TLV contains " + std::to_string(ecdhPubCount) + " ecdh public param(s) and " +
                                 std::to_string(requestPayloadCount) +
                                 "request payload(s), instead of expected 1 times each."));
  }
}

Block
requesttlv::encodeDataContent(const std::vector<uint8_t>& ecdhKey,
                              const std::array<uint8_t, 32>& salt,
                              const RequestId& requestId,
                              const std::vector<std::string>& challenges)
{
  Block response(ndn::tlv::Content);
  response.push_back(ndn::makeBinaryBlock(tlv::EcdhPub, ecdhKey));
  response.push_back(ndn::makeBinaryBlock(tlv::Salt, salt));
  response.push_back(ndn::makeBinaryBlock(tlv::RequestId, requestId));
  for (const auto& entry: challenges) {
    response.push_back(ndn::makeStringBlock(tlv::Challenge, entry));
  }
  response.encode();
  return response;
}

std::list <std::string>
requesttlv::decodeDataContent(const Block& content, std::vector <uint8_t>& ecdhKey,
                              std::array<uint8_t, 32>& salt, RequestId& requestId) {
  std::list<std::string> challenges;
  content.parse();
  int ecdhPubCount = 0, saltCount = 0, requestIdCount = 0;
  for (auto const &element : content.elements()) {
    if (element.type() == tlv::Challenge) {
      challenges.push_back(readString(element));
    }
    else if (element.type() == tlv::EcdhPub) {
      ecdhKey.resize(element.value_size());
      std::memcpy(ecdhKey.data(), element.value(), element.value_size());
      ecdhPubCount++;
    }
    else if (element.type() == tlv::Salt) {
      std::memcpy(salt.data(), element.value(), element.value_size());
      saltCount++;
    }
    else if (element.type() == tlv::RequestId) {
      std::memcpy(requestId.data(), element.value(), element.value_size());
      requestIdCount++;
    }
    else if (ndn::tlv::isCriticalType(element.type())) {
      NDN_THROW(std::runtime_error("Unrecognized TLV Type: " + std::to_string(element.type())));
    }
    else {
      //ignore
    }
  }
  if (ecdhPubCount != 1 || saltCount != 1 || requestIdCount != 1) {
    NDN_THROW(std::runtime_error("Error TLV contains " + std::to_string(ecdhPubCount) + " ecdh public param(s), " +
                                 std::to_string(saltCount) + " salt(s) and " + std::to_string(requestIdCount) +
                                 "request id(s), instead of expected 1 times each."));
  }
  return challenges;
}

} // namespace ndncert
