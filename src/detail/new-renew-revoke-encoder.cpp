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

#include "new-renew-revoke-encoder.hpp"
#include <ndn-cxx/security/transform/base64-encode.hpp>
#include <ndn-cxx/security/transform/buffer-source.hpp>
#include <ndn-cxx/security/transform/stream-sink.hpp>

namespace ndn {
namespace ndncert {

NDN_LOG_INIT(ndncert.encoding.new_renew_revoke);

Block
NewRenewRevokeEncoder::encodeApplicationParameters(RequestType requestType, const std::string& ecdhPub, const security::Certificate& certRequest)
{
  Block request = makeEmptyBlock(ndn::tlv::ApplicationParameters);
  std::stringstream ss;
  try {
    security::transform::bufferSource(certRequest.wireEncode().wire(), certRequest.wireEncode().size())
    >> security::transform::base64Encode(false)
    >> security::transform::streamSink(ss);
  }
  catch (const security::transform::Error& e) {
    NDN_LOG_ERROR("Cannot convert self-signed cert into BASE64 string " << e.what());
    return request;
  }

  request.push_back(makeStringBlock(tlv::EcdhPub, ecdhPub));
  if (requestType == RequestType::NEW || requestType == RequestType::RENEW) {
    request.push_back(makeNestedBlock(tlv::CertRequest, certRequest));
  } else if (requestType == RequestType::REVOKE) {
    request.push_back(makeNestedBlock(tlv::CertToRevoke, certRequest));
  }
  request.encode();
  return request;
}

void
NewRenewRevokeEncoder::decodeApplicationParameters(const Block& payload, RequestType requestType, std::string& ecdhPub,
                                              shared_ptr<security::Certificate>& clientCert) {
  payload.parse();

  ecdhPub = readString(payload.get(tlv::EcdhPub));
  Block requestPayload;
  if (requestType == RequestType::NEW) {
    requestPayload = payload.get(tlv::CertRequest);
  }
  else if (requestType == RequestType::REVOKE) {
    requestPayload = payload.get(tlv::CertToRevoke);
  }
  requestPayload.parse();

  security::Certificate cert = security::Certificate(requestPayload.get(ndn::tlv::Data));
  clientCert =std::make_shared<security::Certificate>(cert);
}

Block
NewRenewRevokeEncoder::encodeDataContent(const std::string& ecdhKey, const std::string& salt,
                                    const CaState& request,
                                    const std::list<std::string>& challenges)
{
  Block response = makeEmptyBlock(ndn::tlv::Content);
  response.push_back(makeStringBlock(tlv::EcdhPub, ecdhKey));
  response.push_back(makeStringBlock(tlv::Salt, salt));
  response.push_back(makeStringBlock(tlv::RequestId, request.m_requestId));
  response.push_back(makeNonNegativeIntegerBlock(tlv::Status, static_cast<size_t>(request.m_status)));
  for (const auto& entry: challenges) {
    response.push_back(makeStringBlock(tlv::Challenge, entry));
  }
  response.encode();
  return response;
}

NewRenewRevokeEncoder::DecodedData
NewRenewRevokeEncoder::decodeDataContent(const Block& content)
{
  content.parse();
  const auto& ecdhKey = readString(content.get(tlv::EcdhPub));
  const auto& salt = readString(content.get(tlv::Salt));
  uint64_t saltInt = std::stoull(salt);
  const auto& requestStatus = static_cast<Status>(readNonNegativeInteger(content.get(tlv::Status)));
  const auto& requestId = readString(content.get(tlv::RequestId));
  std::list<std::string> challenges;
  for (auto const& element : content.elements()) {
    if (element.type() == tlv::Challenge) {
      challenges.push_back(readString(element));
    }
  }
  return DecodedData{ecdhKey, saltInt, requestId, requestStatus, challenges};
}

} // namespace ndncert
} // namespace ndn