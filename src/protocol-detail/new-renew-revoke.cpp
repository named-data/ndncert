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

#include "new-renew-revoke.hpp"
#include "../ndncert-common.hpp"
#include <ndn-cxx/security/transform/base64-encode.hpp>
#include <ndn-cxx/security/transform/buffer-source.hpp>
#include <ndn-cxx/security/transform/stream-sink.hpp>
#include <ndn-cxx/util/logger.hpp>

namespace ndn {
namespace ndncert {

_LOG_INIT(ndncert.encoding.new_renew_revoke);

Block
NEW_RENEW_REVOKE::encodeApplicationParameters(RequestType requestType, const std::string& ecdhPub, const security::v2::Certificate& certRequest)
{
  Block request = makeEmptyBlock(tlv::ApplicationParameters);
  std::stringstream ss;
  try {
    security::transform::bufferSource(certRequest.wireEncode().wire(), certRequest.wireEncode().size())
    >> security::transform::base64Encode(false)
    >> security::transform::streamSink(ss);
  }
  catch (const security::transform::Error& e) {
    _LOG_ERROR("Cannot convert self-signed cert into BASE64 string " << e.what());
    return request;
  }

  request.push_back(makeStringBlock(tlv_ecdh_pub, ecdhPub));
  if (requestType == RequestType::NEW || requestType == RequestType::RENEW) {
    request.push_back(makeNestedBlock(tlv_cert_request, certRequest));
  } else if (requestType == RequestType::REVOKE) {
    request.push_back(makeNestedBlock(tlv_cert_to_revoke, certRequest));
  }
  request.encode();
  return request;
}

void
NEW_RENEW_REVOKE::decodeApplicationParameters(const Block& payload, RequestType requestType, std::string& ecdhPub,
                                              shared_ptr<security::v2::Certificate>& clientCert) {
  payload.parse();

  ecdhPub = readString(payload.get(tlv_ecdh_pub));
  Block requestPayload;
  if (requestType == RequestType::NEW) {
    requestPayload = payload.get(tlv_cert_request);
  }
  else if (requestType == RequestType::REVOKE) {
    requestPayload = payload.get(tlv_cert_to_revoke);
  }
  requestPayload.parse();

  security::v2::Certificate cert = security::v2::Certificate(requestPayload.get(tlv::Data));
  clientCert = make_shared<security::v2::Certificate>(cert);
}

Block
NEW_RENEW_REVOKE::encodeDataContent(const std::string& ecdhKey, const std::string& salt,
                                    const CaState& request,
                                    const std::list<std::string>& challenges)
{
  Block response = makeEmptyBlock(tlv::Content);
  response.push_back(makeStringBlock(tlv_ecdh_pub, ecdhKey));
  response.push_back(makeStringBlock(tlv_salt, salt));
  response.push_back(makeStringBlock(tlv_request_id, request.m_requestId));
  response.push_back(makeNonNegativeIntegerBlock(tlv_status, static_cast<size_t>(request.m_status)));
  for (const auto& entry: challenges) {
    response.push_back(makeStringBlock(tlv_challenge, entry));
  }
  response.encode();
  return response;
}

NEW_RENEW_REVOKE::DecodedData
NEW_RENEW_REVOKE::decodeDataContent(const Block& content)
{
  content.parse();
  const auto& ecdhKey = readString(content.get(tlv_ecdh_pub));
  const auto& salt = readString(content.get(tlv_salt));
  uint64_t saltInt = std::stoull(salt);
  const auto& requestStatus = static_cast<Status>(readNonNegativeInteger(content.get(tlv_status)));
  const auto& requestId = readString(content.get(tlv_request_id));
  std::list<std::string> challenges;
  for (auto const& element : content.elements()) {
    if (element.type() == tlv_challenge) {
      challenges.push_back(readString(element));
    }
  }
  return DecodedData{ecdhKey, saltInt, requestId, requestStatus, challenges};
}

}  // namespace ndncert
}  // namespace ndn