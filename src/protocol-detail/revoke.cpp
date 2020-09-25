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

#include "revoke.hpp"
#include "../logging.hpp"
#include "../ndncert-common.hpp"

#include <ndn-cxx/security/transform/base64-encode.hpp>
#include <ndn-cxx/security/transform/buffer-source.hpp>
#include <ndn-cxx/security/transform/stream-sink.hpp>
#include <ndn-cxx/util/logger.hpp>

namespace ndn {
namespace ndncert {

_LOG_INIT(ndncert.client);

Block
REVOKE::encodeApplicationParameters(const std::string& ecdhPub, const security::v2::Certificate& certToRevoke)
{
  Block request = makeEmptyBlock(tlv::ApplicationParameters);
  std::stringstream ss;
  try {
    security::transform::bufferSource(certToRevoke.wireEncode().wire(), certToRevoke.wireEncode().size())
    >> security::transform::base64Encode(false)
    >> security::transform::streamSink(ss);
  }
  catch (const security::transform::Error& e) {
    _LOG_ERROR("Cannot convert self-signed cert into BASE64 string " << e.what());
    return request;
  }

  request.push_back(makeStringBlock(tlv_ecdh_pub, ecdhPub));
  request.push_back(makeNestedBlock(tlv_cert_to_revoke, certToRevoke));
  request.encode();
  return request;
}

Block
REVOKE::encodeDataContent(const std::string& ecdhKey, const std::string& salt,
                             const CertificateRequest& request,
                             const std::list<std::string>& challenges)
{
  Block response = makeEmptyBlock(tlv::Content);
  response.push_back(makeStringBlock(tlv_ecdh_pub, ecdhKey));
  response.push_back(makeStringBlock(tlv_salt, salt));
  response.push_back(makeStringBlock(tlv_request_id, request.m_requestId));
  response.push_back(makeNonNegativeIntegerBlock(tlv_status, request.m_status));
  for (const auto& entry: challenges) {
    response.push_back(makeStringBlock(tlv_challenge, entry));
  }
  response.encode();
  return response;
}

}  // namespace ndncert
}  // namespace ndn