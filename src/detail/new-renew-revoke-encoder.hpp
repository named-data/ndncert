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

#ifndef NDNCERT_DETAIL_NEW_RENEW_REVOKE_ENCODER_HPP
#define NDNCERT_DETAIL_NEW_RENEW_REVOKE_ENCODER_HPP

#include "detail/ca-request-state.hpp"

namespace ndn {
namespace ndncert {
namespace newRenewRevokeEncoder {

  Block
  encodeApplicationParameters(RequestType requestType, const std::vector<uint8_t>& ecdhPub,
                              const security::Certificate& certRequest);

  void
  decodeApplicationParameters(const Block& block, RequestType requestType, std::vector<uint8_t>& ecdhPub,
                              shared_ptr<security::Certificate>& certRequest);

  Block
  encodeDataContent(const std::vector<uint8_t>& ecdhKey, const std::array<uint8_t, 32>& salt,
                    const RequestId& requestId, const Status& status,
                    const std::list<std::string>& challenges);

  std::list<std::string>
  decodeDataContent(const Block& content, std::vector<uint8_t>& ecdhKey,
                    std::array<uint8_t, 32>& salt, RequestId& requestId, Status& status);

} // namespace NewRenewRevokeEncoder
} // namespace ndncert
} // namespace ndn

#endif // NDNCERT_DETAIL_NEW_RENEW_REVOKE_ENCODER_HPP