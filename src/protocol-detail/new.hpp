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

#ifndef NDNCERT_PROTOCOL_DETAIL_NEW_HPP
#define NDNCERT_PROTOCOL_DETAIL_NEW_HPP

#include <ndn-cxx/security/v2/certificate.hpp>

#include "../certificate-request.hpp"
#include "ndn-cxx/encoding/block.hpp"

namespace ndn {
namespace ndncert {

class NEW {
public:
  /**
   * Encode Client's certificate request into a ApplicationParameters TLV for NEW Interest.
   * For client side use.
   */
  static Block
  encodeApplicationParameters(const std::string& ecdhPub, const security::v2::Certificate& certRequest,
                              const shared_ptr<Data>& probeToken);

  /**
   * Encode CA's response of NEW Interest into a content TLV for NEW Data packet.
   * For CA side use.
   */
  static Block
  encodeDataContent(const std::string& ecdhKey, const std::string& salt,
                    const CertificateRequest& request,
                    const std::list<std::string>& challenges);
};

}  // namespace ndncert
}  // namespace ndn

#endif  // NDNCERT_PROTOCOL_DETAIL_HPP