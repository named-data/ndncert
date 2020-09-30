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

#ifndef NDNCERT_PROTOCOL_DETAIL_ERROR_HPP
#define NDNCERT_PROTOCOL_DETAIL_ERROR_HPP

#include "../configuration.hpp"

namespace ndn {
namespace ndncert {

class ErrorTLV {
public:
  /**
   * Encode error information into a Data content TLV
   */
  static Block
  encodeDataContent(ErrorCode errorCode, const std::string& description);

  /**
   * Decode error information from Data content TLV
   */
  static std::tuple<ErrorCode, std::string>
  decodefromDataContent(const Block& block);
};

}  // namespace ndncert
}  // namespace ndn

#endif // NDNCERT_PROTOCOL_ERROR_HPP