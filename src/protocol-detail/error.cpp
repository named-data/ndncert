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

#include "error.hpp"

namespace ndn {
namespace ndncert {

Block
ErrorTLV::encodeDataContent(ErrorCode errorCode, const std::string& description)
{
  Block response = makeEmptyBlock(tlv::Content);
  response.push_back(makeNonNegativeIntegerBlock(tlv::ErrorCode, static_cast<size_t>(errorCode)));
  response.push_back(makeStringBlock(tlv::ErrorInfo, description));
  response.encode();
  return response;
}

std::tuple<ErrorCode, std::string>
ErrorTLV::decodefromDataContent(const Block& block)
{
  block.parse();
  if (block.find(tlv::ErrorCode) == block.elements_end()) {
    return std::make_tuple(ErrorCode::NO_ERROR, "");
  }
  ErrorCode error = static_cast<ErrorCode>(readNonNegativeInteger(block.get(tlv::ErrorCode)));
  return std::make_tuple(error, readString(block.get(tlv::ErrorInfo)));
}

} // namespace ndncert
} // namespace ndn
