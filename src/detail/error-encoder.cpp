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

#include "detail/error-encoder.hpp"

#include <ndn-cxx/util/logger.hpp>

namespace ndncert::errortlv {

NDN_LOG_INIT(ndncert.encode.error);

Block
encodeDataContent(ErrorCode errorCode, const std::string& description)
{
  Block response(ndn::tlv::Content);
  response.push_back(ndn::makeNonNegativeIntegerBlock(tlv::ErrorCode, static_cast<size_t>(errorCode)));
  response.push_back(ndn::makeStringBlock(tlv::ErrorInfo, description));
  response.encode();
  return response;
}

std::tuple<ErrorCode, std::string>
decodefromDataContent(const Block& block)
{
  try {
    block.parse();

    int codeCount = 0;
    int infoCount = 0;
    int otherCriticalCount = 0;
    ErrorCode error = ErrorCode::NO_ERROR;
    std::string errorInfo;
    for (const auto& item : block.elements()) {
      if (item.type() == tlv::ErrorCode) {
        error = ndn::readNonNegativeIntegerAs<ErrorCode>(block.get(tlv::ErrorCode));
        codeCount++;
      }
      else if (item.type() == tlv::ErrorInfo) {
        errorInfo = readString(block.get(tlv::ErrorInfo));
        infoCount++;
      }
      else if (ndn::tlv::isCriticalType(item.type())) {
        otherCriticalCount++;
      }
      else {
        // ignore
      }
    }

    if (codeCount == 0 && infoCount == 0) {
      return {ErrorCode::NO_ERROR, ""};
    }
    if (codeCount != 1 || infoCount != 1) {
      NDN_THROW(std::runtime_error("Error TLV contains " + std::to_string(codeCount) + " error code(s) and " +
                                   std::to_string(infoCount) + " error info(s), instead of expected 1 time each."));
    }
    if (otherCriticalCount > 0) {
      NDN_THROW(std::runtime_error("Unknown critical TLV type in error packet"));
    }
    return {error, errorInfo};
  }
  catch (const std::exception& e) {
    NDN_LOG_ERROR("Exception in error message decoding: " << e.what());
    return {ErrorCode::NO_ERROR, ""};
  }
}

} // namespace ndncert::errortlv
