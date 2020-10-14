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

#include "ndncert-common.hpp"

namespace ndn {
namespace ndncert {

const std::map<ErrorCode, std::string> errorCodeText = {
  {ErrorCode::NO_ERROR,             "NO_ERROR"},
  {ErrorCode::BAD_INTEREST_FORMAT,  "BAD_INTEREST_FORMAT"},
  {ErrorCode::BAD_PARAMETER_FORMAT, "BAD_PARAMETER_FORMAT"},
  {ErrorCode::BAD_SIGNATURE,        "BAD_SIGNATURE"},
  {ErrorCode::INVALID_PARAMETER,    "INVALID_PARAMETER"},
  {ErrorCode::NAME_NOT_ALLOWED,     "NAME_NOT_ALLOWED"},
  {ErrorCode::BAD_VALIDITY_PERIOD,  "BAD_VALIDITY_PERIOD"},
  {ErrorCode::OUT_OF_TRIES,         "OUT_OF_TRIES"},
  {ErrorCode::OUT_OF_TIME,          "OUT_OF_TIME"},
  {ErrorCode::NO_AVAILABLE_NAMES,   "NO_AVAILABLE_NAMES"}
};

const std::map<RequestType, std::string> requestTypeText = {
  {RequestType::NEW, "New"},
  {RequestType::RENEW, "Renew"},
  {RequestType::REVOKE, "Revoke"},
  {RequestType::NOTINITIALIZED, "Not Initialized"},
};

std::string errorCodeToString(ErrorCode code)
{
  return errorCodeText.at(code);
}

std::string requestTypeToString(RequestType type)
{
  return requestTypeText.at(type);
}

} // namespace ndncert
} // namespace ndn
