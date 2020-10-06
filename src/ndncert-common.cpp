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

std::string statusToString(Status status) {
  switch (status)
  {
  case Status::BEFORE_CHALLENGE:
    return "Before challenge";
  case Status::CHALLENGE:
    return "In challenge";
  case Status::PENDING:
    return "Pending after challenge";
  case Status::SUCCESS:
    return "Success";
  case Status::FAILURE:
    return "Failure";
  case Status::NOT_STARTED:
    return "Not started";
  case Status::ENDED:
    return "Ended";
  default:
    return "Unrecognized status";
  }
}

std::string requestTypeToString(RequestType type)
{
  switch (type)
  {
  case RequestType::NEW:
    return "New";
  case RequestType::RENEW:
    return "Renew";
  case RequestType::REVOKE:
    return "Revoke";
  case RequestType::NOTINITIALIZED:
    return "Not initalized";
  default:
    return "Unrecognized type";
  }
}

std::map<ErrorCode, std::string> errorCodeText = {
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

std::string errorCodeToString(ErrorCode code)
{
  return errorCodeText.at(code);
}

std::string
convertJson2String(const JsonSection& json)
{
  std::stringstream ss;
  boost::property_tree::write_json(ss, json);
  return ss.str();
}

JsonSection
convertString2Json(const std::string& jsonContent)
{
  std::istringstream ss(jsonContent);
  JsonSection json;
  boost::property_tree::json_parser::read_json(ss, json);
  return json;
}

std::string
hexlify(const uint8_t* bytes, size_t byteLen)
{
  std::stringstream ss;
  ss << std::hex;
  for (size_t i = 0; i < byteLen; i++) {
    ss << std::setw(2) << std::setfill('0') << (int)bytes[i];
  }
  return ss.str();
}

}  // namespace ndncert
}  // namespace ndn
