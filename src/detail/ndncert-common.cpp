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

std::ostream&
operator<<(std::ostream& out, ErrorCode code)
{
  switch (code) {
    case ErrorCode::NO_ERROR: out << "NO_ERROR"; break;
    case ErrorCode::BAD_INTEREST_FORMAT: out << "BAD_INTEREST_FORMAT"; break;
    case ErrorCode::BAD_PARAMETER_FORMAT: out << "BAD_PARAMETER_FORMAT"; break;
    case ErrorCode::BAD_SIGNATURE: out << "BAD_SIGNATURE"; break;
    case ErrorCode::INVALID_PARAMETER: out << "INVALID_PARAMETER"; break;
    case ErrorCode::NAME_NOT_ALLOWED: out << "NAME_NOT_ALLOWED"; break;
    case ErrorCode::BAD_VALIDITY_PERIOD: out << "BAD_VALIDITY_PERIOD"; break;
    case ErrorCode::OUT_OF_TRIES: out << "OUT_OF_TRIES"; break;
    case ErrorCode::OUT_OF_TIME: out << "OUT_OF_TIME"; break;
    case ErrorCode::NO_AVAILABLE_NAMES: out << "NO_AVAILABLE_NAMES"; break;
    default: out << "UNKNOWN_ERROR"; break;
  }
  return out;
}

std::ostream&
operator<<(std::ostream& out, RequestType type)
{
  switch (type) {
    case RequestType::NEW: out << "New"; break;
    case RequestType::RENEW: out << "Renew"; break;
    case RequestType::REVOKE: out << "Revoke"; break;
    case RequestType::NOTINITIALIZED: out << "Not Initialized"; break;
    default: out << "UNKNOWN_REQUEST_TYPE"; break;
  }
  return out;
}

} // namespace ndncert
} // namespace ndn
