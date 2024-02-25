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

#include "detail/ndncert-common.hpp"

#include <ndn-cxx/util/backports.hpp>

namespace ndncert {

std::ostream&
operator<<(std::ostream& out, ErrorCode code)
{
  switch (code) {
    case ErrorCode::NO_ERROR: return out << "NO_ERROR";
    case ErrorCode::BAD_INTEREST_FORMAT: return out << "BAD_INTEREST_FORMAT";
    case ErrorCode::BAD_PARAMETER_FORMAT: return out << "BAD_PARAMETER_FORMAT";
    case ErrorCode::BAD_SIGNATURE: return out << "BAD_SIGNATURE";
    case ErrorCode::INVALID_PARAMETER: return out << "INVALID_PARAMETER";
    case ErrorCode::NAME_NOT_ALLOWED: return out << "NAME_NOT_ALLOWED";
    case ErrorCode::BAD_VALIDITY_PERIOD: return out << "BAD_VALIDITY_PERIOD";
    case ErrorCode::OUT_OF_TRIES: return out << "OUT_OF_TRIES";
    case ErrorCode::OUT_OF_TIME: return out << "OUT_OF_TIME";
    case ErrorCode::NO_AVAILABLE_NAMES: return out << "NO_AVAILABLE_NAMES";
  }
  return out << "<Unknown Error " << ndn::to_underlying(code) << ">";
}

std::ostream&
operator<<(std::ostream& out, RequestType type)
{
  switch (type) {
    case RequestType::NOTINITIALIZED: return out << "Not Initialized";
    case RequestType::NEW: return out << "New";
    case RequestType::RENEW: return out << "Renew";
    case RequestType::REVOKE: return out << "Revoke";
  }
  return out << "<Unknown Request Type " << ndn::to_underlying(type) << ">";
}

} // namespace ndncert
