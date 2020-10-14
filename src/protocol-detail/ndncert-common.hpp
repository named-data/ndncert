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

#ifndef NDNCERT_NDNCERT_COMMON_HPP
#define NDNCERT_NDNCERT_COMMON_HPP

#include "ndncert-config.hpp"

#ifdef HAVE_TESTS
#define VIRTUAL_WITH_TESTS virtual
#define PUBLIC_WITH_TESTS_ELSE_PROTECTED public
#define PUBLIC_WITH_TESTS_ELSE_PRIVATE public
#define PROTECTED_WITH_TESTS_ELSE_PRIVATE protected
#else
#define VIRTUAL_WITH_TESTS
#define PUBLIC_WITH_TESTS_ELSE_PROTECTED protected
#define PUBLIC_WITH_TESTS_ELSE_PRIVATE private
#define PROTECTED_WITH_TESTS_ELSE_PRIVATE private
#endif

#include <cstddef>
#include <cstdint>
#include <tuple>
#include <ndn-cxx/encoding/tlv.hpp>
#include <ndn-cxx/data.hpp>
#include <ndn-cxx/encoding/block.hpp>
#include <ndn-cxx/encoding/block-helpers.hpp>
#include <ndn-cxx/face.hpp>
#include <ndn-cxx/interest.hpp>
#include <ndn-cxx/link.hpp>
#include <ndn-cxx/lp/nack.hpp>
#include <ndn-cxx/name.hpp>
#include <ndn-cxx/security/key-chain.hpp>
#include <ndn-cxx/security/certificate.hpp>
#include <ndn-cxx/util/logger.hpp>
#include <boost/algorithm/string.hpp>
#include <boost/assert.hpp>
#include <boost/noncopyable.hpp>
#include <boost/property_tree/info_parser.hpp>
#include <boost/property_tree/json_parser.hpp>
#include <boost/property_tree/ptree.hpp>

namespace ndn {
namespace tlv {
  enum : uint32_t {
    CaPrefix = 129,
    CaInfo = 131,
    ParameterKey = 133,
    ParameterValue = 135,
    CaCertificate = 137,
    MaxValidityPeriod = 139,
    ProbeResponse = 141,
    MaxSuffixLength = 143,
    EcdhPub = 145,
    CertRequest = 147,
    Salt = 149,
    RequestId = 151,
    Challenge = 153,
    Status = 155,
    InitializationVector = 157,
    EncryptedPayload = 159,
    SelectedChallenge = 161,
    ChallengeStatus = 163,
    RemainingTries = 165,
    RemainingTime = 167,
    IssuedCertName = 169,
    ErrorCode = 171,
    ErrorInfo = 173,
    AuthenticationTag = 175,
    CertToRevoke = 177,
    ProbeRedirect = 179
 };
} // namespace tlv
namespace ndncert {

using boost::noncopyable;
typedef boost::property_tree::ptree JsonSection;

// NDNCERT error code
enum class ErrorCode : uint16_t {
  NO_ERROR = 0,
  BAD_INTEREST_FORMAT = 1,
  BAD_PARAMETER_FORMAT = 2,
  BAD_SIGNATURE = 3,
  INVALID_PARAMETER = 4,
  NAME_NOT_ALLOWED = 5,
  BAD_VALIDITY_PERIOD = 6,
  OUT_OF_TRIES = 7,
  OUT_OF_TIME = 8,
  NO_AVAILABLE_NAMES = 9
};

// Convert error code to string
std::string
errorCodeToString(ErrorCode code);

// NDNCERT request type
enum class RequestType : uint16_t {
  NOTINITIALIZED = 0,
  NEW = 1,
  RENEW = 2,
  REVOKE = 3
};

// Convert request type to string
std::string
requestTypeToString(RequestType type);

} // namespace ndncert
} // namespace ndn

#endif // NDNCERT_NDNCERT_COMMON_HPP
