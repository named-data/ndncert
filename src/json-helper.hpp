/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/**
 * Copyright (c) 2017, Regents of the University of California.
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

#ifndef NDNCERT_JSON_HELPER_HPP
#define NDNCERT_JSON_HELPER_HPP

#include "certificate-request.hpp"

namespace ndn {
namespace ndncert {

const std::string JSON_IDNENTIFIER = "identifier";
const std::string JSON_CA_INFO = "ca-info";
const std::string JSON_STATUS = "status";
const std::string JSON_REQUEST_ID = "request-id";
const std::string JSON_CHALLENGES = "challenges";
const std::string JSON_CHALLENGE_TYPE = "challenge-type";
const std::string JSON_FAILURE_INFO = "failure-info";
const std::string JSON_CERTIFICATE = "certificate";

/**
 * @brief Generate JSON file to response PROBE insterest
 *
 * Target JSON format:
 * {
 *   "identifier": "@p identifier",
 *   "ca-info": "@p caInformation"
 * }
 */
const JsonSection
genResponseProbeJson(const Name& identifier, const Name& caInformation);

/**
 * @brief Generate JSON file to response NEW interest
 *
 * Target JSON format:
 * {
 *   "request-id": "@p requestId",
 *   "status": "@p status",
 *   "challenges": [
 *     {
 *       "challenge-type": ""
 *     },
 *     {
 *       "challenge-type": ""
 *     },
 *     ...
 *   ]
 * }
 */
const JsonSection
genResponseNewJson(const std::string& requestId, const std::string& status,
                   const std::list<std::string>& challenges);

/**
 * @brief Generate JSON file to response _SELECT, _VALIDATE, and _STATUS interest
 *
 * if certificate name is not present:
 *
 * Target JSON format:
 * {
 *   "request-id": "@p requestId",
 *   "challenge-type": "@p challengeType",
 *   "status": "@p status"
 * }
 *
 * if certificate name is present:
 *
 * Target JSON format:
 * {
 *   "request-id": "@p requestId",
 *   "challenge-type": "@p challengeType",
 *   "status": "@p status",
 *   "certificate":"@p name"
 * }
 */
const JsonSection
genResponseChallengeJson(const std::string& requestId, const std::string& challengeType,
                         const std::string& status, const Name& name = Name());

/**
 * @brief Generate JSON file when there is an Error
 *
 * Target JSON format:
 * {
 *   "request-id": "@p requestId",
 *   "challenge-type": "@p challengeType",
 *   "status": "failure",
 *   "failure-info": "@p errorInfo",
 * }
 */
const JsonSection
genFailureJson(const std::string& requestId, const std::string& challengeType,
               const std::string& status, const std::string& failureInfo);

} // namespace ndncert
} // namespace ndn

#endif // NDNCERT_JSON_HELPER_HPP
