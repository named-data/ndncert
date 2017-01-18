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

const std::string JSON_IDNENTIFIER = "Identifier";
const std::string JSON_CA_INFO = "CA-Info";
const std::string JSON_STATUS = "Status";
const std::string JSON_REQUEST_ID = "Request-ID";
const std::string JSON_CHALLENGES = "Challenges";
const std::string JSON_CHALLENGE_TYPE = "Challenge-Type";
const std::string JSON_CHALLENGE_INSTRUCTION = "Challenge-Instruction";
const std::string JSON_CHALLENGE_STATUS = "Challenge-Status";
const std::string JSON_ERROR_INFO = "Error-Info";

typedef boost::property_tree::ptree JsonSection;

/**
 * @brief Generate JSON file to response PROBE insterest
 *
 * Target JSON format:
 * {
 *   "Identifier": "",
 *   "CA-Info": ""
 * }
 */
const JsonSection
genResponseProbeJson(const Name& identifier, const Name& CaInformation);

/**
 * @brief Generate JSON file to response NEW interest
 *
 * Target JSON format:
 * {
 *   "Status": "",
 *   "Request-ID": "",
 *   "Challenges": [
 *     {
 *       "Challenge-Type": "",
 *       "Challenge-Instruction": ""
 *     },
 *     {
 *       "Challenge-Type": "",
 *       "Challenge-Instruction": ""
 *     },
 *     ...
 *   ]
 * }
 */
const JsonSection
genResponseNewJson(const CertificateRequest& request,
                   const std::list<std::tuple<std::string, std::string>> challenges);

/**
 * @brief Generate JSON file to response POLL interest
 *
 * Target JSON format:
 * {
 *   "Status": "",
 *   "Challenge-Type": "",
 *   "Challenge-Status": "",
 *   "Challenge-Instruction": ""
 * }
 */
const JsonSection
genResponsePollJson(const CertificateRequest& request);

/**
 * @brief Generate JSON file when there is an Error
 *
 * Target JSON format:
 * {
 *   "Status": "",
 *   "Error-Info": ""
 * }
 */
const JsonSection
genErrorJson(const std::string& errorInfo);

} // namespace ndncert
} // namespace ndn

#endif // NDNCERT_JSON_HELPER_HPP
