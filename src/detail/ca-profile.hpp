/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2017-2021, Regents of the University of California.
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

#ifndef NDNCERT_DETAIL_CA_PROFILE_HPP
#define NDNCERT_DETAIL_CA_PROFILE_HPP

#include "detail/ndncert-common.hpp"

namespace ndncert {

// used in parsing CA configuration file and Client CA profile storage file
const std::string CONFIG_CA_PREFIX = "ca-prefix";
const std::string CONFIG_CA_INFO = "ca-info";
const std::string CONFIG_MAX_VALIDITY_PERIOD = "max-validity-period";
const std::string CONFIG_MAX_SUFFIX_LENGTH = "max-suffix-length";
const std::string CONFIG_PROBE_PARAMETERS = "probe-parameters";
const std::string CONFIG_PROBE_PARAMETER = "probe-parameter-key";
const std::string CONFIG_SUPPORTED_CHALLENGES = "supported-challenges";
const std::string CONFIG_CHALLENGE = "challenge";
const std::string CONFIG_CERTIFICATE = "certificate";
const std::string CONFIG_REDIRECTION = "redirect-to";
const std::string CONFIG_NAME_ASSIGNMENT = "name-assignment";

class CaProfile
{
public:
  /**
   * Parse the configuration json.
   * @param configJson the configuration json to parse
   * @return the CaProfile according to this json
   */
  static CaProfile
  fromJson(const JsonSection& json);

  /**
   * @return the JSON representation of this profile.
   */
  JsonSection
  toJson() const;

public:
  /**
   * @brief CA Name prefix (without /CA suffix).
   */
  Name caPrefix;
  /**
   * @brief CA Information.
   */
  std::string caInfo;
  /**
   * @brief A list of parameter-keys for PROBE.
   */
  std::vector<std::string> probeParameterKeys;
  /**
   * @brief  Maximum allowed validity period of the certificate being requested.
   *
   * The value is in the unit of second.
   * Default: one day (86400 seconds).
   */
  time::seconds maxValidityPeriod;
  /**
   * @brief Maximum allowed suffix length of requested name.
   *
   * E.g., When its value is 2, at most 2 name components can be assigned after m_caPrefix.
   * Default: none.
   */
  optional<size_t> maxSuffixLength = nullopt;
  /**
   * @brief A list of supported challenges. Only CA side will have m_supportedChallenges.
   */
  std::vector<std::string> supportedChallenges;
  /**
   * @brief CA's certificate. Only Client side will have m_cert.
   */
  std::shared_ptr<Certificate> cert;
};

} // namespace ndncert

#endif // NDNCERT_DETAIL_CA_PROFILE_HPP
