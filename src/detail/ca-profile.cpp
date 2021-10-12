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

#include "detail/ca-profile.hpp"
#include "challenge/challenge-module.hpp"
#include <ndn-cxx/util/io.hpp>
#include <boost/filesystem.hpp>

namespace ndn {
namespace ndncert {

CaProfile
CaProfile::fromJson(const JsonSection& json)
{
  CaProfile profile;
  // CA prefix
  profile.caPrefix = Name(json.get(CONFIG_CA_PREFIX, ""));
  if (profile.caPrefix.empty()) {
    NDN_THROW(std::runtime_error("Cannot parse ca-prefix from the config file"));
  }
  // CA info
  profile.caInfo = json.get(CONFIG_CA_INFO, "");
  // CA max validity period
  profile.maxValidityPeriod = time::seconds(json.get(CONFIG_MAX_VALIDITY_PERIOD, 86400));
  // CA max suffix length
  profile.maxSuffixLength = nullopt;
  auto maxSuffixLength = json.get_optional<size_t>(CONFIG_MAX_SUFFIX_LENGTH);
  if (maxSuffixLength) {
    profile.maxSuffixLength = *maxSuffixLength;
  }
  // probe parameter keys
  profile.probeParameterKeys.clear();
  auto probeParametersJson = json.get_child_optional(CONFIG_PROBE_PARAMETERS);
  if (probeParametersJson) {
    for (const auto& item : *probeParametersJson) {
      auto probeParameter = item.second.get(CONFIG_PROBE_PARAMETER, "");
      probeParameter = boost::algorithm::to_lower_copy(probeParameter);
      if (probeParameter == "") {
        NDN_THROW(std::runtime_error("Probe parameter key cannot be empty."));
      }
      profile.probeParameterKeys.push_back(probeParameter);
    }
  }
  // supported challenges
  profile.supportedChallenges.clear();
  auto challengeListJson = json.get_child_optional(CONFIG_SUPPORTED_CHALLENGES);
  if (challengeListJson) {
    for (const auto& item : *challengeListJson) {
      auto challengeType = item.second.get(CONFIG_CHALLENGE, "");
      challengeType = boost::algorithm::to_lower_copy(challengeType);
      if (challengeType == "") {
        NDN_THROW(std::runtime_error("Challenge type cannot be empty."));
      }
      if (!ChallengeModule::isChallengeSupported(challengeType)) {
        NDN_THROW(std::runtime_error("Challenge " + challengeType + " is not supported."));
      }
      profile.supportedChallenges.push_back(challengeType);
    }
  }
  // anchor certificate
  profile.cert = nullptr;
  auto certificateStr = json.get(CONFIG_CERTIFICATE, "");
  if (certificateStr != "") {
    std::istringstream ss(certificateStr);
    profile.cert = io::load<security::Certificate>(ss);
  }
  return profile;
}

JsonSection
CaProfile::toJson() const
{
  JsonSection caItem;
  caItem.put(CONFIG_CA_PREFIX, caPrefix.toUri());
  caItem.put(CONFIG_CA_INFO, caInfo);
  caItem.put(CONFIG_MAX_VALIDITY_PERIOD, maxValidityPeriod.count());
  if (maxSuffixLength) {
    caItem.put(CONFIG_MAX_SUFFIX_LENGTH, *maxSuffixLength);
  }
  if (!probeParameterKeys.empty()) {
    JsonSection probeParametersJson;
    for (const auto& key : probeParameterKeys) {
      JsonSection keyJson;
      keyJson.put(CONFIG_PROBE_PARAMETER, key);
      probeParametersJson.push_back(std::make_pair("", keyJson));
    }
    caItem.add_child("", probeParametersJson);
  }
  if (!supportedChallenges.empty()) {
    JsonSection challengeListJson;
    for (const auto& challenge : supportedChallenges) {
      JsonSection challengeJson;
      challengeJson.put(CONFIG_CHALLENGE, challenge);
      challengeListJson.push_back(std::make_pair("", challengeJson));
    }
    caItem.add_child("", challengeListJson);
  }
  if (cert != nullptr) {
    std::stringstream ss;
    io::save(*cert, ss);
    caItem.put("certificate", ss.str());
  }
  return caItem;
}

} // namespace ndncert
} // namespace ndn
