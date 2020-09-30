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

#include "configuration.hpp"
#include "challenge-module.hpp"
#include <ndn-cxx/util/io.hpp>
#include <boost/filesystem.hpp>

namespace ndn {
namespace ndncert {

void
CaConfigItem::parse(const JsonSection& configJson)
{
  // CA prefix
  m_caPrefix = Name(configJson.get(CONFIG_CA_PREFIX, ""));
  if (m_caPrefix.empty()) {
    BOOST_THROW_EXCEPTION(std::runtime_error("Cannot parse ca-prefix from the config file"));
  }
  // CA info
  m_caInfo = configJson.get(CONFIG_CA_INFO, "");
  // CA max validity period
  m_maxValidityPeriod = time::seconds(configJson.get(CONFIG_MAX_VALIDITY_PERIOD, 86400));
  // CA max suffix length
  m_maxSuffixLength = configJson.get_optional<size_t>(CONFIG_MAX_SUFFIX_LENGTH);
  // probe parameter keys
  m_probeParameterKeys.clear();
  auto probeParametersJson = configJson.get_child_optional(CONFIG_PROBE_PARAMETERS);
  if (probeParametersJson) {
    for (const auto item : *probeParametersJson) {
      auto probeParameter = item.second.get(CONFIG_PROBE_PARAMETER, "");
      probeParameter = boost::algorithm::to_lower_copy(probeParameter);
      if (probeParameter == "") {
        BOOST_THROW_EXCEPTION(std::runtime_error("Probe parameter key cannot be empty."));
      }
      m_probeParameterKeys.push_back(probeParameter);
    }
  }
  // supported challenges
  m_supportedChallenges.clear();
  auto challengeListJson = configJson.get_child_optional(CONFIG_SUPPORTED_CHALLENGES);
  if (challengeListJson) {
    for (const auto item : *challengeListJson) {
      auto challengeType = item.second.get(CONFIG_CHALLENGE, "");
      challengeType = boost::algorithm::to_lower_copy(challengeType);
      if (challengeType == "") {
        BOOST_THROW_EXCEPTION(std::runtime_error("Challenge type canont be empty."));
      }
      if (!ChallengeModule::isChallengeSupported(challengeType)) {
        BOOST_THROW_EXCEPTION(std::runtime_error("Challenge " + challengeType + " is not supported."));
      }
      m_supportedChallenges.push_back(challengeType);
    }
  }
  // anchor certificate
  m_cert = nullptr;
  auto certificateStr = configJson.get("certificate", "");
  if (certificateStr != "") {
    std::istringstream ss(certificateStr);
    m_cert = io::load<security::v2::Certificate>(ss);
  }
}

JsonSection
CaConfigItem::toJson() const
{
  JsonSection caItem;
  caItem.put(CONFIG_CA_PREFIX, m_caPrefix.toUri());
  caItem.put(CONFIG_CA_INFO, m_caInfo);
  caItem.put(CONFIG_MAX_VALIDITY_PERIOD, m_maxValidityPeriod.count());
  caItem.put(CONFIG_MAX_SUFFIX_LENGTH, m_maxSuffixLength);
  if (!m_probeParameterKeys.empty()) {
    JsonSection probeParametersJson;
    for (const auto& key : m_probeParameterKeys) {
      JsonSection keyJson;
      keyJson.put(CONFIG_PROBE_PARAMETER, key);
      probeParametersJson.push_back(std::make_pair("", keyJson));
    }
    caItem.add_child("", probeParametersJson);
  }
  if (!m_supportedChallenges.empty()) {
    JsonSection challengeListJson;
    for (const auto& challenge : m_supportedChallenges) {
      JsonSection challengeJson;
      challengeJson.put(CONFIG_CHALLENGE, challenge);
      challengeListJson.push_back(std::make_pair("", challengeJson));
    }
    caItem.add_child("", challengeListJson);
  }
  if (m_cert != nullptr) {
    std::stringstream ss;
    io::save(*m_cert, ss);
    caItem.put("certificate", ss.str());
  }
  return caItem;
}

void
CaConfig::load(const std::string& fileName)
{
  JsonSection configJson;
  try {
    boost::property_tree::read_json(fileName, configJson);
  }
  catch (const std::exception& error) {
    BOOST_THROW_EXCEPTION(std::runtime_error("Failed to parse configuration file " + fileName + ", " + error.what()));
  }
  if (configJson.begin() == configJson.end()) {
    BOOST_THROW_EXCEPTION(std::runtime_error("No JSON configuration found in file: " + fileName));
  }
  m_caItem.parse(configJson);
  if (m_caItem.m_supportedChallenges.size() == 0) {
    BOOST_THROW_EXCEPTION(std::runtime_error("At least one challenge should be specified."));
  }
}

void
CaConfig::save(const std::string& fileName) const
{
  std::stringstream ss;
  boost::property_tree::write_json(ss, m_caItem.toJson());
  std::ofstream configFile;
  configFile.open(fileName);
  configFile << ss.str();
  configFile.close();
}

void
ClientConfig::load(const std::string& fileName)
{
  JsonSection configJson;
  try {
    boost::property_tree::read_json(fileName, configJson);
  }
  catch (const std::exception& error) {
    BOOST_THROW_EXCEPTION(std::runtime_error("Failed to parse configuration file " + fileName + ", " + error.what()));
  }
  if (configJson.begin() == configJson.end()) {
    BOOST_THROW_EXCEPTION(std::runtime_error("No JSON configuration found in file: " + fileName));
  }
  load(configJson);
}

void
ClientConfig::load(const JsonSection& configSection)
{
  m_caItems.clear();
  auto caList = configSection.get_child("ca-list");
  for (auto item : caList) {
    CaConfigItem caItem;
    caItem.parse(item.second);
    if (caItem.m_cert == nullptr) {
      BOOST_THROW_EXCEPTION(std::runtime_error("No CA certificate is loaded from JSON configuration."));
    }
    m_caItems.push_back(std::move(caItem));
  }
}

void
ClientConfig::save(const std::string& fileName) const
{
  JsonSection configJson;
  for (const auto& caItem : m_caItems) {
    configJson.push_back(std::make_pair("", caItem.toJson()));
  }
  std::stringstream ss;
  boost::property_tree::write_json(ss, configJson);
  std::ofstream configFile;
  configFile.open(fileName);
  configFile << ss.str();
  configFile.close();
}

void
ClientConfig::removeCaItem(const Name& caName)
{
  m_caItems.remove_if([&](const CaConfigItem& item) { return item.m_caPrefix == caName; });
}

}  // namespace ndncert
}  // namespace ndn
