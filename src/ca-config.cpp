/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/**
 * Copyright (c) 2017-2019, Regents of the University of California.
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

#include "ca-config.hpp"
#include "challenge-module.hpp"
#include <ndn-cxx/util/io.hpp>
#include <boost/filesystem.hpp>

namespace ndn {
namespace ndncert {

void
CaConfig::load(const std::string& fileName)
{
  JsonSection configJson;
  try {
    boost::property_tree::read_json(fileName, configJson);
  }
  catch (const std::exception& error) {
    BOOST_THROW_EXCEPTION(Error("Failed to parse configuration file " + fileName + ", " + error.what()));
  }

  if (configJson.begin() == configJson.end()) {
    BOOST_THROW_EXCEPTION(Error("Error processing configuration file: " + fileName + " no data"));
  }
  parse(configJson);
}

void
CaConfig::parse(const JsonSection& configJson)
{
  // essential info
  m_caName = Name(configJson.get("ca-prefix", ""));
  if (m_caName.empty()) {
    BOOST_THROW_EXCEPTION(Error("Cannot read ca-prefix from the config file"));
  }
  m_freshnessPeriod = time::seconds(configJson.get("issuing-freshness", 720));
  m_validityPeriod = time::days(configJson.get("max-validity-period", 360));

  // optional info
  m_probe = configJson.get("probe", "");
  m_caInfo = configJson.get("ca-info", "");

  // optional supported challenges
  auto challengeList = configJson.get_child("supported-challenges");
  m_supportedChallenges = parseChallengeList(challengeList);
}

std::list<std::string>
CaConfig::parseChallengeList(const JsonSection& section)
{
  std::list<std::string> result;
  auto it = section.begin();
  for (; it != section.end(); it++) {
    auto challengeType = it->second.get("type", "");
    if (challengeType == "") {
      BOOST_THROW_EXCEPTION(Error("Cannot read type in supported-challenges from the config file"));
    }
    challengeType = boost::algorithm::to_lower_copy(challengeType);
    if (!ChallengeModule::supportChallenge(challengeType)) {
      BOOST_THROW_EXCEPTION(Error("Does not support challenge read from the config file"));
    }
    result.push_back(challengeType);
  }
  return result;
}

} // namespace ndncert
} // namespace ndn
