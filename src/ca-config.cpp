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

#include "ca-config.hpp"
#include <ndn-cxx/util/io.hpp>
#include <boost/filesystem.hpp>

namespace ndn {
namespace ndncert {

void
CaConfig::load(const std::string& fileName)
{
  try {
    boost::property_tree::read_json(fileName, m_config);
  }
  catch (const boost::property_tree::info_parser_error& error) {
    BOOST_THROW_EXCEPTION(Error("Failed to parse configuration file " + fileName +
                                " " + error.message() + " line " + std::to_string(error.line())));
  }

  if (m_config.begin() == m_config.end()) {
    BOOST_THROW_EXCEPTION(Error("Error processing configuration file: " + fileName + " no data"));
  }

  parse();
}

void
CaConfig::parse()
{
  m_caItems.clear();
  auto caList = m_config.get_child("ca-list");
  auto it = caList.begin();
  for (; it != caList.end(); it++) {
    CaItem item;
    item.m_caName = Name(it->second.get<std::string>("ca-prefix"));
    item.m_probe = it->second.get("probe", false);
    item.m_freshnessPeriod = time::seconds(it->second.get<uint64_t>("issuing-freshness"));
    item.m_validityPeriod = time::days(it->second.get<uint64_t>("validity-period"));

    auto challengeList = it->second.get_child("supported-challenges");
    item.m_supportedChallenges = parseChallengeList(challengeList);
    item.m_anchor = Name(it->second.get<std::string>("ca-anchor"));
    m_caItems.push_back(item);
  }
}

std::list<std::string>
CaConfig::parseChallengeList(const JsonSection& section)
{
  std::list<std::string> result;
  auto it = section.begin();
  for (; it != section.end(); it++) {
    result.push_back(it->second.get<std::string>("type"));
  }
  return result;
}

} // namespace ndncert
} // namespace ndn
