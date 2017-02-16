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

#include "client-config.hpp"

namespace ndn {
namespace ndncert {

void
ClientConfig::load(const std::string& fileName)
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
ClientConfig::parse()
{
  m_caItems.clear();
  auto caList = m_config.get_child("ca-list");
  auto it = caList.begin();
  for (; it != caList.end(); it++) {
    CaItem item;
    item.m_caName = Name(it->second.get<std::string>("ca-prefix"));
    item.m_caInfo = it->second.get<std::string>("ca-info");
    item.m_probe = it->second.get("probe", "");

    auto challengeList = it->second.get_child("supported-challenges");
    item.m_supportedChallenges = parseChallengeList(challengeList);

    m_caItems.push_back(item);
  }
}

std::list<std::string>
ClientConfig::parseChallengeList(const ConfigSection& section)
{
  std::list<std::string> result;
  auto it = section.begin();
  for (; it != section.end(); it++) {
    result.push_back(it->second.get<std::string>("type"));
  }
  return result;
}

void
ClientConfig::addNewCaItem(const CaItem& item)
{
  auto& caList = m_config.get_child("ca-list");

  ConfigSection newCaItem;
  ConfigSection newCaChallengeList;
  newCaItem.put("ca-prefix", item.m_caName.toUri());
  newCaItem.put("ca-info", item.m_caInfo);
  if (item.m_probe != "") {
    newCaItem.put("probe", item.m_probe);
  }
  for (const auto& challengeType : item.m_supportedChallenges) {
    ConfigSection challengeSection;
    challengeSection.put("type", challengeType);
    newCaChallengeList.push_back(std::make_pair("", challengeSection));
  }
  newCaItem.add_child("supported-challenges", newCaChallengeList);
  caList.push_back(std::make_pair("", newCaItem));

  parse();
}

void
ClientConfig::removeCaItem(const Name& caName)
{
  auto& caList = m_config.get_child("ca-list");
  auto it = caList.begin();
  while (it != caList.end()) {
    if (it->second.get<std::string>("ca-prefix") == caName.toUri()) {
      it = caList.erase(it);
      break;
    }
    else {
      it++;
    }
  }
  parse();
}

} // namespace ndncert
} // namespace ndn
