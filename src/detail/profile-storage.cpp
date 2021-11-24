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

#include "detail/profile-storage.hpp"

#include <boost/filesystem.hpp>
#include <boost/property_tree/json_parser.hpp>

namespace ndncert {
namespace requester {

void
ProfileStorage::load(const std::string& fileName)
{
  JsonSection configJson;
  try {
    boost::property_tree::read_json(fileName, configJson);
  }
  catch (const std::exception& error) {
    NDN_THROW(std::runtime_error("Failed to parse configuration file " + fileName + ", " + error.what()));
  }
  if (configJson.begin() == configJson.end()) {
    NDN_THROW(std::runtime_error("No JSON configuration found in file: " + fileName));
  }
  load(configJson);
}

void
ProfileStorage::load(const JsonSection& json)
{
  m_caProfiles.clear();
  auto caList = json.get_child("ca-list");
  for (auto item : caList) {
    CaProfile caItem;
    caItem = CaProfile::fromJson(item.second);
    if (caItem.cert == nullptr) {
      NDN_THROW(std::runtime_error("No CA certificate is loaded from JSON configuration."));
    }
    m_caProfiles.push_back(std::move(caItem));
  }
}

void
ProfileStorage::save(const std::string& fileName) const
{
  JsonSection configJson;
  for (const auto& caItem : m_caProfiles) {
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
ProfileStorage::removeCaProfile(const Name& caName)
{
  m_caProfiles.remove_if([&](const CaProfile& item) { return item.caPrefix == caName; });
}

void
ProfileStorage::addCaProfile(const CaProfile& profile)
{
  for (auto& item : m_caProfiles) {
    if (item.caPrefix == profile.caPrefix) {
      item = profile;
      return;
    }
  }
  m_caProfiles.push_back(profile);
}

const std::list<CaProfile>&
ProfileStorage::getKnownProfiles() const
{
  return m_caProfiles;
}

} // namespace requester
} // namespace ndncert
