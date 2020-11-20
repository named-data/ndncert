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

#include "detail/profile-storage.hpp"
#include "identity-challenge/challenge-module.hpp"
#include "name-assignment/assignment-func.hpp"
#include <ndn-cxx/util/io.hpp>
#include <boost/filesystem.hpp>

namespace ndn {
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
ProfileStorage::load(const JsonSection& configSection)
{
  m_caItems.clear();
  auto caList = configSection.get_child("ca-list");
  for (auto item : caList) {
    CaProfile caItem;
    caItem.parse(item.second);
    if (caItem.m_cert == nullptr) {
      NDN_THROW(std::runtime_error("No CA certificate is loaded from JSON configuration."));
    }
    m_caItems.push_back(std::move(caItem));
  }
}

void
ProfileStorage::save(const std::string& fileName) const
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
ProfileStorage::removeCaProfile(const Name& caName)
{
  m_caItems.remove_if([&](const CaProfile& item) { return item.m_caPrefix == caName; });
}

void
ProfileStorage::addCaProfile(const CaProfile& profile)
{
  for (auto& item : m_caItems) {
    if (item.m_caPrefix == profile.m_caPrefix) {
      item = profile;
      return;
    }
  }
  m_caItems.push_back(profile);
}

const std::list<CaProfile>&
ProfileStorage::getCaItems() const
{
  return m_caItems;
}

} // namespace requester
} // namespace ndncert
} // namespace ndn
