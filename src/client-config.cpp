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

#include "client-config.hpp"
#include "tlv.hpp"

#include <ndn-cxx/util/io.hpp>
#include <fstream>

namespace ndn {
namespace ndncert {

void
ClientConfig::load(const std::string& fileName)
{
  JsonSection config;
  try {
    boost::property_tree::read_json(fileName, config);
  }
  catch (const std::exception& error) {
    BOOST_THROW_EXCEPTION(Error("Failed to parse configuration file " + fileName + ", " + error.what()));
  }

  if (config.begin() == config.end()) {
    BOOST_THROW_EXCEPTION(Error("Error processing configuration file: " + fileName + ", no data"));
  }

  load(config);
}

void
ClientConfig::load(const JsonSection& configSection)
{
  m_caItems.clear();
  auto caList = configSection.get_child("ca-list");
  auto it = caList.begin();
  for (; it != caList.end(); it++) {
    m_caItems.push_back(extractCaItem(it->second));
  }
  m_localNdncertAnchor = configSection.get("local-ndncert-anchor", "");
}

void
ClientConfig::save(const std::string& fileName)
{
  JsonSection configJson;
  JsonSection caList;
  std::stringstream ss;
  for (const auto& item : m_caItems) {
    JsonSection caItem;
    caItem.put("ca-prefix", item.m_caName.toUri());
    caItem.put("ca-info", item.m_caInfo);
    caItem.put("probe", item.m_probe);
    ss.str(std::string());
    io::save(item.m_anchor, ss);
    caItem.put("certificate", ss.str());
    caList.push_back(std::make_pair("", caItem));
  }
  configJson.add_child("ca-list", caList);
  ss.str(std::string());
  boost::property_tree::write_json(ss, configJson);

  std::ofstream configFile;
  configFile.open(fileName, std::ios::trunc);
  configFile << ss.str();
  configFile.close();
}

ClientCaItem
ClientConfig::extractCaItem(const JsonSection& configSection)
{
  ClientCaItem item;
  item.m_caName = Name(configSection.get("ca-prefix", ""));
  if (item.m_caName.empty()) {
    BOOST_THROW_EXCEPTION(Error("Cannot read ca-prefix from the config file"));
  }
  item.m_caInfo = configSection.get("ca-info", "");
  item.m_probe = configSection.get("probe", "");
  std::istringstream ss(configSection.get("certificate", ""));
  auto anchor = io::load<security::v2::Certificate>(ss);
  if (anchor == nullptr) {
    BOOST_THROW_EXCEPTION(Error("Cannot load the certificate from config file"));
  }
  item.m_anchor = *anchor;
  return item;
}

ClientCaItem
ClientConfig::extractCaItem(const Block& contentBlock)
{
  ClientCaItem item;
  item.m_caName = Name(readString(contentBlock.get(tlv_ca_prefix)));
  if (item.m_caName.empty()) {
    BOOST_THROW_EXCEPTION(Error("Cannot read ca-prefix from the config file"));
  }
  item.m_caInfo = readString(contentBlock.get(tlv_ca_info));
  // item.m_probe = configSection.get("probe", "");

  if (!contentBlock.get(tlv_ca_certificate).hasValue()) {
    BOOST_THROW_EXCEPTION(Error("Cannot load the certificate from config file"));
  }

  security::v2::Certificate anchor;
  anchor.wireDecode(contentBlock.get(tlv_ca_certificate));
  item.m_anchor = anchor;

  return item;
}

void
ClientConfig::removeCaItem(const Name& caName)
{
  m_caItems.remove_if([&](const ClientCaItem& item) { return item.m_caName == caName; });
}

}  // namespace ndncert
}  // namespace ndn
