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

CaConfig::CaConfig() = default;

CaConfig::CaConfig(const std::string& fileName)
  : m_fileName(fileName)
{
  open();
  load();
}

void
CaConfig::open()
{
  std::ifstream inputFile;
  inputFile.open(m_fileName.c_str());
  if (!inputFile.good() || !inputFile.is_open()) {
    std::string msg = "Failed to read configuration file: ";
    msg += m_fileName;
    BOOST_THROW_EXCEPTION(Error(msg));
  }

  try {
    boost::property_tree::read_info(inputFile, m_config);
  }
  catch (const boost::property_tree::info_parser_error& error) {
    BOOST_THROW_EXCEPTION(Error("Failed to parse configuration file " + m_fileName +
                                " " + error.message() + " line " + std::to_string(error.line())));
  }

  if (m_config.begin() == m_config.end()) {
    BOOST_THROW_EXCEPTION(Error("Error processing configuration file: " + m_fileName + " no data"));
  }

  inputFile.close();
}

void
CaConfig::load()
{
  m_caName = Name(m_config.get<std::string>("name"));
  m_validatorConfig = m_config.get_child("validator-conf");

  parseCertificateInfo(m_config.get_child("certificate-info"));
  parseCaAnchor(m_config.get_child("ca-anchor"));
  parseChallengeList(m_config.get_child("challenge-list"));
}

void
CaConfig::parseCertificateInfo(const ConfigSection& configSection)
{
  m_freshPeriod = configSection.get<uint64_t>("freshness-period");
}

void
CaConfig::parseCaAnchor(const ConfigSection& configSection)
{
  std::string type = configSection.get<std::string>("type");
  std::string value = configSection.get<std::string>("value");
  if (type == "file") {
    boost::filesystem::path certfilePath = absolute(value,
                                                    boost::filesystem::path(m_fileName).parent_path());
    m_anchor = io::load<security::v2::Certificate>(certfilePath.string());
    if (m_anchor != nullptr) {
      BOOST_ASSERT(m_anchor->getName().size() >= 1);
    }
    else
      BOOST_THROW_EXCEPTION(Error("Cannot read certificate from file: " + certfilePath.native()));
  }
  else if (type == "base64") {
    std::istringstream ss(value);
    m_anchor = io::load<security::v2::Certificate>(ss);
  }
  else {
    BOOST_THROW_EXCEPTION(Error("Unrecognized trust anchor '" + type + "' '" + value + "'"));
  }
}

void
CaConfig::parseChallengeList(const ConfigSection& configSection)
{
  auto it = configSection.begin();
  for (; it != configSection.end(); it++) {
    m_availableChallenges.push_back(it->second.get<std::string>("type"));
  }
}

} // namespace ndncert
} // namespace ndn
