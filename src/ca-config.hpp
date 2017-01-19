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

#ifndef NDNCERT_CA_CONFIG_HPP
#define NDNCERT_CA_CONFIG_HPP

#include "ndncert-common.hpp"
#include <ndn-cxx/security/v2/certificate.hpp>

namespace ndn {
namespace ndncert {

typedef boost::property_tree::ptree ConfigSection;

/**
 * @brief Represents a CA configuration instance
 */
class CaConfig
{
public:
  /**
   * @brief Error that can be thrown from CaConfig
   */
  class Error : public std::runtime_error
  {
  public:
    explicit
    Error(const std::string& what)
      : std::runtime_error(what)
    {
    }
  };

public:
  CaConfig();

  explicit
  CaConfig(const std::string& fileName);

PUBLIC_WITH_TESTS_ELSE_PRIVATE:
  void
  open();

  void
  load();

  void
  parseCertificateInfo(const ConfigSection& configSection);

  void
  parseCaAnchor(const ConfigSection& configSection);

  void
  parseChallengeList(const ConfigSection& configSection);

public:
  Name m_caName;
  uint64_t m_freshPeriod;
  shared_ptr<security::v2::Certificate> m_anchor;
  std::list<std::string> m_availableChallenges;
  ConfigSection m_validatorConfig;

PUBLIC_WITH_TESTS_ELSE_PRIVATE:
  ConfigSection m_config;
  std::string m_fileName;
};

} // namespace ndncert
} // namespace ndn

#endif // NDNCERT_CA_CONFIG_HPP
