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

#include "certificate-request.hpp"
#include <ndn-cxx/security/v2/certificate.hpp>

namespace ndn {
namespace ndncert {

class CaItem
{
public:
  Name m_caName;
  bool m_probe;
  time::seconds m_freshnessPeriod;
  time::days m_validityPeriod;
  std::list<std::string> m_supportedChallenges;
  Name m_anchor;
};

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
    using std::runtime_error::runtime_error;
  };

public:
  void
  load(const std::string& fileName);

private:
  void
  parse();

  std::list<std::string>
  parseChallengeList(const JsonSection& configSection);

public:
  std::list<CaItem> m_caItems;

PUBLIC_WITH_TESTS_ELSE_PRIVATE:
  JsonSection m_config;
};

} // namespace ndncert
} // namespace ndn

#endif // NDNCERT_CA_CONFIG_HPP
