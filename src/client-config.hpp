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

#ifndef NDNCERT_CLIENT_CONFIG_HPP
#define NDNCERT_CLIENT_CONFIG_HPP

#include "ca-config.hpp"
#include <boost/filesystem.hpp>

namespace ndn {
namespace ndncert {

class ClientConfig
{
public:
  class Error : public std::runtime_error
  {
  public:
    using std::runtime_error::runtime_error;
  };

public:
  void
  load(const std::string& fileName);

  void
  addNewCaItem(const CaItem& item);

  void
  removeCaItem(const Name& caName);

PUBLIC_WITH_TESTS_ELSE_PRIVATE:
  void
  parse();

  std::list<std::string>
  parseChallengeList(const ConfigSection& section);

public:
  std::list<CaItem> m_caItems;

PUBLIC_WITH_TESTS_ELSE_PRIVATE:
  ConfigSection m_config;
};

} // namespace ndncert
} // namespace ndn

#endif // NDNCERT_CLIENT_CONFIG_HPP
