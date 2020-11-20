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

#ifndef NDNCERT_CONFIGURATION_HPP
#define NDNCERT_CONFIGURATION_HPP

#include "detail/ca-profile.hpp"
#include "name-assignment/assignment-func.hpp"

namespace ndn {
namespace ndncert {
namespace requester {

/**
 * @brief Represents Client configuration
 * @sa https://github.com/named-data/ndncert/wiki/Client-Configuration-Sample
 */
class ProfileStorage
{
public:
  /**
   * @throw std::runtime_error when config file cannot be correctly parsed.
   */
  void
  load(const std::string& fileName);

  /**
   * @throw std::runtime_error when config file cannot be correctly parsed.
   */
  void
  load(const JsonSection& configSection);

  void
  save(const std::string& fileName) const;

  void
  removeCaProfile(const Name& caName);

  /**
   * Be cautious. This will add a new trust anchor for requesters.
   */
  void
  addCaProfile(const CaProfile& profile);

  const std::list<CaProfile>&
  getCaItems() const;

private:
  std::list<CaProfile> m_caItems;
};

} // namespace requester
} // namespace ndncert
} // namespace ndn

#endif // NDNCERT_CONFIGURATION_HPP
