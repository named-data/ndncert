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

#ifndef NDNCERT_DETAIL_CA_CONFIGURATION_HPP
#define NDNCERT_DETAIL_CA_CONFIGURATION_HPP

#include "detail/ca-profile.hpp"
#include "name-assignment/assignment-func.hpp"

namespace ndncert {
namespace ca {

/**
 * @brief CA's configuration on NDNCERT.
 *
 * The format of CA configuration in JSON
 * {
 *  "ca-prefix": "",
 *  "ca-info": "",
 *  "max-validity-period": "",
 *  "max-suffix-length": "",
 *  "probe-parameters":
 *  [
 *    {"probe-parameter-key": ""},
 *    {"probe-parameter-key": ""}
 *  ]
 *  "supported-challenges":
 *  [
 *    {"challenge": ""},
 *    {"challenge": ""}
 *  ]
 * }
 */
class CaConfig
{
public:
  /**
   * @brief Load CA configuration from the file.
   * @throw std::runtime_error when config file cannot be correctly parsed.
   */
  void
  load(const std::string& fileName);

public:
  /**
   * @brief the CA's profile
   */
  CaProfile caProfile;
  /**
   * @brief Used for CA redirection
   */
  std::vector<std::shared_ptr<Certificate>> redirection;
  /**
   * @brief Name Assignment Functions
   */
  std::vector<std::unique_ptr<NameAssignmentFunc>> nameAssignmentFuncs;
};

} // namespace ca
} // namespace ndncert

#endif // NDNCERT_DETAIL_CA_CONFIGURATION_HPP
