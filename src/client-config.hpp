/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/**
 * Copyright (c) 2017-2018, Regents of the University of California.
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

#include "certificate-request.hpp"
#include <ndn-cxx/security/v2/certificate.hpp>

namespace ndn {
namespace ndncert {

/**
 * @brief The configuration for a trusted CA from a requester's perspective
 */
class ClientCaItem
{
public:
  // The identity name of the CA. Extracted from config field "ca-prefix"
  Name m_caName;

  // A brief introduction to the CA. Extracted from config field "ca-info"
  std::string m_caInfo;
  // An instruction for requesters to use _PROBE. Extracted from config field "probe"
  std::string m_probe;
  // Whether support list function
  bool m_isListEnabled;
  // An instruction for requesters to get a recommended CA. Extracted from config field "target-list"
  std::string m_targetedList;

  // CA's certificate
  security::v2::Certificate m_anchor;
};

/**
 * @brief Represents Client configuration
 *
 * For Client configuration format, please refer to:
 *   https://github.com/named-data/ndncert/wiki/Client-Configuration-Sample
 */
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
  load(const JsonSection& configSection);

  void
  addNewCaItem(const ClientCaItem& item);

  void
  removeCaItem(const Name& caName);

  static ClientCaItem
  extractCaItem(const JsonSection& configSection);

public:
  std::list<ClientCaItem> m_caItems;
  std::string m_localNdncertAnchor;
};

} // namespace ndncert
} // namespace ndn

#endif // NDNCERT_CLIENT_CONFIG_HPP
