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

#ifndef NDNCERT_CLIENT_CONFIG_HPP
#define NDNCERT_CLIENT_CONFIG_HPP

#include "certificate-request.hpp"
<<<<<<< HEAD
#include <ndn-cxx/security/certificate.hpp>
=======

#include <ndn-cxx/security/v2/certificate.hpp>
>>>>>>> Update CaConfig and ClientCaItem. Add INFO packet encoding and decoding.

namespace ndn {
namespace ndncert {

/**
 * @brief The configuration for a trusted CA from a requester's perspective
 */
class ClientCaItem {
public:
  /**
   * CA Name prefix (without /CA suffix).
   */
  Name m_caPrefix;
  /**
   * CA Information.
   */
  std::string m_caInfo;
  /**
   * A list of parameter-keys for PROBE.
   */
  std::list<std::string> m_probeParameterKeys;
  /**
   * Maximum allowed validity period of the certificate being requested.
   * The value is in the unit of second.
   */
  time::seconds m_maxValidityPeriod;
  /**
   * CA's certificate.
   */
  security::v2::Certificate m_anchor;

  //=======old

  // The identity name of the CA. Extracted from config field "ca-prefix"
  Name m_caName;

  // An instruction for requesters to use _PROBE. Extracted from config field "probe"
  std::string m_probe;  // "email::uid::name"
};

/**
 * @brief Represents Client configuration
 *
 * For Client configuration format, please refer to:
 *   https://github.com/named-data/ndncert/wiki/Client-Configuration-Sample
 */
class ClientConfig {
public:
  class Error : public std::runtime_error {
  public:
    using std::runtime_error::runtime_error;
  };

public:
  /**
   * @throw ClientConfig::Error when config file does not exist
   * @throw ClientConfig::Error when the JSON text in the file cannot be parsed correctly
   * @throw ClientConfig::Error when the ca-prefix attribute in JSON text is empty
   * @throw ClientConfig::Error when the certificate in JSON text cannot be parsed correctly
   */
  void
  load(const std::string& fileName);

  void
  load(const JsonSection& configSection);

  void
  save(const std::string& fileName);

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

}  // namespace ndncert
}  // namespace ndn

#endif  // NDNCERT_CLIENT_CONFIG_HPP
