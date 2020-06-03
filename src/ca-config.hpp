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

#ifndef NDNCERT_CA_CONFIG_HPP
#define NDNCERT_CA_CONFIG_HPP

#include "certificate-request.hpp"
#include "client-config.hpp"
#include <ndn-cxx/security/certificate.hpp>

namespace ndn {
namespace ndncert {

/**
 * @brief The function should be able to convert a probe info string to an identity name
 *
 * The function should throw exceptions when there is an unexpected input.
 */
using ProbeHandler = function<std::string/*identity name*/ (const JsonSection& json/*requester input*/)>;

/**
 * @brief The function would be invoked whenever the certificate request status gets update
 *
 * The callback is used to notice the CA application or CA command line tool. The callback is
 * fired whenever a request instance is created, challenge status is updated, and when certificate
 * is issued.
 */
using StatusUpdateCallback = function<void (const CertificateRequest&/*the latest request info*/)>;

/**
 * @brief Represents a CA configuration instance
 *
 * For CA configuration format, please refer to:
 *   https://github.com/named-data/ndncert/wiki/Ca-Configuration-Sample
 *
 * @note Changes made to CaConfig won't be written back to the config
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
  /**
   * @throw CaConfig::Error when config file does not exist
   * @throw CaConfig::Error when the JSON text in the file cannot be parsed correctly
   * @throw CaConfig::Error when the ca-prefix attribute in JSON text is empty
   * @throw CaConfig::Error when the challenge is not specified or is not supported
   */
  void
  load(const std::string& fileName);

private:
  void
  parse(const JsonSection& configJson);

  std::list<std::string>
  parseChallengeList(const JsonSection& configSection);

public:
  // basic info
  Name m_caName;

  // essential config
  time::seconds m_freshnessPeriod;
  time::days m_validityPeriod;
  std::list<std::string> m_supportedChallenges;

  // optional parameters
  std::string m_probe;
  std::string m_caInfo;

  // callbacks
  ProbeHandler m_probeHandler;
  StatusUpdateCallback m_statusUpdateCallback;
};

} // namespace ndncert
} // namespace ndn

#endif // NDNCERT_CA_CONFIG_HPP
