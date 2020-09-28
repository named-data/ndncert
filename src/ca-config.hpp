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
#include <ndn-cxx/security/v2/certificate.hpp>

namespace ndn {
namespace ndncert {

/**
 * @brief The name assignment function provided by the CA operator to generate available
 * namecomponents.
 * The function does not guarantee that all the returned names are available. Therefore the
 * CA should further check the availability of each returned name and remove unavailable results.
 *
 * @p vector, input, a list of parameter key-value pair used for name assignment.
 * @return a vector containing the possible namespaces derived from the parameters.
 */
using NameAssignmentFunc = function<std::vector<std::string>(const std::vector<std::tuple<std::string, std::string>>)>;

/**
 * @brief The function would be invoked whenever the certificate request status is updated.
 * The callback is used to notice the CA application or CA command line tool. The callback is
 * fired whenever a request instance is created, challenge status is updated, and when certificate
 * is issued.
 *
 * @p CertificateRequest, input, the state of the certificate request whose status is updated.
 */
using StatusUpdateCallback = function<void(const CertificateRequest&)>;

/**
 * @brief CA's configuration on NDNCERT.
 * For CA configuration format, please refer to:
 *   https://github.com/named-data/ndncert/wiki/NDNCERT-Protocol-0.3#213-ca-profile
 *
 * The format of CA configuration in JSON
 * {
 *  "ca-prefix": "",
 *  "ca-info": "",
 *  "max-validity-period": "",
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
class CaConfig {
public:
  /**
   * Load CA configuration from the file.
   *
   * @param fileName, the configuration file name.
   * @throw std::runtime_error when config file does not exist or the configuration
   *        in the file cannot be parsed correctly.
   * @throw std::runtime_error when the ca-prefix attribute in JSON text is empty.
   * @throw std::runtime_error when the challenge is not specified or is not supported.
   */
  void
  load(const std::string& fileName);

private:
  void
  parse(const JsonSection& configJson);

  void
  parseProbeParameters(const JsonSection& section);

  void
  parseChallengeList(const JsonSection& configSection);

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
   * A list of supported challenges.
   */
  std::list<std::string> m_supportedChallenges;
  /**
   * NameAssignmentFunc Callback function
   */
  NameAssignmentFunc m_nameAssignmentFunc;
  /**
   * StatusUpdate Callback function
   */
  StatusUpdateCallback m_statusUpdateCallback;
};

}  // namespace ndncert
}  // namespace ndn

#endif  // NDNCERT_CA_CONFIG_HPP
