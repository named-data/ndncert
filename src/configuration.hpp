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

#include "request-state.hpp"

namespace ndn {
namespace ndncert {

struct CaConfigItem {
  /**
   * CA Name prefix (without /CA suffix).
   */
  Name m_caPrefix;
  /**
   * CA Information.
   * Default: "".
   */
  std::string m_caInfo;
  /**
   * A list of parameter-keys for PROBE.
   * Default: empty list.
   */
  std::list<std::string> m_probeParameterKeys;
  /**
   * Maximum allowed validity period of the certificate being requested.
   * The value is in the unit of second.
   * Default: one day (86400 seconds).
   */
  time::seconds m_maxValidityPeriod;
  /**
   * Maximum allowed suffix length of requested name.
   * E.g., When its value is 2, at most 2 name components can be assigned after m_caPrefix.
   * Default: none.
   */
  boost::optional<size_t> m_maxSuffixLength;
  /**
   * A list of supported challenges. Only CA side will have m_supportedChallenges.
   * Default: empty list.
   */
  std::list<std::string> m_supportedChallenges;
  /**
   * CA's certificate. Only Client side will have m_cert.
   * Default: nullptr.
   */
  std::shared_ptr<security::v2::Certificate> m_cert;

  void
  parse(const JsonSection& configJson);

  JsonSection
  toJson() const;

private:
  void
  parseProbeParameters(const JsonSection& section);

  void
  parseChallengeList(const JsonSection& configSection);
};

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
 * @p RequestState, input, the state of the certificate request whose status is updated.
 */
using StatusUpdateCallback = function<void(const RequestState&)>;

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
class CaConfig {
public:
  /**
   * Load CA configuration from the file.
   * @throw std::runtime_error when config file cannot be correctly parsed.
   */
  void
  load(const std::string& fileName);

  void
  save(const std::string& fileName) const;

  CaConfigItem m_caItem;
  /**
   * NameAssignmentFunc Callback function
   */
  NameAssignmentFunc m_nameAssignmentFunc;
  /**
   * StatusUpdate Callback function
   */
  StatusUpdateCallback m_statusUpdateCallback;
};

/**
 * @brief Represents Client configuration
 *
 * For Client configuration format, please refer to:
 *   https://github.com/named-data/ndncert/wiki/Client-Configuration-Sample
 */
class ClientConfig {
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
  removeCaItem(const Name& caName);

  std::list<CaConfigItem> m_caItems;
};

}  // namespace ndncert
}  // namespace ndn

#endif  // NDNCERT_CA_CONFIG_HPP
