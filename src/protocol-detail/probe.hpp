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

#ifndef NDNCERT_PROTOCOL_DETAIL_PROBE_HPP
#define NDNCERT_PROTOCOL_DETAIL_PROBE_HPP

#include "../ca-config.hpp"
#include "../client-config.hpp"

namespace ndn {
namespace ndncert {

class PROBE {

public:
  /**
   * @brief Error that can be thrown from PROBE
   */
  class Error : public std::runtime_error
  {
    public:
    using std::runtime_error::runtime_error;
  };

public:
  static std::vector<std::string>
  parseProbeComponents(const std::string& probe);

  static Block
  encodeApplicationParametersFromProbeInfo(const ClientCaItem& ca, const std::string& probeInfo);

  static Block
  encodeDataContent(const Name& identifier, const std::string& m_probe, const Block& parameterTLV);
};

}  // namespace ndncert
}  // namespace ndn

#endif // NDNCERT_PROTOCOL_DETAIL_HPP