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

#include "probe.hpp"
#include "../logging.hpp"
#include <ndn-cxx/encoding/tlv.hpp>
#include <boost/throw_exception.hpp>

namespace ndn {
namespace ndncert {

// For Client
std::vector<std::string>
PROBE::parseProbeComponents(const std::string& probe)
{
  std::vector<std::string> components;
  std::string delimiter = ":";
  size_t last = 0;
  size_t next = 0;
  while ((next = probe.find(delimiter, last)) != std::string::npos) {
    components.push_back(probe.substr(last, next - last));
    last = next + 1;
  }
  components.push_back(probe.substr(last));
  return components;
}

Block
PROBE::encodeApplicationParametersFromProbeInfo(const ClientCaItem& ca, const std::string& probeInfo)
{
  auto content = makeEmptyBlock(tlv::ApplicationParameters);

  std::vector<std::string> fields = parseProbeComponents(ca.m_probe);
  std::vector<std::string> arguments = parseProbeComponents(probeInfo);
  ;

  if (arguments.size() != fields.size()) {
    BOOST_THROW_EXCEPTION(std::runtime_error("Error in genProbeRequestJson: argument list does not match field list in the config file."));
  }

  for (size_t i = 0; i < fields.size(); ++i) {
    content.push_back(
        makeStringBlock(tlv_parameter_key, fields.at(i)));
    content.push_back(
        makeStringBlock(tlv_parameter_value, arguments.at(i)));
  }
  content.encode();
  return content;
}

// For CA
Block
PROBE::encodeDataContent(const Name& identifier, const std::string& m_probe, const Block& parameterTLV)
{
  std::vector<std::string> fields;
  std::string delimiter = ":";
  size_t last = 0;
  size_t next = 0;
  while ((next = m_probe.find(delimiter, last)) != std::string::npos) {
    fields.push_back(m_probe.substr(last, next - last));
    last = next + 1;
  }
  fields.push_back(m_probe.substr(last));

  Block content = makeEmptyBlock(tlv::Content);

  // TODO: Currently have no mechanism to utilize the given params to determine name
  //for (size_t i = 0; i < fields.size(); ++i) {
  //  root.put(fields.at(i), parameterJson.get(fields.at(i), ""));
  //}

  content.push_back(makeNestedBlock(tlv_probe_response, identifier));

  // TODO: Must be determined based on CA config
  content.push_back(makeEmptyBlock(tlv_allow_longer_name));
  content.encode();
  return content;
}

}  // namespace ndncert
}  // namespace ndn