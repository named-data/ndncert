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

#include <boost/throw_exception.hpp>
#include <ndn-cxx/encoding/tlv.hpp>

namespace ndn {
namespace ndncert {

// For Client
Block
PROBE::encodeApplicationParameters(std::vector<std::tuple<std::string, std::string>>&& parameters)
{
  auto content = makeEmptyBlock(tlv::ApplicationParameters);
  for (size_t i = 0; i < parameters.size(); ++i) {
    content.push_back(makeStringBlock(tlv_parameter_key, std::get<0>(parameters[i])));
    content.push_back(makeStringBlock(tlv_parameter_value, std::get<1>(parameters[i])));
  }
  content.encode();
  return content;
}

std::vector<std::tuple<std::string, std::string>>
PROBE::decodeApplicationParameters(const Block& block)
{
  std::vector<std::tuple<std::string, std::string>> result;
  block.parse();
  for (size_t i = 0; i < block.elements().size() - 1; ++i) {
    if (block.elements().at(i).type() == tlv_parameter_key && block.elements().at(i + 1).type() == tlv_parameter_value) {
      result.push_back(std::make_tuple(readString(block.elements().at(i)), readString(block.elements().at(i + 1))));
    }
  }
  return result;
}

Block
PROBE::encodeDataContent(const std::vector<Name>& identifiers, boost::optional<size_t> maxSuffixLength)
{
  Block content = makeEmptyBlock(tlv::Content);
  for (const auto& name : identifiers) {
    content.push_back(makeNestedBlock(tlv_probe_response, name));
  }
  if (maxSuffixLength) {
    content.push_back(makeNonNegativeIntegerBlock(tlv_max_suffix_length, *maxSuffixLength));
  }
  content.encode();
  return content;
}

std::vector<Name>
PROBE::decodeDataContent(const Block& block)
{
  std::vector<Name> result;
  block.parse();
  for (const auto& item : block.elements()) {
    if (item.type() == tlv_probe_response) {
      result.push_back(Name(item.blockFromValue()));
    }
  }
  return result;
}

}  // namespace ndncert
}  // namespace ndn