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

namespace ndn {
namespace ndncert {

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
PROBE::encodeDataContent(const std::vector<Name>& identifiers, boost::optional<size_t> maxSuffixLength,
                         boost::optional<std::vector<std::shared_ptr<security::Certificate>>> redirectionItems)
{
  Block content = makeEmptyBlock(tlv::Content);
  for (const auto& name : identifiers) {
    Block item(tlv_probe_response);
    item.push_back(name.wireEncode());
    if (maxSuffixLength) {
      item.push_back(makeNonNegativeIntegerBlock(tlv_max_suffix_length, *maxSuffixLength));
    }
    content.push_back(item);
  }
  if (redirectionItems) {
    for (const auto& item : *redirectionItems) {
      content.push_back(makeNestedBlock(tlv_probe_redirect, item->getFullName()));
    }
  }
  content.encode();
  return content;
}

void
PROBE::decodeDataContent(const Block& block,
                         std::vector<std::pair<Name, int>>& availableNames,
                         std::vector<Name>& availableRedirection)
{
  block.parse();
  for (const auto& item : block.elements()) {
    if (item.type() == tlv_probe_response) {
      item.parse();
      Name elementName;
      int maxSuffixLength = 0;
      for (const auto& subBlock: item.elements()) {
          if (subBlock.type() == tlv::Name) {
              if (!elementName.empty()) {
                  BOOST_THROW_EXCEPTION(std::runtime_error("Invalid probe format"));
              }
              elementName.wireDecode(subBlock);
          } else if (subBlock.type() == tlv_max_suffix_length) {
              maxSuffixLength = readNonNegativeInteger(subBlock);
          }
      }
      if (elementName.empty()) {
          BOOST_THROW_EXCEPTION(std::runtime_error("Invalid probe format"));
      }
      availableNames.emplace_back(elementName, maxSuffixLength);
    }
    if (item.type() == tlv_probe_redirect) {
      availableRedirection.emplace_back(Name(item.blockFromValue()));
    }
  }
}

} // namespace ndncert
} // namespace ndn