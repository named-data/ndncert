/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2017-2022, Regents of the University of California.
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

#include "detail/probe-encoder.hpp"

namespace ndncert::probetlv {

Block
encodeApplicationParameters(const std::multimap<std::string, std::string>& parameters)
{
  Block content(ndn::tlv::ApplicationParameters);
  for (const auto& items : parameters) {
    content.push_back(ndn::makeStringBlock(tlv::ParameterKey, items.first));
    content.push_back(ndn::makeStringBlock(tlv::ParameterValue, items.second));
  }
  content.encode();
  return content;
}

std::multimap<std::string, std::string>
decodeApplicationParameters(const Block& block)
{
  std::multimap<std::string, std::string> result;
  block.parse();
  const auto& elements = block.elements();
  for (size_t i = 0; i < elements.size(); i++) {
    if (i + 1 < elements.size() && elements[i].type() == tlv::ParameterKey &&
        elements[i + 1].type() == tlv::ParameterValue) {
      result.emplace(readString(elements.at(i)), readString(elements.at(i + 1)));
      i++;
    }
    else if (ndn::tlv::isCriticalType(elements[i].type())) {
      NDN_THROW(std::runtime_error("Unrecognized TLV Type: " + std::to_string(elements[i].type())));
    }
    else {
      //ignore
    }
  }
  return result;
}

Block
encodeDataContent(const std::vector<Name>& identifiers, std::optional<size_t> maxSuffixLength,
                  const std::vector<Name>& redirectionItems)
{
  Block content(ndn::tlv::Content);
  for (const auto& name : identifiers) {
    Block item(tlv::ProbeResponse);
    item.push_back(name.wireEncode());
    if (maxSuffixLength) {
      item.push_back(ndn::makeNonNegativeIntegerBlock(tlv::MaxSuffixLength, *maxSuffixLength));
    }
    content.push_back(item);
  }

  for (const auto& item : redirectionItems) {
    content.push_back(makeNestedBlock(tlv::ProbeRedirect, item));
  }

  content.encode();
  return content;
}

void
decodeDataContent(const Block& block, std::vector<std::pair<Name, int>>& availableNames,
                  std::vector<Name>& availableRedirection)
{
  block.parse();
  for (const auto& item : block.elements()) {
    if (item.type() == tlv::ProbeResponse) {
      item.parse();
      Name elementName;
      int maxSuffixLength = 0;
      for (const auto& subBlock : item.elements()) {
        if (subBlock.type() == ndn::tlv::Name) {
          if (!elementName.empty()) {
            NDN_THROW(std::runtime_error("Invalid probe format"));
          }
          elementName.wireDecode(subBlock);
        }
        else if (subBlock.type() == tlv::MaxSuffixLength) {
          maxSuffixLength = readNonNegativeInteger(subBlock);
        }
        else if (ndn::tlv::isCriticalType(subBlock.type())) {
          NDN_THROW(std::runtime_error("Unrecognized TLV Type in probe name item: " + std::to_string(subBlock.type())));
        }
        else {
          //ignore
        }
      }
      if (elementName.empty()) {
        NDN_THROW(std::runtime_error("Invalid probe format"));
      }
      availableNames.emplace_back(elementName, maxSuffixLength);
    }
    else if (item.type() == tlv::ProbeRedirect) {
      availableRedirection.emplace_back(Name(item.blockFromValue()));
    }
    else if (ndn::tlv::isCriticalType(item.type())) {
      NDN_THROW(std::runtime_error("Unrecognized TLV Type: " + std::to_string(item.type())));
    }
    else {
      //ignore
    }
  }
}

} // namespace ndncert::probetlv
