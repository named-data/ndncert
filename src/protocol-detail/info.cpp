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

#include "info.hpp"

namespace ndn {
namespace ndncert {

Block
INFO::encodeContentFromCAConfig(const CaConfig& caConfig, const security::v2::Certificate& certificate)
{
  auto content = makeEmptyBlock(tlv::Content);
  content.push_back(makeNestedBlock(tlv_ca_prefix, caConfig.m_caPrefix));
  std::string caInfo = "";
  if (caConfig.m_caInfo == "") {
    caInfo = "Issued by " + certificate.getSignature().getKeyLocator().getName().toUri();
  } else {
    caInfo = caConfig.m_caInfo;
  }
  content.push_back(makeStringBlock(tlv_ca_info, caInfo));

  for (const auto& key : caConfig.m_probeParameterKeys) {
    content.push_back(makeStringBlock(tlv_parameter_key, key));
  }
  content.push_back(makeNonNegativeIntegerBlock(tlv_max_validity_period, caConfig.m_maxValidityPeriod.count()));
  content.push_back(makeNestedBlock(tlv_ca_certificate, certificate));
  content.encode();
  return content;
}

ClientCaItem
INFO::decodeClientConfigFromContent(const Block& block)
{
  ClientCaItem result;
  block.parse();
  for (auto const& item : block.elements()) {
    if (item.type() == tlv_ca_prefix) {
      item.parse();
      result.m_caPrefix.wireDecode(item.get(tlv::Name));
    }
    else if (item.type() == tlv_ca_info) {
      result.m_caInfo = readString(item);
    }
    else if (item.type() == tlv_parameter_key) {
      result.m_probeParameterKeys.push_back(readString(item));
    }
    else if (item.type() == tlv_max_validity_period) {
      result.m_maxValidityPeriod = time::seconds(readNonNegativeInteger(item));
    }
    else if (item.type() == tlv_ca_certificate) {
      item.parse();
      result.m_anchor.wireDecode(item.get(tlv::Data));
    }
    else {
      continue;
    }
  }
  return result;
}

}  // namespace ndncert
}  // namespace ndn