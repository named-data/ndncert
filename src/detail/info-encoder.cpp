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

#include "detail/info-encoder.hpp"

namespace ndn {
namespace ndncert {

Block
infoEncoder::encodeDataContent(const CaProfile& caConfig, const security::Certificate& certificate)
{
  Block content(ndn::tlv::Content);
  content.push_back(makeNestedBlock(tlv::CaPrefix, caConfig.m_caPrefix));
  std::string caInfo = "";
  if (caConfig.m_caInfo == "") {
    caInfo = "Issued by " + certificate.getSignatureInfo().getKeyLocator().getName().toUri();
  }
  else {
    caInfo = caConfig.m_caInfo;
  }
  content.push_back(makeStringBlock(tlv::CaInfo, caInfo));
  for (const auto& key : caConfig.m_probeParameterKeys) {
    content.push_back(makeStringBlock(tlv::ParameterKey, key));
  }
  content.push_back(makeNonNegativeIntegerBlock(tlv::MaxValidityPeriod, caConfig.m_maxValidityPeriod.count()));
  content.push_back(makeNestedBlock(tlv::CaCertificate, certificate));
  content.encode();
  return content;
}

CaProfile
infoEncoder::decodeDataContent(const Block& block)
{
  CaProfile result;
  block.parse();
  for (auto const& item : block.elements()) {
    switch (item.type()) {
    case tlv::CaPrefix:
      item.parse();
      result.m_caPrefix.wireDecode(item.get(ndn::tlv::Name));
      break;
    case tlv::CaInfo:
      result.m_caInfo = readString(item);
      break;
    case tlv::ParameterKey:
      result.m_probeParameterKeys.push_back(readString(item));
      break;
    case tlv::MaxValidityPeriod:
      result.m_maxValidityPeriod = time::seconds(readNonNegativeInteger(item));
      break;
    case tlv::CaCertificate:
      item.parse();
      result.m_cert = std::make_shared<security::Certificate>(item.get(ndn::tlv::Data));
      break;
    default:
      continue;
      break;
    }
  }
  return result;
}

} // namespace ndncert
} // namespace ndn