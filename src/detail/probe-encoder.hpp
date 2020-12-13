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

#ifndef NDNCERT_DETAIL_PROBE_ENCODER_HPP
#define NDNCERT_DETAIL_PROBE_ENCODER_HPP

#include "detail/ndncert-common.hpp"

namespace ndn {
namespace ndncert {
namespace probetlv {

// For Client use
Block
encodeApplicationParameters(const std::multimap<std::string, std::string>& parameters);

void
decodeDataContent(const Block& block, std::vector<std::pair<Name, int>>& availableNames,
                  std::vector<Name>& availableRedirection);

// For CA use
Block
encodeDataContent(const std::vector<Name>& identifiers,
                  optional<size_t> maxSuffixLength = nullopt,
                  std::vector<std::shared_ptr<security::Certificate>> redirectionItems =
                          std::vector<std::shared_ptr<security::Certificate>>());

std::multimap<std::string, std::string>
decodeApplicationParameters(const Block& block);

} // namespace probetlv
} // namespace ndncert
} // namespace ndn

#endif // NDNCERT_DETAIL_PROBE_ENCODER_HPP