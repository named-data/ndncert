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

#ifndef NDNCERT_PROTOCOL_DETAIL_CHALLENGE_HPP
#define NDNCERT_PROTOCOL_DETAIL_CHALLENGE_HPP

#include "../ca-state.hpp"

namespace ndn {
namespace ndncert {

class CHALLENGE {
public:
  static Block
  encodeDataPayload(const CaState& request);

  struct DecodedData{
      Status status;
      std::string challengeStatus;
      size_t remainingTries;
      time::seconds remainingTime;
      optional<Name> issuedCertName;
  };

  static DecodedData
  decodeDataPayload(const Block& data);
};

}  // namespace ndncert
}  // namespace ndn

#endif // NDNCERT_PROTOCOL_DETAIL_HPP