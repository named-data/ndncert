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

#ifndef NDNCERT_DETAIL_INFO_ENCODER_HPP
#define NDNCERT_DETAIL_INFO_ENCODER_HPP

#include "detail/ca-profile.hpp"

namespace ndncert::infotlv {

/**
 * Encode CA configuration and its certificate into a TLV block as INFO Data packet content.
 */
Block
encodeDataContent(const CaProfile& caConfig, const Certificate& certificate);

/**
 * Decode CA configuration from the TLV block of INFO Data packet content.
 */
CaProfile
decodeDataContent(const Block& block);

} // namespace ndncert::infotlv

#endif // NDNCERT_DETAIL_INFO_ENCODER_HPP
