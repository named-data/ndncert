/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/**
 * Copyright (c) 2017, Regents of the University of California.
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

#ifndef NDNCERT_LOGGING_HPP
#define NDNCERT_LOGGING_HPP

#include <ndn-cxx/util/logger.hpp>

namespace ndn {
namespace ndncert {

#define _LOG_INIT(name) NDN_LOG_INIT(ndncert.name)

#define _LOG_DEBUG(x) NDN_LOG_DEBUG(__FILE__ << ":" << __LINE__ << ":" << " " << x)

#define _LOG_TRACE(x) NDN_LOG_TRACE(__FILE__ << ":" << __LINE__ << ":" << " " << x)

#define _LOG_ERROR(x) NDN_LOG_ERROR(x)

} // ndncert
} // ndn

#endif // NDNCERT_LOGGING_HPP
