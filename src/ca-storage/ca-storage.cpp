/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/**
 * Copyright (c) 2017-2019, Regents of the University of California.
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

#include "ca-storage/ca-storage.hpp"

namespace ndn {
namespace ndncert {

unique_ptr<CaStorage>
CaStorage::createCaStorage(const std::string& caStorageType, const Name& caName, const std::string& path)
{
  CaStorageFactory& factory = getFactory();
  auto i = factory.find(caStorageType);
  return i == factory.end() ? nullptr : i->second(caName, path);
}

CaStorage::CaStorageFactory&
CaStorage::getFactory()
{
  static CaStorage::CaStorageFactory factory;
  return factory;
}

} // namespace ndncert
} // namespace ndn
