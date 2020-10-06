/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
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

#ifndef NDNCERT_CA_DETAIL_CA_SQLITE_HPP
#define NDNCERT_CA_DETAIL_CA_SQLITE_HPP

#include "../ca-module.hpp"
#include "../ca-state.hpp"

struct sqlite3;

namespace ndn {
namespace ndncert {

class CaSqlite : public CaStorage
{
public:
  const static std::string STORAGE_TYPE;

  explicit
  CaSqlite(const Name& caName, const std::string& path = "");

  ~CaSqlite();

public:
  // request related
  CaState
  getRequest(const std::string& requestId) override;

  void
  addRequest(const CaState& request) override;

  void
  updateRequest(const CaState& request) override;

  void
  deleteRequest(const std::string& requestId) override;

  std::list<CaState>
  listAllRequests() override;

  std::list<CaState>
  listAllRequests(const Name& caName) override;

private:
  sqlite3* m_database;
};

} // namespace ndncert
} // namespace ndn

#endif // NDNCERT_CA_DETAIL_CA_SQLITE_HPP
