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

#ifndef NDNCERT_DETAIL_CA_MEMORY_HPP
#define NDNCERT_DETAIL_CA_MEMORY_HPP

#include "detail/ca-storage.hpp"

namespace ndn {
namespace ndncert {
namespace ca {

class CaMemory : public CaStorage
{
public:
  CaMemory(const Name& caName = Name(), const std::string& path = "");
  const static std::string STORAGE_TYPE;

public:
  /**
   * @throw if request cannot be fetched from underlying data storage
   */
  RequestState
  getRequest(const RequestID& requestId) override;

  /**
   * @throw if there is an existing request with the same request ID
   */
  void
  addRequest(const RequestState& request) override;

  void
  updateRequest(const RequestState& request) override;

  void
  deleteRequest(const RequestID& requestId) override;

  std::list<RequestState>
  listAllRequests() override;

  std::list<RequestState>
  listAllRequests(const Name& caName) override;

private:
  std::map<RequestID, RequestState> m_requests;
};

} // namespace ca
} // namespace ndncert
} // namespace ndn

#endif // NDNCERT_DETAIL_CA_MEMORY_HPP
