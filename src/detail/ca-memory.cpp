/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2017-2021, Regents of the University of California.
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

#include "detail/ca-memory.hpp"

namespace ndncert {
namespace ca {

const std::string CaMemory::STORAGE_TYPE = "ca-storage-memory";
NDNCERT_REGISTER_CA_STORAGE(CaMemory);

CaMemory::CaMemory(const Name& caName, const std::string& path)
  : CaStorage()
{
}

RequestState
CaMemory::getRequest(const RequestId& requestId)
{
  auto search = m_requests.find(requestId);
  if (search == m_requests.end()) {
    NDN_THROW(std::runtime_error("Request " + ndn::toHex(requestId.data(), requestId.size()) +
                                 " does not exists"));
  }
  return search->second;
}

void
CaMemory::addRequest(const RequestState& request)
{
  auto search = m_requests.find(request.requestId);
  if (search == m_requests.end()) {
    m_requests.insert(std::make_pair(request.requestId, request));
  }
  else {
    NDN_THROW(std::runtime_error("Request " + ndn::toHex(request.requestId.data(), request.requestId.size()) +
                                 " already exists"));
  }
}

void
CaMemory::updateRequest(const RequestState& request)
{
  auto search = m_requests.find(request.requestId);
  if (search == m_requests.end()) {
    m_requests.insert(std::make_pair(request.requestId, request));
  }
  else {
    search->second = request;
  }
}

void
CaMemory::deleteRequest(const RequestId& requestId)
{
  auto search = m_requests.find(requestId);
  auto keyName = search->second.cert.getKeyName();
  if (search != m_requests.end()) {
    m_requests.erase(search);
  }
}

std::list<RequestState>
CaMemory::listAllRequests()
{
  std::list<RequestState> result;
  for (const auto& entry : m_requests) {
    result.push_back(entry.second);
  }
  return result;
}

std::list<RequestState>
CaMemory::listAllRequests(const Name& caName)
{
  std::list<RequestState> result;
  for (const auto& entry : m_requests) {
    if (entry.second.caPrefix == caName) {
      result.push_back(entry.second);
    }
  }
  return result;
}

} // namespace ca
} // namespace ndncert
