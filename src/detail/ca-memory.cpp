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

#include "ca-memory.hpp"
#include <ndn-cxx/security/validation-policy.hpp>

namespace ndn {
namespace ndncert {

const std::string
CaMemory::STORAGE_TYPE = "ca-storage-memory";

NDNCERT_REGISTER_CA_STORAGE(CaMemory);

CaMemory::CaMemory(const Name& caName, const std::string& path)
  : CaStorage()
{
}

CaState
CaMemory::getRequest(const std::string& requestId)
{
  auto search = m_requests.find(requestId);
  if (search == m_requests.end()) {
    NDN_THROW(std::runtime_error("Request " + requestId + " doest not exists"));
  }
  return search->second;
}

void
CaMemory::addRequest(const CaState& request)
{
  auto search = m_requests.find(request.m_requestId);
  if (search == m_requests.end()) {
    m_requests[request.m_requestId] = request;
  }
  else {
    NDN_THROW(std::runtime_error("Request " + request.m_requestId + " already exists"));
  }
}

void
CaMemory::updateRequest(const CaState& request)
{
  m_requests[request.m_requestId].m_status = request.m_status;
  m_requests[request.m_requestId].m_challengeState = request.m_challengeState;
}

void
CaMemory::deleteRequest(const std::string& requestId)
{
  auto search = m_requests.find(requestId);
  auto keyName = search->second.m_cert.getKeyName();
  if (search != m_requests.end()) {
    m_requests.erase(search);
  }
}

std::list<CaState>
CaMemory::listAllRequests()
{
  std::list<CaState> result;
  for (const auto& entry : m_requests) {
    result.push_back(entry.second);
  }
  return result;
}

std::list<CaState>
CaMemory::listAllRequests(const Name& caName)
{
  std::list<CaState> result;
  for (const auto& entry : m_requests) {
    if (entry.second.m_caPrefix == caName) {
      result.push_back(entry.second);
    }
  }
  return result;
}

} // namespace ndncert
} // namespace ndn
