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

#include <ndn-cxx/security/v2/validation-policy.hpp>

namespace ndn {
namespace ndncert {

const std::string
CaMemory::STORAGE_TYPE = "ca-storage-memory";

NDNCERT_REGISTER_CA_STORAGE(CaMemory);

CaState
CaMemory::getRequest(const std::string& requestId)
{
  auto search = m_requests.find(requestId);
  if (search == m_requests.end()) {
    BOOST_THROW_EXCEPTION(Error("Request " + requestId + " doest not exists"));
  }
  return search->second;
}

void
CaMemory::addRequest(const CaState& request)
{
    auto keyNameTLV = request.m_cert.getKeyName();
    if (request.m_requestType == RequestType::NEW) {
      if (m_requestKeyIndex.find(keyNameTLV) != m_requestKeyIndex.end()
            && !m_requestKeyIndex.find(keyNameTLV)->second.empty()){
        BOOST_THROW_EXCEPTION(Error("Request for " + keyNameTLV.toUri() + " already exists"));
        return;
      }
      if (m_certsKeyIndex.find(keyNameTLV) != m_certsKeyIndex.end()) {
        BOOST_THROW_EXCEPTION(Error("Cert for " + keyNameTLV.toUri() + " already exists"));
        return;
      }
    }

  auto search = m_requests.find(request.m_requestId);
  if (search == m_requests.end()) {
    m_requests[request.m_requestId] = request;
    m_requestKeyIndex[keyNameTLV].insert(request.m_requestId);
  }
  else {
    BOOST_THROW_EXCEPTION(Error("Request " + request.m_requestId + " already exists"));
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
    m_requestKeyIndex.find(keyName)->second.erase(requestId);
    if (m_requestKeyIndex.find(keyName)->second.empty()) m_requestKeyIndex.erase(keyName);
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

// certificate related
security::v2::Certificate
CaMemory::getCertificate(const std::string& certId)
{
  auto search = m_issuedCerts.find(certId);
  if (search != m_issuedCerts.end()) {
    return search->second;
  }
  BOOST_THROW_EXCEPTION(Error("Certificate with ID " + certId + " does not exists"));
}

void
CaMemory::addCertificate(const std::string& certId, const security::v2::Certificate& cert)
{
  auto search = m_issuedCerts.find(certId);
  if (search == m_issuedCerts.end()) {
    m_issuedCerts[certId] = cert;
    m_certsKeyIndex[cert.getKeyName()] = certId;
  }
  else {
    BOOST_THROW_EXCEPTION(Error("Certificate " + cert.getName().toUri() + " already exists"));
  }
}

void
CaMemory::updateCertificate(const std::string& certId, const security::v2::Certificate& cert)
{
  m_issuedCerts[certId] = cert;
}

void
CaMemory::deleteCertificate(const std::string& certId)
{
  auto search = m_issuedCerts.find(certId);
  if (search != m_issuedCerts.end()) {
    m_certsKeyIndex.erase(search->second.getKeyName());
    m_issuedCerts.erase(search);
  }
}

std::list<security::v2::Certificate>
CaMemory::listAllIssuedCertificates()
{
  std::list<security::v2::Certificate> result;
  for (const auto& entry : m_issuedCerts) {
    result.push_back(entry.second);
  }
  return result;
}

std::list<security::v2::Certificate>
CaMemory::listAllIssuedCertificates(const Name& caName)
{
  std::list<security::v2::Certificate> result;
  for (const auto& entry : m_issuedCerts) {
    const auto& klName = entry.second.getSignature().getKeyLocator().getName();
    if (security::v2::extractIdentityFromKeyName(klName) == caName) {
      result.push_back(entry.second);
    }
  }
  return result;
}

} // namespace ndncert
} // namespace ndn
