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

#include "ca-memory.hpp"

namespace ndn {
namespace ndncert {

const std::string
CaMemory::STORAGE_TYPE = "ca-storage-memory";

NDNCERT_REGISTER_CA_STORAGE(CaMemory);

CertificateRequest
CaMemory::getRequest(const std::string& requestId)
{
  auto search = m_requests.find(requestId);
  if (search == m_requests.end()) {
    BOOST_THROW_EXCEPTION(Error("Request " + requestId + " doest not exists"));
  }
  return search->second;
}

void
CaMemory::addRequest(const CertificateRequest& request)
{
  for (auto& entry : m_requests) {
    const auto& existingRequest = entry.second;
    if (existingRequest.getCert().getKeyName() == request.getCert().getKeyName()) {
      BOOST_THROW_EXCEPTION(Error("Request for " + request.getCert().getKeyName().toUri() + " already exists"));
      return;
    }
  }
  for (auto& entry : m_issuedCerts) {
    const auto& cert = entry.second;
    if (cert.getKeyName() == request.getCert().getKeyName()) {
      BOOST_THROW_EXCEPTION(Error("Cert for " + request.getCert().getKeyName().toUri() + " already exists"));
      return;
    }
  }

  auto search = m_requests.find(request.getRequestId());
  if (search == m_requests.end()) {
    m_requests[request.getRequestId()] = request;
  }
  else {
    BOOST_THROW_EXCEPTION(Error("Request " + request.getRequestId() + " already exists"));
  }
}

void
CaMemory::updateRequest(const CertificateRequest& request)
{
  m_requests[request.getRequestId()] = request;
}

void
CaMemory::deleteRequest(const std::string& requestId)
{
  auto search = m_requests.find(requestId);
  if (search != m_requests.end()) {
    m_requests.erase(search);
  }
}

// certificate related
security::v2::Certificate
CaMemory::getCertificate(const std::string& certId)
{
  security::v2::Certificate cert;
  auto search = m_issuedCerts.find(certId);
  if (search != m_issuedCerts.end()) {
    cert = search->second;
    return cert;
  }
  else {
    BOOST_THROW_EXCEPTION(Error("Certificate with ID " + certId + " does not exists"));
  }
}

void
CaMemory::addCertificate(const std::string& certId, const security::v2::Certificate& cert)
{
  auto search = m_issuedCerts.find(certId);
  if (search == m_issuedCerts.end()) {
    m_issuedCerts[certId] = cert;
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
    m_issuedCerts.erase(search);
  }
}

} // namespace ndncert
} // namespace ndn
