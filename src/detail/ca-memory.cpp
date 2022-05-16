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

#include "detail/ca-memory.hpp"
//added_gm by liupenghui 
#if 1
#include <ndn-cxx/security/validation-policy.hpp>
#endif

namespace ndncert::ca {

const std::string CaMemory::STORAGE_TYPE = "ca-storage-memory";
NDNCERT_REGISTER_CA_STORAGE(CaMemory);

CaMemory::CaMemory(const Name&, const std::string&)
  : CaStorage()
{
}

RequestState
CaMemory::getRequest(const RequestId& requestId)
{
  auto it = m_requests.find(requestId);
  if (it == m_requests.end()) {
    NDN_THROW(std::runtime_error("Request " + ndn::toHex(requestId) + " does not exist"));
  }
  return it->second;
}

void
CaMemory::addRequest(const RequestState& request)
{
  auto result = m_requests.insert({request.requestId, request});
  if (!result.second) {
    NDN_THROW(std::runtime_error("Request " + ndn::toHex(request.requestId) + " already exists"));
  }
}

void
CaMemory::updateRequest(const RequestState& request)
{
  m_requests.insert_or_assign(request.requestId, request);
}

void
CaMemory::deleteRequest(const RequestId& requestId)
{
  m_requests.erase(requestId);
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

//added_gm by liupenghui 
#if 1
void
CaMemory::addCertificate(const std::string& apply_email, const Certificate& cert)
{
  auto search = m_issuedCerts.find(cert.getKeyName());
  if (search == m_issuedCerts.end()) {
  	Cert_storage cert_data;
	cert_data.email = apply_email;
	cert_data.cert = cert;
	m_issuedCerts[cert.getKeyName()] = cert_data;
  }
  else {
	NDN_THROW(std::runtime_error("Certificate " + cert.getName().toUri() + " already exists"));
  }
}


Certificate
CaMemory::getCertificate(const Name& certKeyName)
{
  auto search = m_issuedCerts.find(certKeyName);
  if (search != m_issuedCerts.end()) {
	return search->second.cert;
  }
  NDN_THROW(std::runtime_error("Certificate with certification Name " + certKeyName.toUri() + " does not exists"));
}

std::string
CaMemory::getApplyEmailofCertificate(const Certificate& cert)
{
  auto search = m_issuedCerts.find(cert.getKeyName());
  if (search != m_issuedCerts.end()) {
    return search->second.email;
  }
  NDN_THROW(std::runtime_error("Certificate with certification Name " + cert.getKeyName().toUri() + " does not exists"));
}


void
CaMemory::deleteCertificate(const Name& certKeyName)
{
  auto search = m_issuedCerts.find(certKeyName);
  if (search != m_issuedCerts.end()) {
	m_issuedCerts.erase(search);
  }
}


std::list<Certificate>
CaMemory::listAllIssuedCertificates()
{
  std::list<Certificate> result;
  for (const auto& entry : m_issuedCerts) {
	result.push_back(entry.second.cert);
  }
  return result;
}


std::list<Certificate>
CaMemory::listAllIssuedCertificates(const Name& caName)
{
  std::list<Certificate> result;
  for (const auto& entry : m_issuedCerts) {
	const auto& klName = entry.second.cert.getSignatureInfo().getKeyLocator().getName();
	if (ndn::security::v2::extractIdentityNameFromKeyLocator(klName) == caName) {
	  result.push_back(entry.second.cert);
	}
  }
  return result;
}


#endif

} // namespace ndncert::ca

