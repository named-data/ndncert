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

#ifndef NDNCERT_CA_DETAIL_CA_MEMORY_HPP
#define NDNCERT_CA_DETAIL_CA_MEMORY_HPP

#include "../ca-storage.hpp"

namespace ndn {
namespace ndncert {

class CaMemory : public CaStorage
{
public:
  const static std::string STORAGE_TYPE;

public:
  // certificate request related
  CertificateRequest
  getRequest(const std::string& requestId) override;

  void
  addRequest(const CertificateRequest& request) override;

  void
  updateRequest(const CertificateRequest& request) override;

  void
  deleteRequest(const std::string& requestId) override;

  // certificate related
  security::v2::Certificate
  getCertificate(const std::string& certId) override;

  void
  addCertificate(const std::string& certId, const security::v2::Certificate& cert) override;

  void
  updateCertificate(const std::string& certId, const security::v2::Certificate& cert) override;

  void
  deleteCertificate(const std::string& certId) override;

private:
  std::map<std::string, CertificateRequest> m_requests;
  std::map<std::string, security::v2::Certificate> m_issuedCerts;
};

} // namespace ndncert
} // namespace ndn

#endif // NDNCERT_CA_DETAIL_CA_MEMORY_HPP
