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

#ifndef NDNCERT_CA_DETAIL_CA_SQLITE_HPP
#define NDNCERT_CA_DETAIL_CA_SQLITE_HPP

#include "../ca-module.hpp"
#include "../certificate-request.hpp"

struct sqlite3;

namespace ndn {
namespace ndncert {

class CaSqlite : public CaStorage
{
public:
  const static std::string STORAGE_TYPE;

  explicit
  CaSqlite(const std::string& location = "");

  ~CaSqlite();

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

  std::list<CertificateRequest>
  listAllRequests() override;

  std::list<CertificateRequest>
  listAllRequests(const Name& caName) override;

  // certificate related
  security::v2::Certificate
  getCertificate(const std::string& certId) override;

  void
  addCertificate(const std::string& certId, const security::v2::Certificate& cert) override;

  void
  updateCertificate(const std::string& certId, const security::v2::Certificate& cert) override;

  void
  deleteCertificate(const std::string& certId) override;

  std::list<security::v2::Certificate>
  listAllIssuedCertificates() override;

  std::list<security::v2::Certificate>
  listAllIssuedCertificates(const Name& caName) override;

PUBLIC_WITH_TESTS_ELSE_PRIVATE:
  static std::string
  convertJson2String(const JsonSection& json);

  static JsonSection
  convertString2Json(const std::string& jsonContent);

private:
  sqlite3* m_database;
};

} // namespace ndncert
} // namespace ndn

#endif // NDNCERT_CA_DETAIL_CA_SQLITE_HPP
