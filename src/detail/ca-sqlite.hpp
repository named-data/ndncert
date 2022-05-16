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

#ifndef NDNCERT_DETAIL_CA_SQLITE_HPP
#define NDNCERT_DETAIL_CA_SQLITE_HPP

#include "detail/ca-storage.hpp"
//added_gm by liupenghui 
#if 1
#include <ndn-cxx/security/certificate.hpp>
#endif

struct sqlite3;

namespace ndncert::ca {

class CaSqlite : public CaStorage
{
public:
  static const std::string STORAGE_TYPE;

  explicit
  CaSqlite(const Name& caName, const std::string& path = "");

  ~CaSqlite() override;

public:
  RequestState
  getRequest(const RequestId& requestId) override;

  void
  addRequest(const RequestState& request) override;

  void
  updateRequest(const RequestState& request) override;

  void
  deleteRequest(const RequestId& requestId) override;

  std::list<RequestState>
  listAllRequests() override;

  std::list<RequestState>
  listAllRequests(const Name& caName) override;
  //added_gm by liupenghui 
#if 1
  void
  addCertificate(const std::string& apply_email, const Certificate& cert) override;
  
  Certificate
  getCertificate(const Name& certKeyName) override;
  
  std::string
  getApplyEmailofCertificate(const Certificate& cert);
  
  void
  deleteCertificate(const Name& certKeyName) override;
  
  std::list<Certificate>
  listAllIssuedCertificates() override;
  
  
  std::list<Certificate>
  listAllIssuedCertificates(const Name& caName) override;
#endif

private:
  sqlite3* m_database;
};

} // namespace ndncert::ca

#endif // NDNCERT_DETAIL_CA_SQLITE_HPP

