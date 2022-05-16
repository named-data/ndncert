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

#ifndef NDNCERT_DETAIL_CA_STORAGE_HPP
#define NDNCERT_DETAIL_CA_STORAGE_HPP

#include "detail/ca-request-state.hpp"

//added_gm by liupenghui 
#if 1
#include <ndn-cxx/security/certificate.hpp>
#endif

#include <map>

namespace ndncert::ca {

class CaStorage : boost::noncopyable
{
public:
  virtual
  ~CaStorage() = default;

  /**
   * @throw std::runtime_error The request cannot be fetched from underlying data storage
   */
  virtual RequestState
  getRequest(const RequestId& requestId) = 0;

  /**
   * @throw std::runtime_error There is an existing request with the same request ID
   */
  virtual void
  addRequest(const RequestState& request) = 0;

  virtual void
  updateRequest(const RequestState& request) = 0;

  virtual void
  deleteRequest(const RequestId& requestId) = 0;

  virtual std::list<RequestState>
  listAllRequests() = 0;

  virtual std::list<RequestState>
  listAllRequests(const Name& caName) = 0;
//added_gm by liupenghui 
#if 1
  virtual void
  addCertificate(const std::string& apply_email, const Certificate& cert) = 0;

  virtual Certificate
  getCertificate(const Name& certKeyName) = 0;

  virtual std::string
  getApplyEmailofCertificate(const Certificate& cert) = 0;

  virtual void
  deleteCertificate(const Name& certKeyName) = 0;
  
  virtual std::list<Certificate>
  listAllIssuedCertificates() = 0;

  
  virtual std::list<Certificate>
  listAllIssuedCertificates(const Name& caName) = 0;
#endif

public: // factory
  template<class CaStorageType>
  static void
  registerCaStorage(const std::string& type = CaStorageType::STORAGE_TYPE)
  {
    auto& factory = getFactory();
    BOOST_ASSERT(factory.count(type) == 0);
    factory[type] = [] (const Name& caName, const std::string& path) {
      return std::make_unique<CaStorageType>(caName, path);
    };
  }

  static std::unique_ptr<CaStorage>
  createCaStorage(const std::string& caStorageType, const Name& caName, const std::string& path);

private:
  using CreateFunc = std::function<std::unique_ptr<CaStorage>(const Name&, const std::string&)>;
  using CaStorageFactory = std::map<std::string, CreateFunc>;

  static CaStorageFactory&
  getFactory();
};

} // namespace ndncert::ca

#define NDNCERT_REGISTER_CA_STORAGE(C)                        \
static class NdnCert##C##CaStorageRegistrationClass           \
{                                                             \
public:                                                       \
  NdnCert##C##CaStorageRegistrationClass()                    \
  {                                                           \
    ::ndncert::ca::CaStorage::registerCaStorage<C>();         \
  }                                                           \
} g_NdnCert##C##CaStorageRegistrationVariable

#endif // NDNCERT_DETAIL_CA_STORAGE_HPP

