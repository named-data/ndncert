/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/**
 * Copyright (c) 2017-2019, Regents of the University of California.
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

#ifndef NDNCERT_CA_STORAGE_HPP
#define NDNCERT_CA_STORAGE_HPP

#include "certificate-request.hpp"

namespace ndn {
namespace ndncert {

class CaStorage : noncopyable
{
public:
  /**
   * @brief Error that can be thrown from CaStorage
   */
  class Error : public std::runtime_error
  {
  public:
    using std::runtime_error::runtime_error;
  };

  virtual
  ~CaStorage();

public: // certificate request related
  virtual CertificateRequest
  getRequest(const std::string& requestId) = 0;

  virtual void
  addRequest(const CertificateRequest& request) = 0;

  virtual void
  updateRequest(const CertificateRequest& request) = 0;

  virtual void
  deleteRequest(const std::string& requestId) = 0;

  virtual std::list<CertificateRequest>
  listAllRequests() = 0;

  virtual std::list<CertificateRequest>
  listAllRequests(const Name& caName) = 0;

public: // certificate related
  virtual security::v2::Certificate
  getCertificate(const std::string& certId) = 0;

  virtual void
  addCertificate(const std::string& certId, const security::v2::Certificate& cert) = 0;

  virtual void
  updateCertificate(const std::string& certId, const security::v2::Certificate& cert) = 0;

  virtual void
  deleteCertificate(const std::string& certId) = 0;

  virtual std::list<security::v2::Certificate>
  listAllIssuedCertificates() = 0;

  virtual std::list<security::v2::Certificate>
  listAllIssuedCertificates(const Name& caName) = 0;

public: // factory
  template<class CaStorageType>
  static void
  registerCaStorage(const std::string& caStorageType = CaStorageType::STORAGE_TYPE)
  {
    CaStorageFactory& factory = getFactory();
    BOOST_ASSERT(factory.count(caStorageType) == 0);
    factory[caStorageType] = [] {
      return make_unique<CaStorageType>();
    };
  }

  static unique_ptr<CaStorage>
  createCaStorage(const std::string& caStorageType);

private:
  using CaStorageCreateFunc = function<unique_ptr<CaStorage> ()>;
  using CaStorageFactory = std::map<std::string, CaStorageCreateFunc>;

  static CaStorageFactory&
  getFactory();
};

#define NDNCERT_REGISTER_CA_STORAGE(C)                           \
static class NdnCert ## C ## CaStorageRegistrationClass          \
{                                                                \
public:                                                          \
  NdnCert ## C ## CaStorageRegistrationClass()                   \
  {                                                              \
    ::ndn::ndncert::CaStorage::registerCaStorage<C>();           \
  }                                                              \
} g_NdnCert ## C ## CaStorageRegistrationVariable

} // namespace ndncert
} // namespace ndn

#endif // NDNCERT_CA_STORAGE_HPP
