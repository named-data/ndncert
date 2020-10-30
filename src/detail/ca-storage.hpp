/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/**
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

#ifndef NDNCERT_DETAIL_CA_STORAGE_HPP
#define NDNCERT_DETAIL_CA_STORAGE_HPP

#include "detail/ca-request-state.hpp"

namespace ndn {
namespace ndncert {
namespace ca {

class CaStorage : noncopyable
{
public: // request related
  /**
   * @throw if request cannot be fetched from underlying data storage
   */
  virtual RequestState
  getRequest(const RequestID& requestId) = 0;

  /**
   * @throw if there is an existing request with the same request ID
   */
  virtual void
  addRequest(const RequestState& request) = 0;

  virtual void
  updateRequest(const RequestState& request) = 0;

  virtual void
  deleteRequest(const RequestID& requestId) = 0;

  virtual std::list<RequestState>
  listAllRequests() = 0;

  virtual std::list<RequestState>
  listAllRequests(const Name& caName) = 0;

public: // factory
  template<class CaStorageType>
  static void
  registerCaStorage(const std::string& caStorageType = CaStorageType::STORAGE_TYPE)
  {
    CaStorageFactory& factory = getFactory();
    BOOST_ASSERT(factory.count(caStorageType) == 0);
    factory[caStorageType] = [] (const Name& caName, const std::string& path) {
      return std::make_unique<CaStorageType>(caName, path);
    };
  }

  static unique_ptr<CaStorage>
  createCaStorage(const std::string& caStorageType, const Name& caName, const std::string& path);

  virtual
  ~CaStorage() = default;

private:
  using CaStorageCreateFunc = function<unique_ptr<CaStorage> (const Name&, const std::string&)>;
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
    ::ndn::ndncert::ca::CaStorage::registerCaStorage<C>();       \
  }                                                              \
} g_NdnCert ## C ## CaStorageRegistrationVariable

} // namespace ca
} // namespace ndncert
} // namespace ndn

#endif // NDNCERT_DETAIL_CA_STORAGE_HPP
