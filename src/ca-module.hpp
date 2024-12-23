/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2017-2024, Regents of the University of California.
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

#ifndef NDNCERT_CA_MODULE_HPP
#define NDNCERT_CA_MODULE_HPP

#include "detail/ca-configuration.hpp"
#include "detail/ca-storage.hpp"

#include <ndn-cxx/face.hpp>
#include <ndn-cxx/security/key-chain.hpp>

namespace ndncert::ca {

/**
 * @brief The function would be invoked whenever the certificate request status is updated.
 * The callback is used to notice the CA application or CA command line tool. The callback is
 * fired whenever a request instance is created, challenge status is updated, and when certificate
 * is issued.
 *
 * @param RequestState The state of the certificate request whose status is updated.
 */
using StatusUpdateCallback = std::function<void(const RequestState&)>;

class CaModule : boost::noncopyable
{
public:
  CaModule(ndn::Face& face, ndn::KeyChain& keyChain, const std::string& configPath,
           const std::string& storageType = "ca-storage-sqlite3");

  CaConfig&
  getCaConf()
  {
    return m_config;
  }

  const std::unique_ptr<CaStorage>&
  getCaStorage() const
  {
    return m_storage;
  }

  void
  setStatusUpdateCallback(StatusUpdateCallback cb)
  {
    m_statusUpdateCallback = std::move(cb);
  }

  const Data&
  getCaProfileData();

NDNCERT_PUBLIC_WITH_TESTS_ELSE_PRIVATE:
  void
  registerPrefix();

  void
  onCaProfileDiscovery(const Interest& request);

  void
  onProbe(const Interest& request);

  void
  onNewRenewRevoke(const Interest& request, RequestType requestType);

  void
  onChallenge(const Interest& request);

  std::unique_ptr<RequestState>
  getCertificateRequest(const Interest& request);

  Certificate
  issueCertificate(const RequestState& requestState);

  Data
  makeErrorPacket(const Name& name, ErrorCode errorCode, std::string_view errorInfo);

NDNCERT_PUBLIC_WITH_TESTS_ELSE_PRIVATE:
  ndn::Face& m_face;
  ndn::KeyChain& m_keyChain;
  CaConfig m_config;
  std::unique_ptr<CaStorage> m_storage;

  uint8_t m_requestIdGenKey[32];
  std::unique_ptr<Data> m_profileData;
  StatusUpdateCallback m_statusUpdateCallback;

  std::vector<ndn::ScopedRegisteredPrefixHandle> m_registeredPrefixes;
  std::vector<ndn::ScopedInterestFilterHandle> m_interestFilters;
};

} // namespace ndncert::ca

#endif // NDNCERT_CA_MODULE_HPP
