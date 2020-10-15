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

#ifndef NDNCERT_CA_MODULE_HPP
#define NDNCERT_CA_MODULE_HPP

#include "configuration.hpp"
#include "detail/crypto-helper.hpp"
#include "detail/ca-storage.hpp"

namespace ndn {
namespace ndncert {

class CaModule : noncopyable
{
public:
  CaModule(Face& face, security::KeyChain& keyChain, const std::string& configPath,
           const std::string& storageType = "ca-storage-sqlite3");

  ~CaModule();

  CaConfig&
  getCaConf()
  {
    return m_config;
  }

  const unique_ptr<CaStorage>&
  getCaStorage()
  {
    return m_storage;
  }

  void
  setStatusUpdateCallback(const StatusUpdateCallback& onUpdateCallback);

  Data
  getCaProfileData();

PUBLIC_WITH_TESTS_ELSE_PRIVATE:
  void
  onCaProfileDiscovery(const Interest& request);

  void
  onProbe(const Interest& request);

  void
  onNewRenewRevoke(const Interest& request, RequestType requestType);

  void
  onChallenge(const Interest& request);

  void
  onRegisterFailed(const std::string& reason);

  CaState
  getCertificateRequest(const Interest& request);

  security::Certificate
  issueCertificate(const CaState& requestState);

  void
  registerPrefix();

  Data
  generateErrorDataPacket(const Name& name, ErrorCode error, const std::string& errorInfo);

PUBLIC_WITH_TESTS_ELSE_PRIVATE:
  Face& m_face;
  CaConfig m_config;
  unique_ptr<CaStorage> m_storage;
  security::KeyChain& m_keyChain;
  uint8_t m_requestIdGenKey[32];
  std::unique_ptr<Data> m_profileData;

  std::list<RegisteredPrefixHandle> m_registeredPrefixHandles;
  std::list<InterestFilterHandle> m_interestFilterHandles;
};

} // namespace ndncert
} // namespace ndn

#endif // NDNCERT_CA_MODULE_HPP
