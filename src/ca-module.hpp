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

#include "ca-config.hpp"
#include "crypto-support/crypto-helper.hpp"
#include "ca-storage.hpp"

namespace ndn {
namespace ndncert {

class CaModule : noncopyable
{
public:
  /**
   * @brief Error that can be thrown from CaModule
   */
  class Error : public std::runtime_error
  {
  public:
    using std::runtime_error::runtime_error;
  };

public:
  CaModule(Face& face, security::v2::KeyChain& keyChain, const std::string& configPath,
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
  setNameAssignmentFunction(const NameAssignmentFunc& handler);

  bool
  setStatusUpdateCallback(const StatusUpdateCallback& onUpdateCallback);

  static JsonSection
  jsonFromBlock(const Block& block);

  static Block
  dataContentFromJson(const JsonSection& jsonSection);

PUBLIC_WITH_TESTS_ELSE_PRIVATE:
  shared_ptr<Data>
  generateCaConfigMetaData();

  shared_ptr<Data>
  generateCaConfigData();

  void
  onInfo(const Interest& request);

  void
  onProbe(const Interest& request);

  void
  onNewRenewRevoke(const InterestFilter& filter, const Interest& request, RequestType requestType);

  void
  onChallenge(const Interest& request);

  void
  onRegisterFailed(const std::string& reason);

  CertificateRequest
  getCertificateRequest(const Interest& request);

  security::v2::Certificate
  issueCertificate(const CertificateRequest& certRequest);

  void
  registerPrefix();

  Data
  generateErrorDataPacket(const Name& name, ErrorCode error, const std::string& errorInfo);

PUBLIC_WITH_TESTS_ELSE_PRIVATE:
  Face& m_face;
  CaConfig m_config;
  unique_ptr<CaStorage> m_storage;
  security::v2::KeyChain& m_keyChain;

  std::list<RegisteredPrefixHandle> m_registeredPrefixHandles;
  std::list<InterestFilterHandle> m_interestFilterHandles;

  ECDHState m_ecdh;
  uint8_t m_aesKey[16] = {0};
};

} // namespace ndncert
} // namespace ndn

#endif // NDNCERT_CA_MODULE_HPP
