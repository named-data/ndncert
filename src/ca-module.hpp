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

  bool
  setProbeHandler(const ProbeHandler& handler);

  bool
  setStatusUpdateCallback(const StatusUpdateCallback& onUpdateCallback);

PUBLIC_WITH_TESTS_ELSE_PRIVATE:
  void
  onProbe(const Interest& request);

  void
  onNew(const Interest& request);

  void
  onChallenge(const Interest& request);

  void
  onDownload(const Interest& request);

  void
  onRegisterFailed(const std::string& reason);

  CertificateRequest
  getCertificateRequest(const Interest& request);

  security::v2::Certificate
  issueCertificate(const CertificateRequest& certRequest);

  static Block
  dataContentFromJson(const JsonSection& jsonSection);

  void
  registerPrefix();

  static JsonSection
  jsonFromBlock(const Block& block);

PUBLIC_WITH_TESTS_ELSE_PRIVATE:
  const JsonSection
  genProbeResponseJson(const Name& identifier);

  const JsonSection
  genProbeResponseJson();

  const JsonSection
  genNewResponseJson(const std::string& ecdhKey, const std::string& salt,
                     const CertificateRequest& request, const std::list<std::string>& challenges);

  const JsonSection
  genChallengeResponseJson(const CertificateRequest& request);

PUBLIC_WITH_TESTS_ELSE_PRIVATE:
  Face& m_face;
  CaConfig m_config;
  unique_ptr<CaStorage> m_storage;
  security::v2::KeyChain& m_keyChain;

  std::list<RegisteredPrefixHandle> m_registeredPrefixHandles;
  std::list<InterestFilterHandle> m_interestFilterHandles;

  ECDHState m_ecdh;
  uint8_t m_aesKey[32] = {0};
};

} // namespace ndncert
} // namespace ndn

#endif // NDNCERT_CA_MODULE_HPP
