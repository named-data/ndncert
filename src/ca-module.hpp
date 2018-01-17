/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/**
 * Copyright (c) 2017-2018, Regents of the University of California.
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
#include "ca-storage.hpp"
#include "json-helper.hpp"

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
  setProbeHandler(const Name caName, const ProbeHandler& handler);

  bool
  setRecommendCaHandler(const Name caName, const RecommendCaHandler& handler);

  bool
  setStatusUpdateCallback(const Name caName, const StatusUpdateCallback& onUpateCallback);

PUBLIC_WITH_TESTS_ELSE_PRIVATE:
  void
  handleLocalhostList(const Interest& query);

  void
  handleList(const Interest& request, const CaItem& caItem);

  void
  handleProbe(const Interest& request, const CaItem& caItem);

  void
  handleNew(const Interest& request, const CaItem& caItem);

  void
  handleSelect(const Interest& request, const CaItem& caItem);

  void
  handleValidate(const Interest& request, const CaItem& caItem);

  void
  handleStatus(const Interest& request, const CaItem& caItem);

  void
  handleDownload(const Interest& request, const CaItem& caItem);

  void
  onRegisterFailed(const std::string& reason);

  CertificateRequest
  getCertificateRequest(const Interest& request, const Name& caName);

  security::v2::Certificate
  issueCertificate(const CertificateRequest& certRequest, const CaItem& caItem);

  static JsonSection
  jsonFromNameComponent(const Name& name, int pos);

  static Block
  dataContentFromJson(const JsonSection& jsonSection);

  void
  registerPrefix();

PUBLIC_WITH_TESTS_ELSE_PRIVATE:
  Face& m_face;
  CaConfig m_config;
  unique_ptr<CaStorage> m_storage;
  security::v2::KeyChain& m_keyChain;

  std::list<const RegisteredPrefixId*> m_registeredPrefixIds;
  std::list<const InterestFilterId*> m_interestFilterIds;
};

} // namespace ndncert
} // namespace ndn

#endif // NDNCERT_CA_MODULE_HPP
