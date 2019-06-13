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

#ifndef NDNCERT_CLIENT_MODULE_HPP
#define NDNCERT_CLIENT_MODULE_HPP

#include "client-config.hpp"
#include "crypto-support/crypto-helper.hpp"
#include "certificate-request.hpp"

namespace ndn {
namespace ndncert {

// TODO
// For each CA item in Client.Conf, create a validator instance and initialize it with CA's cert
// The validator instance should be in ClientCaItem

class ClientModule : noncopyable
{
public:
  /**
   * @brief Error that can be thrown from ClientModule
   */
  class Error : public std::runtime_error
  {
  public:
    using std::runtime_error::runtime_error;
  };

public:
  ClientModule(security::v2::KeyChain& keyChain);

  virtual
  ~ClientModule();

  ClientConfig&
  getClientConf()
  {
    return m_config;
  }

  int
  getApplicationStatus() const
  {
    return m_status;
  }

  std::string
  getChallengeStatus() const
  {
    return m_challengeStatus;
  }

  shared_ptr<Interest>
  generateProbeInfoInterest(const Name& caName);

  /**
   * @brief Process the replied PROBE INFO Data packet
   * Warning: this function will add a new trust anchor into the application.
   * Please invoke this function only when reply can be fully trusted or the CA
   * can be verified in later challenge phase.
   */
  void
  onProbeInfoResponse(const Data& reply);

  shared_ptr<Interest>
  generateProbeInterest(const ClientCaItem& ca, const std::string& probeInfo);

  void
  onProbeResponse(const Data& reply);

  shared_ptr<Interest>
  generateNewInterest(const time::system_clock::TimePoint& notBefore,
                      const time::system_clock::TimePoint& notAfter,
                      const Name& identityName = Name(), const shared_ptr<Data>& probeToken = nullptr);

  std::list<std::string>
  onNewResponse(const Data& reply);

  shared_ptr<Interest>
  generateChallengeInterest(const JsonSection& paramJson);

  void
  onChallengeResponse(const Data& reply);

  shared_ptr<Interest>
  generateDownloadInterest();

  shared_ptr<Interest>
  generateCertFetchInterest();

  void
  onDownloadResponse(const Data& reply);

  void
  onCertFetchResponse(const Data& reply);

  // helper functions
  static JsonSection
  getJsonFromData(const Data& data);

  static Block
  paramFromJson(const JsonSection& json);

PUBLIC_WITH_TESTS_ELSE_PRIVATE:
  const JsonSection
  genProbeRequestJson(const ClientCaItem& ca, const std::string& probeInfo);

  const JsonSection
  genNewRequestJson(const std::string& ecdhPub, const security::v2::Certificate& certRequest,
                    const shared_ptr<Data>& probeToken = nullptr);

PUBLIC_WITH_TESTS_ELSE_PRIVATE:
  ClientConfig m_config;
  security::v2::KeyChain& m_keyChain;

  ClientCaItem m_ca;
  security::Key m_key;
  Name m_identityName;

  std::string m_requestId = "";
  int m_status = STATUS_NOT_STARTED;
  std::string m_challengeStatus = "";
  std::string m_challengeType = "";
  std::string m_certId = "";
  std::list<std::string> m_challengeList;
  bool m_isCertInstalled = false;

  int m_remainingTries = 0;
  time::system_clock::TimePoint m_freshBefore;

  ECDHState m_ecdh;
  uint8_t m_aesKey[32] = {0};
};

} // namespace ndncert
} // namespace ndn

#endif // NDNCERT_CLIENT_MODULE_HPP
