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

#ifndef NDNCERT_CLIENT_MODULE_HPP
#define NDNCERT_CLIENT_MODULE_HPP

#include "client-config.hpp"
#include "certificate-request.hpp"

namespace ndn {
namespace ndncert {

class RequestState
{

public:
  ClientCaItem m_ca;
  security::Key m_key;

  std::string m_requestId;
  std::string m_status;
  std::string m_challengeType;
  std::list<std::string> m_challengeList;

  bool m_isInstalled = false;
};

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

  using LocalhostListCallback = function<void (const ClientConfig&)>;
  using ListCallback = function<void (const std::list<Name>&, const Name&, const Name&)>;
  using RequestCallback = function<void (const shared_ptr<RequestState>&)>;
  using ErrorCallback = function<void (const std::string&)>;

public:
  ClientModule(Face& face, security::v2::KeyChain& keyChain, size_t retryTimes = 2);

  virtual
  ~ClientModule();

  ClientConfig&
  getClientConf()
  {
    return m_config;
  }

  /**
   * @brief Send /CA-prefix/CA/_DOWNLOAD/ANCHOR to get CA's latest anchor with the config
   */
  void
  requestCaTrustAnchor(const Name& caName, const DataCallback& trustAnchorCallback,
                       const ErrorCallback& errorCallback);

  /**
   * @brief Send /localhost/CA/List to query local available CAs
   *
   * For more information:
   *   https://github.com/named-data/ndncert/wiki/Intra-Node-Design
   */
  void
  requestLocalhostList(const LocalhostListCallback& listCallback, const ErrorCallback& errorCallback);

  /**
   * @brief Handle the list request response
   */
  void
  handleLocalhostListResponse(const Interest& request, const Data& reply,
                              const LocalhostListCallback& listCallback, const ErrorCallback& errorCallback);

  void
  requestList(const ClientCaItem& ca, const std::string& additionalInfo,
              const ListCallback& listCallback, const ErrorCallback& errorCallback);

  void
  handleListResponse(const Interest& request, const Data& reply, const ClientCaItem& ca,
                     const ListCallback& listCallback, const ErrorCallback& errorCallback);

  void
  sendProbe(const ClientCaItem& ca, const std::string& probeInfo,
            const RequestCallback& requestCallback, const ErrorCallback& errorCallback);

  void
  handleProbeResponse(const Interest& request, const Data& reply, const ClientCaItem& ca,
                      const RequestCallback& requestCallback, const ErrorCallback& errorCallback);

  void
  sendNew(const ClientCaItem& ca, const Name& identityName,
          const RequestCallback& requestCallback, const ErrorCallback& errorCallback);

  void
  handleNewResponse(const Interest& request, const Data& reply,
                    const shared_ptr<RequestState>& state,
                    const RequestCallback& requestCallback, const ErrorCallback& errorCallback);

  void
  sendSelect(const shared_ptr<RequestState>& state, const std::string& challengeType,
             const JsonSection& selectParams,
             const RequestCallback& requestCallback, const ErrorCallback& errorCallback);

  void
  handleSelectResponse(const Interest& request, const Data& reply,
                       const shared_ptr<RequestState>& state,
                       const RequestCallback& requestCallback, const ErrorCallback& errorCallback);

  void
  sendValidate(const shared_ptr<RequestState>& state, const JsonSection& validateParams,
               const RequestCallback& requestCallback, const ErrorCallback& errorCallback);

  void
  handleValidateResponse(const Interest& request, const Data& reply,
                         const shared_ptr<RequestState>& state,
                         const RequestCallback& requestCallback, const ErrorCallback& errorCallback);

  void
  requestStatus(const shared_ptr<RequestState>& state,
                const RequestCallback& requestCallback, const ErrorCallback& errorCallback);

  void
  handleStatusResponse(const Interest& request, const Data& reply,
                       const shared_ptr<RequestState>& state,
                       const RequestCallback& requestCallback, const ErrorCallback& errorCallback);

  void
  requestDownload(const shared_ptr<RequestState>& state, const RequestCallback& requestCallback,
                  const ErrorCallback& errorCallback);

  void
  handleDownloadResponse(const Interest& request, const Data& reply,
                         const shared_ptr<RequestState>& state,
                         const RequestCallback& requestCallback, const ErrorCallback& errorCallback);

  // helper functions
  static JsonSection
  getJsonFromData(const Data& data);

  static Block
  nameBlockFromJson(const JsonSection& json);

  static bool
  checkStatus(const RequestState& state, const JsonSection& json, const ErrorCallback& errorCallback);

protected:
  virtual void
  onTimeout(const Interest& interest, int nRetriesLeft,
            const DataCallback& dataCallback, const ErrorCallback& errorCallback);

  virtual void
  onNack(const Interest& interest, const lp::Nack& nack, const ErrorCallback& errorCallback);

protected:
  ClientConfig m_config;
  Face& m_face;
  security::v2::KeyChain& m_keyChain;
  size_t m_retryTimes;
};

} // namespace ndncert
} // namespace ndn

#endif // NDNCERT_CLIENT_MODULE_HPP
