/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/**
 * Copyright (c) 2017, Regents of the University of California.
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

#include "client-module.hpp"
#include "logging.hpp"
#include "json-helper.hpp"
#include <ndn-cxx/security/signing-helpers.hpp>
#include <ndn-cxx/security/verification-helpers.hpp>

namespace ndn {
namespace ndncert {

_LOG_INIT(ndncert.client);

ClientModule::ClientModule(Face& face, security::v2::KeyChain& keyChain, size_t retryTimes)
  : m_face(face)
  , m_keyChain(keyChain)
  , m_retryTimes(retryTimes)
{
}

void
ClientModule::sendProbe(const ClientCaItem& ca, const std::string& probeInfo,
                        const RequestCallback& requestCallback,
                        const ErrorCallback& errorCallback)
{
  Interest interest(Name(ca.m_caName).append("_PROBE").append(probeInfo));
  interest.setMustBeFresh(true);
  DataCallback dataCb = bind(&ClientModule::handleProbeResponse, this, _1, _2, ca, requestCallback, errorCallback);
  m_face.expressInterest(interest, dataCb,
                         bind(&ClientModule::onNack, this, _1, _2, errorCallback),
                         bind(&ClientModule::onTimeout, this, _1, m_retryTimes, dataCb,
                              requestCallback, errorCallback));

  _LOG_TRACE("PROBE interest sent with Probe info " << probeInfo);
}

void
ClientModule::handleProbeResponse(const Interest& request, const Data& reply,
                                  const ClientCaItem& ca,
                                  const RequestCallback& requestCallback,
                                  const ErrorCallback& errorCallback)
{
  if (!security::verifySignature(reply, ca.m_anchor)) {
    errorCallback("Cannot verify data from " + ca.m_caName.toUri());
    return;
  };
  JsonSection contentJson = getJsonFromData(reply);
  std::string identityNameString = contentJson.get(JSON_IDNENTIFIER, "");
  if (!identityNameString.empty()) {
    Name identityName(identityNameString);
    sendNew(ca, identityName, requestCallback, errorCallback);

    _LOG_TRACE("Got PROBE response with identity " << identityName);
  }
  else {
    errorCallback("The response does not carry required fields.");
    return;
  }
}

void
ClientModule::sendNew(const ClientCaItem& ca, const Name& identityName,
                      const RequestCallback& requestCallback,
                      const ErrorCallback& errorCallback)
{
  security::Identity identity = m_keyChain.createIdentity(identityName);

  auto state = make_shared<RequestState>();
  state->m_key = m_keyChain.createKey(identity);
  state->m_ca = ca;
  state->m_isInstalled = false;

  // generate certificate request
  security::v2::Certificate certRequest;
  certRequest.setName(Name(state->m_key.getName()).append("cert-request").appendVersion());
  certRequest.setContentType(tlv::ContentType_Key);
  certRequest.setFreshnessPeriod(time::hours(24));
  certRequest.setContent(state->m_key.getPublicKey().buf(), state->m_key.getPublicKey().size());
  SignatureInfo signatureInfo;
  signatureInfo.setValidityPeriod(security::ValidityPeriod(time::system_clock::now(),
                                                           time::system_clock::now() + time::days(10)));
  m_keyChain.sign(certRequest, signingByKey(state->m_key.getName()).setSignatureInfo(signatureInfo));

  // generate interest
  Interest interest(Name(ca.m_caName).append(Name("_NEW")).append(certRequest.wireEncode()));
  m_keyChain.sign(interest, signingByKey(state->m_key.getName()));

  DataCallback dataCb = bind(&ClientModule::handleNewResponse, this, _1, _2, state, requestCallback, errorCallback);
  m_face.expressInterest(interest, dataCb,
                         bind(&ClientModule::onNack, this, _1, _2, errorCallback),
                         bind(&ClientModule::onTimeout, this, _1, m_retryTimes, dataCb,
                              requestCallback, errorCallback));

  _LOG_TRACE("NEW interest sent with identity " << identityName);
}

void
ClientModule::handleNewResponse(const Interest& request, const Data& reply,
                                const shared_ptr<RequestState>& state,
                                const RequestCallback& requestCallback,
                                const ErrorCallback& errorCallback)
{
  if (!security::verifySignature(reply, state->m_ca.m_anchor)) {
    errorCallback("Cannot verify data from " + state->m_ca.m_caName.toUri());
    return;
  }

  const JsonSection& json = getJsonFromData(reply);
  state->m_status = json.get(JSON_STATUS, "");
  state->m_requestId = json.get(JSON_REQUEST_ID, "");

  if (!checkStatus(*state, json, errorCallback)) {
    return;
  }

  JsonSection challengesJson = json.get_child(JSON_CHALLENGES);
  std::list<std::string> challengeList;
  for (const auto& challengeJson : challengesJson) {
    challengeList.push_back(challengeJson.second.get<std::string>(JSON_CHALLENGE_TYPE));
  }
  state->m_challengeList = challengeList;

  _LOG_TRACE("Got NEW response with requestID " << state->m_requestId
             << " with status " << state->m_status
             << " with challenge number " << challengeList.size());

  requestCallback(state);
}

void
ClientModule::sendSelect(const shared_ptr<RequestState>& state,
                         const std::string& challengeType,
                         const JsonSection& selectParams,
                         const RequestCallback& requestCallback,
                         const ErrorCallback& errorCallback)
{
  JsonSection requestIdJson;
  requestIdJson.put(JSON_REQUEST_ID, state->m_requestId);

  state->m_challengeType = challengeType;

  Name interestName(state->m_ca.m_caName);
  interestName.append("_SELECT")
    .append(nameBlockFromJson(requestIdJson))
    .append(challengeType)
    .append(nameBlockFromJson(selectParams));
  Interest interest(interestName);
  m_keyChain.sign(interest, signingByKey(state->m_key.getName()));

  DataCallback dataCb = bind(&ClientModule::handleSelectResponse, this, _1, _2, state, requestCallback, errorCallback);
  m_face.expressInterest(interest, dataCb,
                         bind(&ClientModule::onNack, this, _1, _2, errorCallback),
                         bind(&ClientModule::onTimeout, this, _1, m_retryTimes, dataCb,
                              requestCallback, errorCallback));

   _LOG_TRACE("SELECT interest sent with challenge type " << challengeType);
}

void
ClientModule::handleSelectResponse(const Interest& request,
                                   const Data& reply,
                                   const shared_ptr<RequestState>& state,
                                   const RequestCallback& requestCallback,
                                   const ErrorCallback& errorCallback)
{
  if (!security::verifySignature(reply, state->m_ca.m_anchor)) {
    errorCallback("Cannot verify data from " + state->m_ca.m_caName.toUri());
    return;
  }

  JsonSection json = getJsonFromData(reply);

  _LOG_TRACE("SELECT response would change the status from " << state->m_status << " to " + json.get<std::string>(JSON_STATUS));

  state->m_status = json.get<std::string>(JSON_STATUS);

  if (!checkStatus(*state, json, errorCallback)) {
    return;
  }

  _LOG_TRACE("Got SELECT response with status " << state->m_status);

  requestCallback(state);
}

void
ClientModule::sendValidate(const shared_ptr<RequestState>& state,
                           const JsonSection& validateParams,
                           const RequestCallback& requestCallback,
                           const ErrorCallback& errorCallback)
{
  JsonSection requestIdJson;
  requestIdJson.put(JSON_REQUEST_ID, state->m_requestId);

  Name interestName(state->m_ca.m_caName);
  interestName.append("_VALIDATE")
    .append(nameBlockFromJson(requestIdJson))
    .append(state->m_challengeType)
    .append(nameBlockFromJson(validateParams));
  Interest interest(interestName);
  m_keyChain.sign(interest, signingByKey(state->m_key.getName()));

  DataCallback dataCb = bind(&ClientModule::handleValidateResponse, this, _1, _2, state, requestCallback, errorCallback);
  m_face.expressInterest(interest, dataCb,
                         bind(&ClientModule::onNack, this, _1, _2, errorCallback),
                         bind(&ClientModule::onTimeout, this, _1, m_retryTimes, dataCb,
                              requestCallback, errorCallback));

  _LOG_TRACE("VALIDATE interest sent");
}

void
ClientModule::handleValidateResponse(const Interest& request,
                                     const Data& reply,
                                     const shared_ptr<RequestState>& state,
                                     const RequestCallback& requestCallback,
                                     const ErrorCallback& errorCallback)
{
  if (!security::verifySignature(reply, state->m_ca.m_anchor)) {
    errorCallback("Cannot verify data from " + state->m_ca.m_caName.toUri());
    return;
  }

  JsonSection json = getJsonFromData(reply);
  state->m_status = json.get<std::string>(JSON_STATUS);

  if (!checkStatus(*state, json, errorCallback)) {
    return;
  }

  _LOG_TRACE("Got VALIDATE response with status " << state->m_status);

  requestCallback(state);
}


void
ClientModule::requestStatus(const shared_ptr<RequestState>& state,
                            const RequestCallback& requestCallback,
                            const ErrorCallback& errorCallback)
{
  JsonSection requestIdJson;
  requestIdJson.put(JSON_REQUEST_ID, state->m_requestId);

  Name interestName(state->m_ca.m_caName);
  interestName.append("_STATUS").append(nameBlockFromJson(requestIdJson));
  Interest interest(interestName);

  m_keyChain.sign(interest, signingByKey(state->m_key.getName()));

  DataCallback dataCb = bind(&ClientModule::handleStatusResponse, this, _1, _2, state, requestCallback, errorCallback);
  m_face.expressInterest(interest, dataCb,
                         bind(&ClientModule::onNack, this, _1, _2, errorCallback),
                         bind(&ClientModule::onTimeout, this, _1, m_retryTimes, dataCb,
                              requestCallback, errorCallback));

  _LOG_TRACE("STATUS interest sent");
}

void
ClientModule::handleStatusResponse(const Interest& request, const Data& reply,
                                   const shared_ptr<RequestState>& state,
                                   const RequestCallback& requestCallback,
                                   const ErrorCallback& errorCallback)
{
  if (!security::verifySignature(reply, state->m_ca.m_anchor)) {
    errorCallback("Cannot verify data from " + state->m_ca.m_caName.toUri());
    return;
  }

  JsonSection json = getJsonFromData(reply);
  state->m_status = json.get<std::string>(JSON_STATUS);

  if (!checkStatus(*state, json, errorCallback)) {
    return;
  }

  _LOG_TRACE("Got STATUS response with status " << state->m_status);

  requestCallback(state);
}

void
ClientModule::requestDownload(const shared_ptr<RequestState>& state,
                              const RequestCallback& requestCallback,
                              const ErrorCallback& errorCallback)
{
  JsonSection requestIdJson;
  requestIdJson.put(JSON_REQUEST_ID, state->m_requestId);

  Name interestName(state->m_ca.m_caName);
  interestName.append("_DOWNLOAD").append(nameBlockFromJson(requestIdJson));
  Interest interest(interestName);
  interest.setMustBeFresh(true);

  DataCallback dataCb = bind(&ClientModule::handleDownloadResponse, this, _1, _2, state, requestCallback, errorCallback);
  m_face.expressInterest(interest, dataCb,
                         bind(&ClientModule::onNack, this, _1, _2, errorCallback),
                         bind(&ClientModule::onTimeout, this, _1, m_retryTimes, dataCb,
                              requestCallback, errorCallback));

  _LOG_TRACE("DOWNLOAD interest sent");
}

void
ClientModule::handleDownloadResponse(const Interest& request, const Data& reply,
                                     const shared_ptr<RequestState>& state,
                                     const RequestCallback& requestCallback,
                                     const ErrorCallback& errorCallback)
{
  if (!security::verifySignature(reply, state->m_ca.m_anchor)) {
    errorCallback("Cannot verify data from " + state->m_ca.m_caName.toUri());
    return;
  }

  try {
    security::v2::Certificate cert(reply.getContent().blockFromValue());
    m_keyChain.addCertificate(state->m_key, cert);

    _LOG_TRACE("Got DOWNLOAD response and installed the cert " << cert.getName());
  }
  catch (const std::exception& e) {
    errorCallback(std::string(e.what()));
    return;
  }

  state->m_isInstalled = true;
  requestCallback(state);
}

void
ClientModule::onTimeout(const Interest& interest, int nRetriesLeft, const DataCallback& dataCallback,
                        const RequestCallback& requestCallback, const ErrorCallback& errorCallback)
{
  if (nRetriesLeft > 0) {
    m_face.expressInterest(interest, dataCallback,
                           bind(&ClientModule::onNack, this, _1, _2, errorCallback),
                           bind(&ClientModule::onTimeout, this, _1, nRetriesLeft - 1, dataCallback,
                                requestCallback, errorCallback));
  }
  else {
    errorCallback("Run out retries: still timeout");
    return;
  }
}

void
ClientModule::onNack(const Interest& interest, const lp::Nack& nack, const ErrorCallback& errorCallback)
{
  errorCallback("Got Nack");
}

JsonSection
ClientModule::getJsonFromData(const Data& data)
{
  Block jsonBlock = data.getContent();
  std::string jsonString = encoding::readString(jsonBlock);
  std::istringstream ss(jsonString);
  JsonSection json;
  boost::property_tree::json_parser::read_json(ss, json);
  return json;
}

Block
ClientModule::nameBlockFromJson(const JsonSection& json)
{
  std::stringstream ss;
  boost::property_tree::write_json(ss, json);
  return makeStringBlock(ndn::tlv::NameComponent, ss.str());
}

bool
ClientModule::checkStatus(const RequestState& state, const JsonSection& json,
                          const ErrorCallback& errorCallback)
{
  if (state.m_status == "error") {
    errorCallback(json.get(JSON_ERROR_INFO, ""));
    return false;
  }
  if (state.m_requestId.empty() || state.m_status.empty()) {
    errorCallback("The response does not carry required fields. requestID: " + state.m_requestId
                  + " status: " + state.m_status);
    return false;
  }
  return true;
}

} // namespace ndncert
} // namespace ndn
