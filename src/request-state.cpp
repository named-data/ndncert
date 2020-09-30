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

#include "request-state.hpp"
#include <ndn-cxx/util/indented-stream.hpp>

namespace ndn {
namespace ndncert {

ChallengeState::ChallengeState(const std::string& challengeStatus,
                               const system_clock::TimePoint& challengeTp,
                               size_t remainingTries, time::seconds remainingTime,
                               JsonSection&& challengeSecrets)
    : m_challengeStatus(challengeStatus)
    , m_timestamp(challengeTp)
    , m_remainingTries(remainingTries)
    , m_remainingTime(remainingTime)
    , m_secrets(std::move(challengeSecrets))
{
}

RequestState::RequestState()
    : m_requestType(RequestType::NOTINITIALIZED)
    , m_status(Status::NOT_STARTED)
{
}

RequestState::RequestState(const Name& caName, const std::string& requestId, RequestType requestType, Status status,
                                       const security::v2::Certificate& cert, Block encryptionKey)
    : m_caPrefix(caName)
    , m_requestId(requestId)
    , m_requestType(requestType)
    , m_status(status)
    , m_cert(cert)
    , m_encryptionKey(std::move(encryptionKey))
{
}

RequestState::RequestState(const Name& caName, const std::string& requestId, RequestType requestType, Status status,
                                       const security::v2::Certificate& cert, const std::string& challengeType,
                                       const std::string& challengeStatus, const system_clock::TimePoint& challengeTp,
                                       size_t remainingTries, time::seconds remainingTime, JsonSection&& challengeSecrets,
                                       Block encryptionKey)
    : m_caPrefix(caName)
    , m_requestId(requestId)
    , m_requestType(requestType)
    , m_status(status)
    , m_cert(cert)
    , m_challengeType(challengeType)
    , m_challengeState(ChallengeState(challengeStatus, challengeTp, remainingTries, remainingTime, std::move(challengeSecrets)))
    , m_encryptionKey(std::move(encryptionKey))
{
}

std::ostream&
operator<<(std::ostream& os, const RequestState& request)
{
  os << "Request's CA name:\n";
  os << "  " << request.m_caPrefix << "\n";
  os << "Request's request ID:\n";
  os << "  " << request.m_requestId << "\n";
  os << "Request's status:\n";
  os << "  " << statusToString(request.m_status) << "\n";
  os << "Request's challenge type:\n";
  os << "  " << request.m_challengeType << "\n";
  if (request.m_challengeState) {
    os << "Challenge Status:\n";
    os << "  " << request.m_challengeState->m_challengeStatus << "\n";
    os << "Challenge remaining tries:\n";
    os << "  " << request.m_challengeState->m_remainingTries << " times\n";
    os << "Challenge remaining time:\n";
    os << "  " << request.m_challengeState->m_remainingTime.count() << " seconds\n";
    os << "Challenge last update:\n";
    os << "  " << time::toIsoString(request.m_challengeState->m_timestamp) << "\n";
    os << "Challenge secret:\n";
    os << "  " << convertJson2String(request.m_challengeState->m_secrets) << "\n";
  }
  os << "Certificate:\n";
  util::IndentedStream os2(os, "  ");
  os2 << request.m_cert;
  return os;
}

}  // namespace ndncert
}  // namespace ndn
