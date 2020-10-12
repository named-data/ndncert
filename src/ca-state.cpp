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

#include "ca-state.hpp"
#include <ndn-cxx/util/indented-stream.hpp>

namespace ndn {
namespace ndncert {

std::string statusToString(Status status) {
  switch (status)
  {
  case Status::BEFORE_CHALLENGE:
    return "Before challenge";
  case Status::CHALLENGE:
    return "In challenge";
  case Status::PENDING:
    return "Pending after challenge";
  case Status::SUCCESS:
    return "Success";
  case Status::FAILURE:
    return "Failure";
  case Status::NOT_STARTED:
    return "Not started";
  case Status::ENDED:
    return "Ended";
  default:
    return "Unrecognized status";
  }
}

ChallengeState::ChallengeState(const std::string& challengeStatus,
                               const time::system_clock::TimePoint& challengeTp,
                               size_t remainingTries, time::seconds remainingTime,
                               JsonSection&& challengeSecrets)
    : m_challengeStatus(challengeStatus)
    , m_timestamp(challengeTp)
    , m_remainingTries(remainingTries)
    , m_remainingTime(remainingTime)
    , m_secrets(std::move(challengeSecrets))
{
}

CaState::CaState()
    : m_requestType(RequestType::NOTINITIALIZED)
    , m_status(Status::NOT_STARTED)
{
}

CaState::CaState(const Name& caName, const std::string& requestId, RequestType requestType, Status status,
                 const security::Certificate& cert, Block encryptionKey)
    : m_caPrefix(caName)
    , m_requestId(requestId)
    , m_requestType(requestType)
    , m_status(status)
    , m_cert(cert)
    , m_encryptionKey(std::move(encryptionKey))
{
}

CaState::CaState(const Name& caName, const std::string& requestId, RequestType requestType, Status status,
                 const security::Certificate& cert, const std::string& challengeType,
                 const std::string& challengeStatus, const time::system_clock::TimePoint& challengeTp,
                 size_t remainingTries, time::seconds remainingTime, JsonSection&& challengeSecrets,
                 Block encryptionKey)
    : m_caPrefix(caName)
    , m_requestId(requestId)
    , m_requestType(requestType)
    , m_status(status)
    , m_cert(cert)
    , m_encryptionKey(std::move(encryptionKey))
    , m_challengeType(challengeType)
    , m_challengeState(ChallengeState(challengeStatus, challengeTp, remainingTries, remainingTime, std::move(challengeSecrets)))
{
}

std::ostream&
operator<<(std::ostream& os, const CaState& request)
{
  os << "Request's CA name: " << request.m_caPrefix << "\n";
  os << "Request's request ID: " << request.m_requestId << "\n";
  os << "Request's status: " << statusToString(request.m_status) << "\n";
  os << "Request's challenge type: " << request.m_challengeType << "\n";
  if (request.m_challengeState) {
    os << "Challenge Status: " << request.m_challengeState->m_challengeStatus << "\n";
    os << "Challenge remaining tries:" << request.m_challengeState->m_remainingTries << " times\n";
    os << "Challenge remaining time: " << request.m_challengeState->m_remainingTime.count() << " seconds\n";
    os << "Challenge last update: " << time::toIsoString(request.m_challengeState->m_timestamp) << "\n";
    os << "Challenge secret:\n" << convertJson2String(request.m_challengeState->m_secrets) << "\n";
  }
  os << "Certificate:\n";
  util::IndentedStream os2(os, "  ");
  os2 << request.m_cert;
  return os;
}

} // namespace ndncert
} // namespace ndn
