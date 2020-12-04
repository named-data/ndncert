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

#include "detail/ca-request-state.hpp"
#include <ndn-cxx/util/indented-stream.hpp>

namespace ndn {
namespace ndncert {

std::string statusToString(Status status)
{
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
  default:
    return "Unrecognized status";
  }
}

Status
statusFromBlock(const Block& block)
{
  auto status_int = readNonNegativeInteger(block);
  if (status_int > 6)
      NDN_THROW(std::runtime_error("Unrecognized Status"));
  return static_cast<Status>(status_int);
}

namespace ca {

ChallengeState::ChallengeState(const std::string& challengeStatus,
                               const time::system_clock::TimePoint& challengeTp,
                               size_t remainingTries, time::seconds remainingTime,
                               JsonSection&& challengeSecrets)
    : challengeStatus(challengeStatus)
    , timestamp(challengeTp)
    , remainingTries(remainingTries)
    , remainingTime(remainingTime)
    , secrets(std::move(challengeSecrets))
{
}

std::ostream&
operator<<(std::ostream& os, const RequestState& request)
{
  os << "Request's CA name: " << request.caPrefix << "\n";
  os << "Request's request ID: " << toHex(request.requestId.data(), request.requestId.size()) << "\n";
  os << "Request's status: " << statusToString(request.status) << "\n";
  os << "Request's challenge type: " << request.challengeType << "\n";
  if (request.challengeState) {
    os << "Challenge Status: " << request.challengeState->challengeStatus << "\n";
    os << "Challenge remaining tries:" << request.challengeState->remainingTries << " times\n";
    os << "Challenge remaining time: " << request.challengeState->remainingTime.count() << " seconds\n";
    os << "Challenge last update: " << time::toIsoString(request.challengeState->timestamp) << "\n";
  }
  os << "Certificate:\n";
  util::IndentedStream os2(os, "  ");
  os2 << request.cert;
  return os;
}

} // namespace ca
} // namespace ndncert
} // namespace ndn
