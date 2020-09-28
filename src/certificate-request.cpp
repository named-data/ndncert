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

#include "certificate-request.hpp"
#include <ndn-cxx/util/indented-stream.hpp>

namespace ndn {
namespace ndncert {

CertificateRequest::CertificateRequest() = default;

CertificateRequest::CertificateRequest(const Name& caName, const std::string& requestId, int requestType, Status status,
                                       const security::v2::Certificate& cert)
    : m_caPrefix(caName)
    , m_requestId(requestId)
    , m_requestType(requestType)
    , m_status(status)
    , m_cert(cert)
{
}

CertificateRequest::CertificateRequest(const Name& caName, const std::string& requestId, int requestType, Status status,
                                       const std::string& challengeStatus, const std::string& challengeType,
                                       const std::string& challengeTp, int remainingTime, int remainingTries,
                                       const JsonSection& challengeSecrets, const security::v2::Certificate& cert)
    : m_caPrefix(caName)
    , m_requestId(requestId)
    , m_requestType(requestType)
    , m_status(status)
    , m_cert(cert)
    , m_challengeStatus(challengeStatus)
    , m_challengeType(challengeType)
    , m_challengeTp(challengeTp)
    , m_remainingTime(remainingTime)
    , m_remainingTries(remainingTries)
    , m_challengeSecrets(challengeSecrets)
{
}

void
CertificateRequest::setProbeToken(const shared_ptr<Data>& probeToken)
{
  m_probeToken = probeToken;
}

std::ostream&
operator<<(std::ostream& os, const CertificateRequest& request)
{
  os << "Request CA name:\n";
  os << "  " << request.m_caPrefix << "\n";
  os << "Request ID:\n";
  os << "  " << request.m_requestId << "\n";
  os << "Request Status:\n";
  os << "  " << statusToString(request.m_status) << "\n";
  if (request.m_challengeStatus != "") {
    os << "Challenge Status:\n";
    os << "  " << request.m_challengeStatus << "\n";
  }
  if (request.m_challengeType != "") {
    os << "Request Challenge Type:\n";
    os << "  " << request.m_challengeType << "\n";
  }
  os << "Certificate:\n";
  util::IndentedStream os2(os, "  ");
  os2 << request.m_cert;
  return os;
}

}  // namespace ndncert
}  // namespace ndn
