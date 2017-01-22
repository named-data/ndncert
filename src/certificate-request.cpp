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

#include "certificate-request.hpp"
#include <ndn-cxx/util/indented-stream.hpp>

namespace ndn {
namespace ndncert {

CertificateRequest::CertificateRequest(const Name& caName,
                                       const std::string& requestId,
                                       const security::v2::Certificate& cert)
  : m_caName(caName)
  , m_requestId(requestId)
  , m_status(Pending)
  , m_cert(static_cast<const Data&>(cert))
{
}

CertificateRequest::CertificateRequest(const Name& caName,
                                       const std::string& requestId,
                                       const ApplicationStatus& status,
                                       const std::string& challengeType,
                                       const std::string& challengeStatus,
                                       const std::string& challengeDefinedField,
                                       const security::v2::Certificate& cert)
  : m_caName(caName)
  , m_requestId(requestId)
  , m_status(status)
  , m_challengeType(challengeType)
  , m_challengeStatus(challengeStatus)
  , m_challengeDefinedField(challengeDefinedField)
  , m_cert(static_cast<const Data&>(cert))
{
}

std::ostream&
operator<<(std::ostream& os, CertificateRequest::ApplicationStatus status)
{
  std::string statusString;
  switch (status) {
    case CertificateRequest::Pending: {
      statusString = "pending";
      break;
    }
    case CertificateRequest::Verifying: {
      statusString = "verifying";
      break;
    }
    case CertificateRequest::Success: {
      statusString = "success";
      break;
    }
    case CertificateRequest::Failure: {
      statusString = "failure";
      break;
    }
  }
  os << statusString;
  return os;
}

std::ostream&
operator<<(std::ostream& os, const CertificateRequest& request)
{
  os << "Request CA name:\n";
  os << "  " << request.getCaName() << "\n";
  os << "Request ID:\n";
  os << "  " << request.getRequestId() << "\n";
  os << "Request Status:\n";
  os << "  " << request.getStatus() << "\n";
  if (request.getChallengeType() != "") {
    os << "Request Challenge Type:\n";
    os << "  " << request.getChallengeType() << "\n";
  }
  if (request.getChallengeStatus() != "") {
    os << "Request Challenge Status:\n";
    os << "  " << request.getChallengeStatus() << "\n";
  }
  os << "Certificate:\n";
  util::IndentedStream os2(os, "  ");
  os2 << request.getCert();
  return os;
}

} // namespace ndncert
} // namespace ndn
