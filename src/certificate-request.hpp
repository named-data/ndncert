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

#ifndef NDNCERT_CERTIFICATE_REQUEST_HPP
#define NDNCERT_CERTIFICATE_REQUEST_HPP

#include "ndncert-common.hpp"
#include <ndn-cxx/security/v2/certificate.hpp>

namespace ndn {
namespace ndncert {

typedef boost::property_tree::ptree JsonSection;

/**
 * @brief Represents a certificate request instance.
 *
 * ChallengeModule should take use of m_challengeStatus, m_challengeInstruction and
 * m_challengeDefinedField to finish verification.
 *
 */
class CertificateRequest
{
public:
  CertificateRequest();
  CertificateRequest(const Name& caName, const std::string& requestId, int status, const security::v2::Certificate& cert);
  CertificateRequest(const Name& caName, const std::string& requestId, int status,
                     const std::string& challengeStatus, const std::string& challengeType,
                     const std::string& challengeTp, int remainingTime, int remainingTries,
                     const JsonSection& challengeSecrets, const security::v2::Certificate& cert);

  void
  setProbeToken(const std::shared_ptr<Data>& probeToken);

public:
  Name m_caName;
  std::string m_requestId = "";
  int m_status = -1;
  security::v2::Certificate m_cert;
  std::shared_ptr<Data> m_probeToken = nullptr;

  std::string m_challengeStatus = "";
  std::string m_challengeType = "";
  std::string m_challengeTp = "";
  int m_remainingTime = 0;
  int m_remainingTries = 0;
  JsonSection m_challengeSecrets;
};

std::ostream&
operator<<(std::ostream& os, const CertificateRequest& request);

} // namespace ndncert
} // namespace ndn

#endif // NDNCERT_CERTIFICATE_REQUEST_HPP
