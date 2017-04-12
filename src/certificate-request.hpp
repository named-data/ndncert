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

  CertificateRequest(const Name& caName, const std::string& requestId,
                     const security::v2::Certificate& cert);

  CertificateRequest(const Name& caName, const std::string& requestId,
                     const std::string& status, const std::string& challengeType,
                     const std::string& challengeSecrets,
                     const security::v2::Certificate& cert);

  const Name&
  getCaName() const
  {
    return m_caName;
  }

  const std::string&
  getRequestId() const
  {
    return m_requestId;
  }

  const std::string&
  getStatus() const
  {
    return m_status;
  }

  const std::string&
  getChallengeType() const
  {
    return m_challengeType;
  }

  const JsonSection&
  getChallengeSecrets() const
  {
    return m_challengeSecrets;
  }

  const security::v2::Certificate&
  getCert() const
  {
    return m_cert;
  }

  void
  setStatus(const std::string& status)
  {
    m_status = status;
  }

  void
  setChallengeType(const std::string& challengeType)
  {
    m_challengeType = challengeType;
  }

  void
  setChallengeSecrets(const JsonSection& challengeSecrets)
  {
    m_challengeSecrets = challengeSecrets;
  }

  bool
  isEmpty()
  {
    return m_requestId == "";
  }

private:
  Name m_caName;
  std::string m_requestId;
  std::string m_status;
  std::string m_challengeType;

  /**
   * @brief Defined by ChallengeModule to store secret information.
   *
   * This field will be stored by CA.
   */
  JsonSection m_challengeSecrets;

  security::v2::Certificate m_cert;
};

std::ostream&
operator<<(std::ostream& os, const CertificateRequest& request);

} // namespace ndncert
} // namespace ndn

#endif // NDNCERT_CERTIFICATE_REQUEST_HPP
