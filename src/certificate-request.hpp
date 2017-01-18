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

#ifndef NDNCERT_CERTFICATE_REQUEST_HPP
#define NDNCERT_CERTFICATE_REQUEST_HPP

#include "ndncert-common.hpp"
#include <ndn-cxx/security/v2/certificate.hpp>

namespace ndn {
namespace ndncert {

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
  enum ApplicationStatus {
    Pending = 0,
    Verifying = 1,
    Success = 2,
    Failure = 3
  };

public:
  CertificateRequest(const Name& caName, const std::string& requestId,
                     const security::v2::Certificate& cert);

  CertificateRequest(const Name& caName, const std::string& requestId,
                     const ApplicationStatus& status, const std::string& challengeType,
                     const std::string& challengeStatus, const std::string& challengeDefinedField,
                     const security::v2::Certificate& certBlock);

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

  const ApplicationStatus&
  getStatus() const
  {
    return m_status;
  }

  const std::string&
  getChallengeType() const
  {
    return m_challengeType;
  }

  const std::string&
  getChallengeDefinedField() const
  {
    return m_challengeDefinedField;
  }

  const std::string&
  getChallengeInstruction() const
  {
    return m_challengeInstruction;
  }

  const std::string&
  getChallengeStatus() const
  {
    return m_challengeStatus;
  }

  const security::v2::Certificate&
  getCert() const
  {
    return m_cert;
  }

  /**
   * These setters should only be invoked by ChallengeModule
   */
  void
  setStatus(const ApplicationStatus& status)
  {
    m_status = status;
  }

  void
  setChallengeType(const std::string& challengeType)
  {
    m_challengeType = challengeType;
  }

  void
  setChallengeStatus(const std::string& challengeStatus)
  {
    m_challengeStatus = challengeStatus;
  }

  void
  setChallengeDefinedField(const std::string& challengeDefinedField)
  {
    m_challengeDefinedField = challengeDefinedField;
  }

  void
  setChallengeInstruction(const std::string& challengeInstruction)
  {
    m_challengeInstruction = challengeInstruction;
  }

private:
  Name m_caName;
  std::string m_requestId;
  ApplicationStatus m_status;
  std::string m_challengeType;

  /**
   * @brief Defined by ChallengeModule to indicate the verification status.
   *
   * This field will be stored by CA.
   */
  std::string m_challengeStatus;

  /**
   * @brief Defined by ChallengeModule to store secret information.
   *
   * This field will be stored by CA.
   */
  std::string m_challengeDefinedField;

  /**
   * @brief Defined by ChallengeModule to indicate end entity the next step.
   *
   * This field will be presented to end entity.
   * This field will NOT be stored by CA.
   */
  std::string m_challengeInstruction;

  security::v2::Certificate m_cert;
};

std::ostream&
operator<<(std::ostream& os, CertificateRequest::ApplicationStatus status);

std::ostream&
operator<<(std::ostream& os, const CertificateRequest& request);

} // namespace ndncert
} // namespace ndn

#endif // NDNCERT_CERTFICATE_REQUEST_HPP
