/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2017-2025, Regents of the University of California.
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

#ifndef NDNCERT_CHALLENGE_DNS_HPP
#define NDNCERT_CHALLENGE_DNS_HPP

#include "challenge-module.hpp"

#include <optional>

namespace ndncert {

/**
 * @brief Provide DNS-based challenge following Let's Encrypt DNS-01 practice.
 *
 * The main process of this challenge module is:
 *   1. Requester provides the domain name they want to prove ownership of.
 *   2. The challenge module generates a challenge token and responds with the DNS record details.
 *   3. Requester creates a TXT record at _ndncert-challenge.<domain> with the challenge response.
 *   4. Requester confirms the record is in place.
 *   5. The challenge module performs DNS lookup to verify the TXT record exists.
 *
 * DNS Challenge Response Format:
 *   The TXT record value is a SHA-256 hash of:
 *   challenge-token + "." + requester-key-hash
 *
 * There are several challenge statuses in DNS challenge:
 *   NEED_RECORD: When DNS record details have been provided and record needs to be created.
 *   WRONG_RECORD: When DNS lookup fails or record doesn't match.
 *
 * Failure info when challenge fails:
 *   FAILURE_MAXRETRY: When run out of retry times for DNS verification.
 *   FAILURE_TIMEOUT: When the challenge lifetime expires.
 *   FAILURE_DNS_LOOKUP: When DNS lookup consistently fails.
 *
 * @sa https://letsencrypt.org/docs/challenge-types/#dns-01-challenge
 */
class ChallengeDns : public ChallengeModule
{
public:
  ChallengeDns(const size_t& maxAttemptTimes = 3,
               const time::seconds secretLifetime = time::seconds(3600),
               const std::string& configPath = "");

  // For CA
  std::tuple<ErrorCode, std::string>
  handleChallengeRequest(const Block& params, ca::RequestState& request) override;

  // For Client
  std::multimap<std::string, std::string>
  getRequestedParameterList(Status status, const std::string& challengeStatus) override;

  Block
  genChallengeRequestTLV(Status status, const std::string& challengeStatus,
                         const std::multimap<std::string, std::string>& params) override;

  // challenge status
  static const std::string NEED_RECORD;
  static const std::string WRONG_RECORD;
  
  // challenge parameters
  static const std::string PARAMETER_KEY_DOMAIN;
  static const std::string PARAMETER_KEY_CONFIRMATION;

NDNCERT_PUBLIC_WITH_TESTS_ELSE_PRIVATE:
  static bool
  isValidDomainName(const std::string& domain);

  static std::string
  computeChallengeResponse(const std::string& token, const std::string& keyHash);

  NDNCERT_VIRTUAL_WITH_TESTS bool
  verifyDnsRecord(const std::string& domain, const std::string& expectedValue) const;

  std::string
  getDnsRecordName(const std::string& domain) const;

private:
  void
  parseConfigFile() const;

  time::seconds
  getRemainingTime(const time::system_clock::time_point& currentTime,
                   const time::system_clock::time_point& startTime) const;

  std::string
  validateSingleParameter(const std::multimap<std::string, std::string>& params,
                          const std::string& expectedKey) const;

  static const std::string DNS_PREFIX;

private:
  std::string m_configFile;
  mutable bool m_isConfigParsed = false;
  mutable std::optional<std::string> m_configResolverIpV4;
  mutable std::optional<uint16_t> m_configResolverPort;
};

} // namespace ndncert

#endif // NDNCERT_CHALLENGE_DNS_HPP