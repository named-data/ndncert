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

#ifndef NDNCERT_REQUESTER_HPP
#define NDNCERT_REQUESTER_HPP

#include "configuration.hpp"
#include "ca-state.hpp"
#include "crypto-support/crypto-helper.hpp"

namespace ndn {
namespace ndncert {

// TODO
// For each RequesterState, create a validator instance and initialize it with CA's cert
// The validator instance should be in CaProfile

struct RequesterState {
  explicit
  RequesterState(security::v2::KeyChain& keyChain, const CaProfile& caItem, RequestType requestType);

  /**
   * The CA profile for this request.
   */
  CaProfile m_caItem;
  /**
   * The local keychain to generate and install identities, keys and certificates
   */
  security::v2::KeyChain& m_keyChain;
  /**
   * The type of request. Either NEW, RENEW, or REVOKE.
   */
  RequestType m_type;

  /**
   * The identity name for the requesting certificate.
   */
  Name m_identityName;
  /**
   * The keypair for the request.
   */
  security::Key m_keyPair;
  /**
   * The CA-generated request ID for the request.
   */
  std::string m_requestId;
  /**
   * The current status of the request.
   */
  Status m_status = Status::NOT_STARTED;

  /**
   * The type of challenge chosen.
   */
  std::string m_challengeType;
  /**
   * The status of the current challenge.
   */
  std::string m_challengeStatus;
  /**
   * The remaining number of tries left for the challenge
   */
  int m_remainingTries = 0;
  /**
   * The time this challenge will remain fresh
   */
  time::system_clock::TimePoint m_freshBefore;
  /**
   * the name of the certificate being issued.
   */
  Name m_issuedCertName;

  ECDHState m_ecdh;
  uint8_t m_aesKey[16] = {0};

  bool m_isCertInstalled = false;
  bool m_isNewlyCreatedIdentity = false;
  bool m_isNewlyCreatedKey = false;
};

class Requester : noncopyable
{
public:
  /**
   * Generates a INFO interest corresponds to the CA for given prefix.
   * @param caName the name prefix of the CA.
   * @return A shared pointer to an interest ready to be sent.
   */
  static shared_ptr<Interest>
  genCaProfileInterest(const Name& caName);

  /**
   * Decodes the replied data for the configuration of the CA.
   * Will first verify the signature of the packet using the key provided inside the profile.
   * The application should be cautious whether to add CaProfile into the RequesterCaCache.
   * @param reply
   * @return the CaProfile if decoding is successful
   * @throw std::runtime_error if the decoding fails or receiving an error packet.
   */
  static boost::optional<CaProfile>
  onCaProfileResponse(const Data& reply);

  static boost::optional<CaProfile>
  onCaProfileResponseAfterRedirection(const Data& reply, const Name& caCertFullName);

  /**
   * Generates a PROBE interest to the CA (for suggested name assignments).
   * @param ca the CA that interest is send to
   * @param probeInfo the requester information to carry to the CA
   * @return A shared pointer of to the encoded interest, ready to be sent.
   */
  static shared_ptr<Interest>
  genProbeInterest(const CaProfile& ca, std::vector<std::tuple<std::string, std::string>>&& probeInfo);

  /**
   * Decodes the replied data for PROBE process from the CA.
   * Will first verify the signature of the packet using the key provided inside the profile.
   * @param reply The replied data packet
   * @param ca the profile of the CA that replies the packet
   * @param identityNames The vector to load the decoded identity names from the data.
   * @param otherCas The vector to load the decoded redirection CA prefixes from the data.
   * @throw std::runtime_error if the decoding fails or receiving an error packet.
   */
  static void
  onProbeResponse(const Data& reply, const CaProfile& ca,
                  std::vector<Name>& identityNames, std::vector<Name>& otherCas);

  // NEW/REVOKE/RENEW related helpers
  /**
   * Generates a NEW interest to the CA.
   * @param state The current requester state for this request. Will be modified in the function.
   * @param identityName The identity name to be requested.
   * @param notBefore The expected notBefore field for the certificate (starting time)
   * @param notAfter The expected notAfter field for the certificate (expiration time)
   * @return The shared pointer to the encoded interest.
   */
  static shared_ptr<Interest>
  genNewInterest(RequesterState& state, const Name& identityName,
                      const time::system_clock::TimePoint& notBefore,
                      const time::system_clock::TimePoint& notAfter);

  /**
   * Generates a REVOKE interest to the CA.
   * @param state The current requester state for this request. Will be modified in the function.
   * @param certificate the certificate to the revoked.
   * @return The shared pointer to the encoded interest.
   */
  static shared_ptr<Interest>
  genRevokeInterest(RequesterState& state, const security::v2::Certificate& certificate);

  /**
   * Decodes the replied data of NEW, RENEW, or REVOKE interest from the CA.
   * @param state the current requester state for the request. Will be updated in the function.
   * @param reply the replied data from the network
   * @return the list of challenge accepted by the CA, for CHALLENGE step.
   * @throw std::runtime_error if the decoding fails or receiving an error packet.
   */
  static std::list<std::string>
  onNewRenewRevokeResponse(RequesterState& state, const Data& reply);

  // CHALLENGE helpers
  /**
   * Generates the required parameter for the selected challenge for the request
   * @param state The requester state of the request.Will be updated in the function.
   * @param challengeSelected The selected challenge for the request.
   *            Can use state.m_challengeType to continue.
   * @return The requirement list for the current stage of the challenge, in name, prompt mapping.
   */
  static std::vector<std::tuple<std::string, std::string>>
  selectOrContinueChallenge(RequesterState& state, const std::string& challengeSelected);

  /**
   * Generates the CHALLENGE interest for the request.
   * @param state The requester state of the request.
   * @param parameters The requirement list, in name, value mapping.
   * @return The shared pointer to the encoded interest
   */
  static shared_ptr<Interest>
  genChallengeInterest(const RequesterState& state,
                       std::vector<std::tuple<std::string, std::string>>&& parameters);

  /**
   * Decodes the responsed data from the CHALLENGE interest.
   * @param state the corresponding requester state of the request. Will be modified.
   * @param reply the response data.
   * @throw std::runtime_error if the decoding fails or receiving an error packet.
   */
  static void
  onChallengeResponse(RequesterState& state, const Data& reply);

  /**
   * Generate the interest to fetch the issued certificate
   * @param state the state of the request.
   * @return The shared pointer to the encoded interest
   */
  static shared_ptr<Interest>
  genCertFetchInterest(const RequesterState& state);

  /**
   * Decoded and installs the response certificate from the certificate fetch.
   * @param reply the data replied from the certificate fetch interest.
   * @return The shared pointer to the certificate being fetched.
   */
  static shared_ptr<security::v2::Certificate>
  onCertFetchResponse(const Data& reply);

  /**
   * End the current request session and performs cleanup if necessary.
   * @param state the requester state for the request.
   */
  static void
  endSession(RequesterState& state);

private:
  static void
  processIfError(const Data& data);
};

} // namespace ndncert
} // namespace ndn

#endif // NDNCERT_REQUESTER_HPP