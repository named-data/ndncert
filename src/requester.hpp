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

#include "requester-state.hpp"

namespace ndn {
namespace ndncert {

// TODO
// For each RequesterState, create a validator instance and initialize it with CA's cert
// The validator instance should be in CaProfile

class Requester : noncopyable
{
public:
  /**
   * Generates a CA profile discovery Interest following RDR protocol.
   * @p caName, the name prefix of the CA.
   * @return A shared pointer to an Interest ready to be sent.
   */
  static shared_ptr<Interest>
  genCaProfileDiscoveryInterest(const Name& caName);

  /**
   * Generates a CA profile fetching Interest following RDR protocol.
   * @p reply, the Data packet replied from discovery Interest.
   * @return A shared pointer to an Interest ready to be sent.
   */
  static shared_ptr<Interest>
  genCaProfileInterestFromDiscoveryResponse(const Data& reply);

  /**
   * Decodes the CA profile from the replied CA profile Data packet.
   * Will first verify the signature of the packet using the key provided inside the profile.
   * The application should be cautious whether to add CaProfile into the RequesterCaCache.
   * @p reply, the Data packet replied from CA profile fetching Interest.
   * @return the CaProfile if decoding is successful
   * @throw std::runtime_error if the decoding fails or receiving an error packet.
   */
  static boost::optional<CaProfile>
  onCaProfileResponse(const Data& reply);

  /**
   * Decodes the CA profile from the replied CA profile Data packet after the redirection.
   * Will first verify the signature of the packet using the key provided inside the profile and
   * verify the certificate's digest matches the one obtained from the original CA.
   * The application should be cautious whether to add CaProfile into the RequesterCaCache.
   * @p reply, the Data packet replied from CA profile fetching Interest.
   * @p caCertFullName, the full name obtained from original CA's probe response.
   * @return the CaProfile if decoding is successful
   * @throw std::runtime_error if the decoding fails or receiving an error packet.
   */
  static boost::optional<CaProfile>
  onCaProfileResponseAfterRedirection(const Data& reply, const Name& caCertFullName);

  /**
   * Generates a PROBE interest to the CA (for suggested name assignments).
   * @p ca, the CA that interest is send to
   * @p probeInfo, the requester information to carry to the CA
   * @return A shared pointer of to the encoded interest, ready to be sent.
   */
  static shared_ptr<Interest>
  genProbeInterest(const CaProfile& ca, std::vector<std::tuple<std::string, std::string>>&& probeInfo);

  /**
   * Decodes the replied data for PROBE process from the CA.
   * Will first verify the signature of the packet using the key provided inside the profile.
   * @p reply, The replied data packet
   * @p ca, the profile of the CA that replies the packet
   * @p identityNames, The vector to load the decoded identity names from the data.
   * @p otherCas, The vector to load the decoded redirection CA prefixes from the data.
   * @throw std::runtime_error if the decoding fails or receiving an error packet.
   */
  static void
  onProbeResponse(const Data& reply, const CaProfile& ca,
                  std::vector<std::pair<Name, int>>& identityNames, std::vector<Name>& otherCas);

  // NEW/REVOKE/RENEW related helpers
  /**
   * Generates a NEW interest to the CA.
   * @p state, The current requester state for this request. Will be modified in the function.
   * @p identityName, The identity name to be requested.
   * @p notBefore, The expected notBefore field for the certificate (starting time)
   * @p notAfter, The expected notAfter field for the certificate (expiration time)
   * @return The shared pointer to the encoded interest.
   */
  static shared_ptr<Interest>
  genNewInterest(RequesterState& state, const Name& identityName,
                 const time::system_clock::TimePoint& notBefore,
                 const time::system_clock::TimePoint& notAfter);

  /**
   * Generates a REVOKE interest to the CA.
   * @p state, The current requester state for this request. Will be modified in the function.
   * @p certificate, the certificate to the revoked.
   * @return The shared pointer to the encoded interest.
   */
  static shared_ptr<Interest>
  genRevokeInterest(RequesterState& state, const security::Certificate& certificate);

  /**
   * Decodes the replied data of NEW, RENEW, or REVOKE interest from the CA.
   * @p state, the current requester state for the request. Will be updated in the function.
   * @p reply, the replied data from the network
   * @return the list of challenge accepted by the CA, for CHALLENGE step.
   * @throw std::runtime_error if the decoding fails or receiving an error packet.
   */
  static std::list<std::string>
  onNewRenewRevokeResponse(RequesterState& state, const Data& reply);

  // CHALLENGE helpers
  /**
   * Generates the required parameter for the selected challenge for the request
   * @p state, The requester state of the request.Will be updated in the function.
   * @p challengeSelected, The selected challenge for the request.
   *            Can use state.m_challengeType to continue.
   * @return The requirement list for the current stage of the challenge, in name, prompt mapping.
   * @throw std::runtime_error if the challenge is not supported.
   */
  static std::vector<std::tuple<std::string, std::string>>
  selectOrContinueChallenge(RequesterState& state, const std::string& challengeSelected);

  /**
   * Generates the CHALLENGE interest for the request.
   * @p state, The requester state of the request.
   * @p parameters, The requirement list, in name, value mapping.
   * @return The shared pointer to the encoded interest
   * @throw std::runtime_error if the challenge is not selected or is not supported.
   */
  static shared_ptr<Interest>
  genChallengeInterest(const RequesterState& state,
                       std::vector<std::tuple<std::string, std::string>>&& parameters);

  /**
   * Decodes the responded data from the CHALLENGE interest.
   * @p state, the corresponding requester state of the request. Will be modified.
   * @p reply, the response data.
   * @throw std::runtime_error if the decoding fails or receiving an error packet.
   */
  static void
  onChallengeResponse(RequesterState& state, const Data& reply);

  /**
   * Generate the interest to fetch the issued certificate
   * @p state, the state of the request.
   * @return The shared pointer to the encoded interest
   */
  static shared_ptr<Interest>
  genCertFetchInterest(const RequesterState& state);

  /**
   * Decoded and installs the response certificate from the certificate fetch.
   * @p reply, the data replied from the certificate fetch interest.
   * @return The shared pointer to the certificate being fetched.
   */
  static shared_ptr<security::Certificate>
  onCertFetchResponse(const Data& reply);

  /**
   * End the current request session and performs cleanup if necessary.
   * @p state, the requester state for the request.
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
