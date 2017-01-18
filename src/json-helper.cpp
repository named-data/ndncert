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

#include "json-helper.hpp"
#include <boost/lexical_cast.hpp>

namespace ndn {
namespace ndncert {

const JsonSection
genResponseProbeJson(const Name& identifier, const Name& CaInformation)
{
  JsonSection root;

  root.put(JSON_IDNENTIFIER, identifier.toUri());
  root.put(JSON_CA_INFO, CaInformation.toUri());

  return root;
}

const JsonSection
genResponseNewJson(const CertificateRequest& request,
                   const std::list<std::tuple<std::string, std::string>> challenges)
{
  JsonSection root;
  JsonSection challengesSection;
  root.put(JSON_STATUS, boost::lexical_cast<std::string>(request.getStatus()));
  root.put(JSON_REQUEST_ID, request.getRequestId());

  for (const auto& entry : challenges) {
    JsonSection challenge;
    challenge.put(JSON_CHALLENGE_TYPE, std::get<0>(entry));
    challenge.put(JSON_CHALLENGE_INSTRUCTION, std::get<1>(entry));
    challengesSection.push_back(std::make_pair("", challenge));
  }
  root.add_child(JSON_CHALLENGES, challengesSection);

  return root;
}

const JsonSection
genResponsePollJson(const CertificateRequest& request)
{
  JsonSection root;
  root.put(JSON_STATUS, boost::lexical_cast<std::string>(request.getStatus()));
  root.put(JSON_CHALLENGE_TYPE, request.getChallengeType());
  root.put(JSON_CHALLENGE_STATUS, request.getChallengeStatus());
  root.put(JSON_CHALLENGE_INSTRUCTION, request.getChallengeInstruction());
  return root;
}

const JsonSection
genErrorJson(const std::string& errorInfo)
{
  JsonSection root;
  root.put(JSON_STATUS, "error");
  root.put(JSON_ERROR_INFO, errorInfo);
  return root;
}

} // namespace ndncert
} // namespace ndn
