/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2017-2022, Regents of the University of California.
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

#include "detail/ca-configuration.hpp"

#include <ndn-cxx/util/io.hpp>

#include <boost/filesystem.hpp>
#include <boost/property_tree/json_parser.hpp>

namespace ndncert::ca {

void
CaConfig::load(const std::string& fileName)
{
  JsonSection configJson;
  try {
    boost::property_tree::read_json(fileName, configJson);
  }
  catch (const std::exception& error) {
    NDN_THROW(std::runtime_error("Failed to parse configuration file " + fileName + ", " + error.what()));
  }

  if (configJson.begin() == configJson.end()) {
    NDN_THROW(std::runtime_error("No JSON configuration found in file: " + fileName));
  }
  caProfile = CaProfile::fromJson(configJson);
  if (caProfile.supportedChallenges.empty()) {
    NDN_THROW(std::runtime_error("At least one challenge should be specified."));
  }

  // parse redirection section if present
  redirection.clear();
  auto redirectionItems = configJson.get_child_optional(CONFIG_REDIRECTION);
  if (redirectionItems) {
    for (const auto& item : *redirectionItems) {
      auto caPrefixStr = item.second.get(CONFIG_CA_PREFIX, "");
      auto caCertStr = item.second.get(CONFIG_CERTIFICATE, "");
      if (caCertStr.empty()) {
        NDN_THROW(std::runtime_error("Redirect-to item's certificate cannot be empty."));
      }
      std::istringstream ss(caCertStr);
      auto caCert = ndn::io::load<Certificate>(ss);
      if (!caPrefixStr.empty() && Name(caPrefixStr) != caCert->getIdentity()) {
        NDN_THROW(std::runtime_error("Redirect-to item's prefix and certificate does not match."));
      }

      auto policyType = item.second.get(CONFIG_REDIRECTION_POLICY_TYPE, "");
      auto policyParam = item.second.get(CONFIG_REDIRECTION_POLICY_PARAM, "");
      if (policyType.empty()) {
        NDN_THROW(std::runtime_error("Redirect-to policy type expected but not provided."));
      }
      auto policy = RedirectionPolicy::createPolicyFunc(policyType, policyParam);
      if (policy == nullptr) {
        NDN_THROW(std::runtime_error("Error on creating redirection policy"));
      }
      redirection.emplace_back(caCert, std::move(policy));
    }
  }

  // parse name assignment if present
  nameAssignmentFuncs.clear();
  auto nameAssignmentItems = configJson.get_child_optional(CONFIG_NAME_ASSIGNMENT);
  if (nameAssignmentItems) {
    for (const auto& [key, val] : *nameAssignmentItems) {
      auto func = NameAssignmentFunc::createNameAssignmentFunc(key, val.data());
      if (func == nullptr) {
        NDN_THROW(std::runtime_error("Error on creating name assignment function"));
      }
      nameAssignmentFuncs.push_back(std::move(func));
    }
  }
}

} // namespace ndncert::ca
