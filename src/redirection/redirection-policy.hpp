/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2017-2024, Regents of the University of California.
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

#ifndef NDNCERT_REDIRECTION_POLICY_HPP
#define NDNCERT_REDIRECTION_POLICY_HPP

#include "detail/ndncert-common.hpp"

#include <map>

namespace ndncert {

class RedirectionPolicy : boost::noncopyable
{
public:
  virtual
  ~RedirectionPolicy() = default;

  /**
   * @brief The Redirection Policy provided by the CA operator to decide if redirection is suitable.
   * @param params A list of parameter key-value pairs from the probe.
   * @return true if the provided @p params conform to the configured redirection policy.
   */
  virtual bool
  isRedirecting(const std::multimap<std::string, std::string>& params) = 0;

public: // factory
  template<class PolicyType>
  static void
  registerRedirectionPolicy(const std::string& type)
  {
    PolicyFactory& factory = getFactory();
    BOOST_ASSERT(factory.count(type) == 0);
    factory[type] = [] (const std::string& format) { return std::make_unique<PolicyType>(format); };
  }

  static std::unique_ptr<RedirectionPolicy>
  createPolicyFunc(const std::string& policyType, const std::string& format = "");

private:
  using CreateFunc = std::function<std::unique_ptr<RedirectionPolicy>(const std::string &)>;
  using PolicyFactory = std::map<std::string, CreateFunc>;

  static PolicyFactory&
  getFactory();
};

} // namespace ndncert

#define NDNCERT_REGISTER_REDIRECTION_POLICY(C, T)                             \
static class NdnCert##C##RedirectionPolicyRegistrationClass                   \
{                                                                             \
public:                                                                       \
  NdnCert##C##RedirectionPolicyRegistrationClass()                            \
  {                                                                           \
    ::ndncert::RedirectionPolicy::registerRedirectionPolicy<C>(T);            \
  }                                                                           \
} g_NdnCert##C##RedirectionPolicyRegistrationVariable

#endif // NDNCERT_REDIRECTION_POLICY_HPP
