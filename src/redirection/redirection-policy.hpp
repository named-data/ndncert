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

#ifndef NDNCERT_REDIRECTION_POLICY_HPP
#define NDNCERT_REDIRECTION_POLICY_HPP

#include "detail/ca-request-state.hpp"

#include <map>

namespace ndncert {

class RedirectionPolicy : boost::noncopyable
{
protected:
  explicit RedirectionPolicy(const std::string& format = "") {}

public:
  virtual ~RedirectionPolicy() = default;

  /**
   * @brief The Redirection Policy provided by the CA operator to decide if redirection is suitable.
   *
   *
   * @param vector A list of parameter key-value pair from probe.
   * @return a boolean that is true if the provided params conform to the configured redirection policy.
   */
  virtual bool
  isRedirecting(const std::multimap<std::string, std::string>& params) = 0;

public:
  template <class PolicyType>
  static void
  registerRedirectionPolicy(const std::string& typeName)
  {
    PolicyFactory& factory = getFactory();
    BOOST_ASSERT(factory.count(typeName) == 0);
    factory[typeName] = [](const std::string& format) { return std::make_unique<PolicyType>(format); };
  }

  static std::unique_ptr<RedirectionPolicy>
  createPolicyFunc(const std::string& policyType, const std::string& format = "");

private:
  typedef std::function<std::unique_ptr<RedirectionPolicy>(const std::string&)> FactoryCreateFunc;
  typedef std::map<std::string, FactoryCreateFunc> PolicyFactory;

  static PolicyFactory&
  getFactory();
};

#define NDNCERT_REGISTER_POLICY_FACTORY(C, T)                                  \
  static class NdnCert##C##PolicyFactoryRegistrationClass                      \
  {                                                                               \
  public:                                                                         \
    NdnCert##C##PolicyFactoryRegistrationClass()                               \
    {                                                                             \
      ::ndncert::RedirectionPolicy::registerRedirectionPolicy<C>(T);        \
    }                                                                             \
  } g_NdnCert##C##RedirectionPolicyRegistrationVariable

} // namespace ndncert

#endif // NDNCERT_REDIRECTION_POLICY_HPP
