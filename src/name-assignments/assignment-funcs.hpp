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

#ifndef NDNCERT_ASSIGNMENT_FUNCS_HPP
#define NDNCERT_ASSIGNMENT_FUNCS_HPP

#include <configuration.hpp>
#include "ca-state.hpp"

namespace ndn {
namespace ndncert {

class NameAssignmentFuncFactory : noncopyable {
public:
  explicit
  NameAssignmentFuncFactory(const std::string& factoryType);

  virtual ~NameAssignmentFuncFactory() = default;

  template <class ChallengeType>
  static void
  registerNameAssignmentFuncFactories(const std::string& typeName)
  {
    FuncFactoryFactory& factory = getFactory();
    BOOST_ASSERT(factory.count(typeName) == 0);
    factory[typeName] = [] { return make_unique<ChallengeType>(); };
  }

  static bool
  isChallengeSupported(const std::string& challengeType);

  static unique_ptr<NameAssignmentFuncFactory>
  createNameAssignmentFuncFactory(const std::string& challengeType);

  virtual NameAssignmentFunc
  getFunction(const std::string& factoryParam) = 0;

public:
  const std::string FACTORY_TYPE;

private:
  typedef function<unique_ptr<NameAssignmentFuncFactory>()> FactoryCreateFunc;
  typedef std::map<std::string, FactoryCreateFunc> FuncFactoryFactory;

  static FuncFactoryFactory&
  getFactory();
};

#define NDNCERT_REGISTER_FUNCFACTORY(C, T)                               \
  static class NdnCert##C##FuncFactoryRegistrationClass {                \
  public:                                                                \
    NdnCert##C##FuncFactoryRegistrationClass()                           \
    {                                                                    \
      ::ndn::ndncert::NameAssignmentFuncFactory::registerNameAssignmentFuncFactories<C>(T); \
    }                                                                    \
  } g_NdnCert##C##ChallengeRegistrationVariable

}  // namespace ndncert
}  // namespace ndn

#endif  // NDNCERT_ASSIGNMENT_FUNCS_HPP
