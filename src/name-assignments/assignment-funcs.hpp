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

#include "../ca-state.hpp"

namespace ndn {
namespace ndncert {

/**
 * @brief The name assignment function provided by the CA operator to generate available
 * namecomponents.
 * The function does not guarantee that all the returned names are available. Therefore the
 * CA should further check the availability of each returned name and remove unavailable results.
 *
 * @p vector, input, a list of parameter key-value pair used for name assignment.
 * @return a vector containing the possible namespaces derived from the parameters.
 */
using NameAssignmentFunc = function<std::vector<PartialName>(const std::vector<std::tuple<std::string, std::string>>&)>;

class NameAssignmentFuncFactory : noncopyable {
public:
  explicit
  NameAssignmentFuncFactory(const std::string& factoryType, const std::string& format = "");

  virtual ~NameAssignmentFuncFactory() = default;

  template <class ChallengeType>
  static void
  registerNameAssignmentFuncFactories(const std::string& typeName)
  {
    FuncFactoryFactory& factory = getFactory();
    BOOST_ASSERT(factory.count(typeName) == 0);
    factory[typeName] = [](const std::string& format) { return make_unique<ChallengeType>(format); };
  }

  static unique_ptr<NameAssignmentFuncFactory>
  createNameAssignmentFuncFactory(const std::string& challengeType, const std::string& format = "");

  virtual std::vector<PartialName>
  assignName(const std::vector<std::tuple<std::string, std::string>>& params) = 0;

public:
  const std::string FACTORY_TYPE;
  std::vector<std::string> m_nameFormat;

private:
  typedef function<unique_ptr<NameAssignmentFuncFactory>(const std::string&)> FactoryCreateFunc;
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
