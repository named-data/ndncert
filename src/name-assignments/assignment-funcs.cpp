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

#include "assignment-funcs.hpp"
#include <ndn-cxx/util/random.hpp>

namespace ndn {
namespace ndncert {

NameAssignmentFuncFactory::NameAssignmentFuncFactory(const std::string& factoryType, const std::string& format)
  : FACTORY_TYPE(factoryType)
{
  auto s = format;
  size_t pos = 0;
  while ((pos = s.find("/")) != std::string::npos) {
    m_nameFormat.push_back(s.substr(0, pos));
    s.erase(0, pos + 1);
  }
  m_nameFormat.push_back(s);
}

unique_ptr<NameAssignmentFuncFactory>
NameAssignmentFuncFactory::createNameAssignmentFuncFactory(const std::string& challengeType, const std::string& format)
{
  FuncFactoryFactory& factory = getFactory();
  auto i = factory.find(challengeType);
  return i == factory.end() ? nullptr : i->second(format);
}

NameAssignmentFuncFactory::FuncFactoryFactory&
NameAssignmentFuncFactory::getFactory()
{
  static NameAssignmentFuncFactory::FuncFactoryFactory factory;
  return factory;
}

} // namespace ndncert
} // namespace ndn
