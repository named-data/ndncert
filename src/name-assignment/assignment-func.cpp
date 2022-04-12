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

#include "assignment-func.hpp"

namespace ndncert {

NameAssignmentFunc::NameAssignmentFunc(const std::string& format)
{
  size_t index = 0, startIndex = 0;
  while ((index = format.find("/", startIndex)) != std::string::npos) {
    auto component = format.substr(startIndex, index - startIndex);
    if (!component.empty()) {
      m_nameFormat.push_back(component);
    }
    startIndex = index + 1;
  }
  if (startIndex != format.size()) {
    m_nameFormat.push_back(format.substr(startIndex));
  }
}

std::unique_ptr<NameAssignmentFunc>
NameAssignmentFunc::createNameAssignmentFunc(const std::string& challengeType, const std::string& format)
{
  auto& factory = getFactory();
  auto i = factory.find(challengeType);
  return i == factory.end() ? nullptr : i->second(format);
}

NameAssignmentFunc::FuncFactory&
NameAssignmentFunc::getFactory()
{
  static FuncFactory factory;
  return factory;
}

} // namespace ndncert
