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

#include "assignment-param.hpp"

namespace ndn {
namespace ndncert {

NDNCERT_REGISTER_FUNCFACTORY(AssignmentParam, "param");

AssignmentParam::AssignmentParam(const std::string& format)
  : NameAssignmentFunc("param", format)
{}

std::vector<PartialName>
AssignmentParam::assignName(const std::vector<std::tuple<std::string, std::string>>& params)
{
  std::vector<PartialName> resultList;
  Name result;
  for (const auto& item : m_nameFormat) {
    auto it = std::find_if(params.begin(), params.end(),
                           [&](const std::tuple<std::string, std::string>& e) { return std::get<0>(e) == item; });
    if (it != params.end() && !std::get<1>(*it).empty()) {
      result.append(std::get<1>(*it));
    }
    else {
      return resultList;
    }
  }
  resultList.push_back(std::move(result));
  return resultList;
}

} // namespace ndncert
} // namespace ndn
