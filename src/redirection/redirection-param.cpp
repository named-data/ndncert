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

#include "redirection-param.hpp"

#include <boost/algorithm/string/classification.hpp>
#include <boost/algorithm/string/split.hpp>

namespace ndncert {

NDNCERT_REGISTER_REDIRECTION_POLICY(RedirectionParam, "param");

RedirectionParam::RedirectionParam(const std::string& format)
{
  if (format.empty()) {
    return;
  }

  std::vector<std::string> strs;
  boost::split(strs, format, boost::is_any_of("&"));
  for (const auto& s : strs) {
    auto i = s.find('=');
    if (i == std::string::npos) {
      NDN_THROW(std::runtime_error("Redirection param format: no '=' in format piece"));
    }
    m_format.emplace(s.substr(0, i), s.substr(i + 1));
  }
}

bool
RedirectionParam::isRedirecting(const std::multimap<std::string, std::string>& params)
{
  for (const auto& p : m_format) {
    bool found = false;
    for (auto it = params.find(p.first); it != params.end() && it->first == p.first; ++it) {
      if (it->second == p.second) {
        found = true;
        break;
      }
    }
    if (!found) {
      return false;
    }
  }
  return true;
}

} // namespace ndncert
