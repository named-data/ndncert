/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2013-2020 Regents of the University of California.
 *
 * This file is part of ndn-cxx library (NDN C++ library with eXperimental eXtensions).
 *
 * ndn-cxx library is free software: you can redistribute it and/or modify it under the
 * terms of the GNU Lesser General Public License as published by the Free Software
 * Foundation, either version 3 of the License, or (at your option) any later version.
 *
 * ndn-cxx library is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
 * PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more details.
 *
 * You should have received copies of the GNU General Public License and GNU Lesser
 * General Public License along with ndn-cxx, e.g., in COPYING.md file.  If not, see
 * <http://www.gnu.org/licenses/>.
 *
 * See AUTHORS.md for complete list of ndn-cxx authors and contributors.
 */

#ifndef NDN_TESTS_TEST_HOME_FIXTURE_HPP
#define NDN_TESTS_TEST_HOME_FIXTURE_HPP

#include <ndn-cxx/security/key-chain.hpp>
#include <cstdlib>
#include <fstream>
#include <initializer_list>
#include <boost/algorithm/string.hpp>
#include <boost/filesystem.hpp>

namespace ndn {
namespace ndncert {
namespace tests {

/**
 * @brief TestHomeFixture to set TEST_HOME variable and allow config file creation
 */
template<class Path>
class TestHomeFixture
{
public:
  TestHomeFixture()
    : m_testHomeDir(Path().PATH)
  {
    setenv("TEST_HOME", m_testHomeDir.c_str(), true);
  }

  ~TestHomeFixture()
  {
    unsetenv("TEST_HOME");
  }

  void
  createClientConf(std::initializer_list<std::string> lines) const
  {
    boost::filesystem::create_directories(boost::filesystem::path(m_testHomeDir) / ".ndn");
    std::ofstream of((boost::filesystem::path(m_testHomeDir) / ".ndn" / "client.conf").c_str());
    for (auto line : lines) {
      boost::replace_all(line, "%PATH%", m_testHomeDir);
      of << line << std::endl;
    }
  }

protected:
  std::string m_testHomeDir;
};

struct DefaultPibDir
{
  const std::string PATH = "build/keys";
};

} // namespace tests
} // namespace ndncert
} // namespace ndn

#endif // NDN_TESTS_TEST_HOME_FIXTURE_HPP
