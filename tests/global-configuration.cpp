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

#include "tests/boost-test.hpp"

#include <ndn-cxx/util/exception.hpp>

#include <boost/filesystem/operations.hpp>
#include <boost/filesystem/path.hpp>

#include <stdexcept>
#include <stdlib.h>

namespace ndncert::tests {

class GlobalConfiguration
{
public:
  GlobalConfiguration()
  {
    const char* envHome = ::getenv("HOME");
    if (envHome)
      m_home.assign(envHome);

    // in case an earlier test run crashed without a chance to run the destructor
    boost::filesystem::remove_all(TESTDIR);

    auto testHome = TESTDIR / "test-home";
    boost::filesystem::create_directories(testHome);

    if (::setenv("HOME", testHome.c_str(), 1) != 0)
      NDN_THROW(std::runtime_error("setenv() failed"));
  }

  ~GlobalConfiguration() noexcept
  {
    if (m_home.empty())
      ::unsetenv("HOME");
    else
      ::setenv("HOME", m_home.data(), 1);

    boost::system::error_code ec;
    boost::filesystem::remove_all(TESTDIR, ec); // ignore error
  }

private:
  static inline const boost::filesystem::path TESTDIR{UNIT_TESTS_TMPDIR};
  std::string m_home;
};

BOOST_TEST_GLOBAL_CONFIGURATION(GlobalConfiguration);

} // namespace ndncert::tests
