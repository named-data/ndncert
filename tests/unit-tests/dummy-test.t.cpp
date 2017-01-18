/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/**
 * Copyright (c) 2017, Regents of the University of California.
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

#include "test-common.hpp"

namespace ndn {
namespace ndncert {
namespace tests {

// See http://redmine.named-data.net/projects/nfd/wiki/UnitTesting on how to name a test suite.
BOOST_AUTO_TEST_SUITE(TestSkeleton)

BOOST_AUTO_TEST_CASE(Test1)
{
  int i = 0;

  // For reference of available Boost.Test macros, see
  // http://www.boost.org/doc/libs/1_54_0/libs/test/doc/html/utf/testing-tools/reference.html

  BOOST_REQUIRE_NO_THROW(i = 1);
  BOOST_REQUIRE_EQUAL(i, 1);
}

// Use UnitTestTimeFixture to mock clocks.
BOOST_FIXTURE_TEST_CASE(Test2, UnitTestTimeFixture)
{
  // this->advanceClocks increments mock clocks.
  advanceClocks(time::milliseconds(500), 2);
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace tests
} // namespace ndncert
} // namespace ndn
