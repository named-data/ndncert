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

#include <name-assignments/assignment-random.hpp>
#include <name-assignments/assignment-param.hpp>
#include <name-assignments/assignment-hash.hpp>
#include "test-common.hpp"

namespace ndn {
namespace ndncert {
namespace tests {

BOOST_AUTO_TEST_SUITE(TestNameAssignment)
BOOST_AUTO_TEST_CASE(NameAssignmentRandom)
{
  AssignmentRandom randomAssignment;
  auto func = randomAssignment.getFunction("");
  BOOST_CHECK_EQUAL(func(std::vector<std::tuple<std::string, std::string>>()).size(), 1);
  BOOST_CHECK_EQUAL(func(std::vector<std::tuple<std::string, std::string>>()).begin()->size(), 1);
}

BOOST_AUTO_TEST_CASE(NameAssignmentParam)
{
  AssignmentParam paramAssignment;
  auto func = paramAssignment.getFunction("abc:xyz");
  std::vector<std::tuple<std::string, std::string>> requirements;
  requirements.emplace_back("abc", "123");
  BOOST_CHECK_EQUAL(func(requirements).size(), 0);
  requirements.emplace_back("xyz", "789");
  BOOST_CHECK_EQUAL(func(requirements).size(), 1);
  BOOST_CHECK_EQUAL(*func(requirements).begin(), Name("/123/789"));
  requirements.emplace_back("fake", "456");
  BOOST_CHECK_EQUAL(func(requirements).size(), 1);
  BOOST_CHECK_EQUAL(*func(requirements).begin(), Name("/123/789"));
  requirements[1] = std::tuple<std::string, std::string>("xyz", "");
  BOOST_CHECK_EQUAL(func(requirements).size(), 0);
}

BOOST_AUTO_TEST_CASE(NameAssignmentHash)
{
  AssignmentHash hashAssignment;
  auto func = hashAssignment.getFunction("abc:xyz");
  std::vector<std::tuple<std::string, std::string>> requirements;
  requirements.emplace_back("abc", "123");
  BOOST_CHECK_EQUAL(func(requirements).size(), 0);
  requirements.emplace_back("xyz", "789");
  BOOST_CHECK_EQUAL(func(requirements).size(), 1);
  BOOST_CHECK_EQUAL(func(requirements).begin()->size(), 1);
  requirements.emplace_back("fake", "456");
  BOOST_CHECK_EQUAL(func(requirements).size(), 1);
  BOOST_CHECK_EQUAL(func(requirements).begin()->size(), 1);
  requirements[1] = std::tuple<std::string, std::string>("xyz", "");
  BOOST_CHECK_EQUAL(func(requirements).size(), 1);
  BOOST_CHECK_EQUAL(func(requirements).begin()->size(), 1);
}

BOOST_AUTO_TEST_SUITE_END()

}  // namespace tests
}  // namespace ndncert
}  // namespace ndn


