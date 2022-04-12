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

#include "redirection/redirection-policy.hpp"
#include "redirection/redirection-param.hpp"
#include "redirection/redirection-email.hpp"

#include "test-common.hpp"

namespace ndncert::tests {

BOOST_AUTO_TEST_SUITE(TestRedirectionPolicy)

BOOST_AUTO_TEST_CASE(RedirectionPolicyParam)
{
  RedirectionParam assignment("");
  std::multimap<std::string, std::string> params;
  BOOST_CHECK(assignment.isRedirecting(params));
  params.emplace("abc", "123");
  BOOST_CHECK(assignment.isRedirecting(params));

  RedirectionParam assignment1("abc=123");
  params.clear();
  BOOST_CHECK(!assignment1.isRedirecting(params));
  params.emplace("abc", "124");
  BOOST_CHECK(!assignment1.isRedirecting(params));
  params.emplace("abc", "123");
  BOOST_CHECK(assignment1.isRedirecting(params));

  RedirectionParam assignment2("abc=123&xyz=789");
  params.clear();
  BOOST_CHECK(!assignment2.isRedirecting(params));
  params.emplace("abc", "123");
  BOOST_CHECK(!assignment2.isRedirecting(params));
  params.emplace("xyz", "788");
  BOOST_CHECK(!assignment2.isRedirecting(params));
  params.emplace("xyz", "789");
  BOOST_CHECK(assignment2.isRedirecting(params));
  params.emplace("abz", "789");
  BOOST_CHECK(assignment2.isRedirecting(params));
}

BOOST_AUTO_TEST_CASE(RedirectionPolicyEmail)
{
  RedirectionEmail assignment("cs.ucla.edu");
  std::multimap<std::string, std::string> params;
  BOOST_CHECK(!assignment.isRedirecting(params));
  params.emplace("email", "das@math.ucla.edu");
  BOOST_CHECK(!assignment.isRedirecting(params));

  params.clear();
  params.emplace("email", "das@cs.ucla.edu");
  BOOST_CHECK(assignment.isRedirecting(params));

  params.clear();
  params.emplace("email", "das@ucla.edu");
  BOOST_CHECK(!assignment.isRedirecting(params));
}

BOOST_AUTO_TEST_SUITE_END() // TestNameAssignment

} // namespace ndncert::tests
