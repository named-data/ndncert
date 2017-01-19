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

#include "boost-test.hpp"
#include "challenge-module.hpp"

namespace ndn {
namespace ndncert {
namespace tests {

BOOST_AUTO_TEST_SUITE(TestChallengeModule)

BOOST_AUTO_TEST_CASE(GetJsonFromNameComponent)
{
  JsonSection json;
  json.put("test", "123");
  std::stringstream ss;
  boost::property_tree::write_json(ss, json);
  std::string jsonString = ss.str();
  Block jsonContent = makeStringBlock(ndn::tlv::NameComponent, ss.str());

  Name name("ndn");
  name.append(jsonContent);
  BOOST_CHECK(ChallengeModule::getJsonFromNameComponent(name, 1) == json);
}

BOOST_AUTO_TEST_CASE(GenDownloadName)
{
  Name interestName = ChallengeModule::genDownloadName(Name("ca"), "123");
  BOOST_CHECK_EQUAL(interestName.getSubName(0, 1), Name("ca"));
  BOOST_CHECK_EQUAL(interestName.getSubName(1, 1), Name("_DOWNLOAD"));

  JsonSection json;
  json.put(JSON_REQUEST_ID, "123");
  BOOST_CHECK(ChallengeModule::getJsonFromNameComponent(interestName, 2) == json);
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace tests
} // namespace ndncert
} // namespace ndn
