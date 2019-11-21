/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
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

#include "client-config.hpp"

#include "boost-test.hpp"

namespace ndn {
namespace ndncert {
namespace tests {

BOOST_AUTO_TEST_SUITE(TestClientConfig)

BOOST_AUTO_TEST_CASE(ReadConfigFile)
{
  ClientConfig config;
  config.load("tests/unit-tests/client.conf.test");
  BOOST_CHECK_EQUAL(config.m_caItems.size(), 2);

  const auto& item = config.m_caItems.front();
  BOOST_CHECK_EQUAL(item.m_caName, "/ndn/edu/ucla");
  BOOST_CHECK_EQUAL(item.m_caInfo, "UCLA's ceritificate authority, located in BH4805.");
  BOOST_CHECK_EQUAL(item.m_probe, "email");
  BOOST_CHECK_EQUAL(item.m_anchor.getName(),
                    "/ndn/site1/KEY/%11%BC%22%F4c%15%FF%17/self/%FD%00%00%01Y%C8%14%D9%A5");

  BOOST_CHECK_EQUAL(config.m_localNdncertAnchor, "/usr/local/etc/ndncert/anchor.key");
}

BOOST_AUTO_TEST_CASE(ReadNonexistConfigFile)
{
  ClientConfig config;
  BOOST_CHECK_THROW(config.load("tests/unit-tests/nonexist"), ClientConfig::Error);
}

BOOST_AUTO_TEST_CASE(ReadConfigFileWithInvalidCert)
{
  ClientConfig config;
  BOOST_CHECK_THROW(config.load("tests/unit-tests/client.conf.test2"), ClientConfig::Error);
}

BOOST_AUTO_TEST_CASE(ReadConfigFileWithoutCaPrefix)
{
  ClientConfig config;
  BOOST_CHECK_THROW(config.load("tests/unit-tests/client.conf.test3"), ClientConfig::Error);
}

BOOST_AUTO_TEST_CASE(AddAndRemoveCaItem)
{
  ClientConfig config;
  config.load("tests/unit-tests/client.conf.test");

  ClientCaItem item;
  item.m_caName = Name("/test");
  item.m_caInfo = "test";
  item.m_probe = "test";

  config.m_caItems.push_back(item);
  BOOST_CHECK_EQUAL(config.m_caItems.size(), 3);
  auto lastItem = config.m_caItems.back();
  BOOST_CHECK_EQUAL(lastItem.m_caName, "/test");

  config.removeCaItem(Name("/test"));
  BOOST_CHECK_EQUAL(config.m_caItems.size(), 2);
  lastItem = config.m_caItems.back();
  BOOST_CHECK_EQUAL(lastItem.m_caName, "/ndn/edu/ucla/zhiyi");
}

BOOST_AUTO_TEST_SUITE_END() // TestClientConfig

} // namespace tests
} // namespace ndncert
} // namespace ndn
