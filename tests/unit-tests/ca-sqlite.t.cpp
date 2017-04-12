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

#include "identity-management-fixture.hpp"
#include "ca-detail/ca-sqlite.hpp"

namespace ndn {
namespace ndncert {
namespace tests {

BOOST_FIXTURE_TEST_SUITE(TestCaSqlite, IdentityManagementV2TimeFixture)

BOOST_AUTO_TEST_CASE(Initialization)
{
  BOOST_CHECK_NO_THROW(CaSqlite storage);
}

BOOST_AUTO_TEST_CASE(CertificateOperations)
{
  CaSqlite storage;

  auto identity = addIdentity(Name("/ndn/site1"));
  auto key = identity.getDefaultKey();
  auto cert = key.getDefaultCertificate();

  BOOST_CHECK_NO_THROW(storage.addCertificate("123", cert));
  auto result = storage.getCertificate("123");
  BOOST_CHECK_EQUAL(cert, result);
}

BOOST_AUTO_TEST_CASE(RequestOperations)
{
  CaSqlite storage;

  auto identity = addIdentity(Name("/ndn/site2"));
  auto key = identity.getDefaultKey();
  auto cert = key.getDefaultCertificate();

  CertificateRequest request1(Name("/ndn/site2"), "123", cert);
  BOOST_CHECK_NO_THROW(storage.addRequest(request1));
  auto result = storage.getRequest("123");
  BOOST_CHECK_EQUAL(request1.getCert(), result.getCert());
  BOOST_CHECK_EQUAL(request1.getStatus(), result.getStatus());
  BOOST_CHECK_EQUAL(request1.getCaName(), result.getCaName());

  JsonSection json;
  json.put("code", "1234");
  std::stringstream ss;
  boost::property_tree::write_json(ss, json);
  std::string jsonValue = ss.str();

  CertificateRequest request2(Name("/ndn/site2"), "123", "need-verify", "EMAIL", jsonValue, cert);
  storage.updateRequest(request2);
  result = storage.getRequest("123");
  BOOST_CHECK_EQUAL(request2.getCert(), result.getCert());
  BOOST_CHECK_EQUAL(request2.getStatus(), result.getStatus());
  BOOST_CHECK_EQUAL(request2.getCaName(), result.getCaName());
}

BOOST_AUTO_TEST_SUITE_END() // TestCaModule

} // namespace tests
} // namespace ndncert
} // namespace ndn
