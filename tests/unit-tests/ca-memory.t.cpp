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
#include "ca-detail/ca-memory.hpp"
#include "ca-detail/ca-sqlite.hpp"

namespace ndn {
namespace ndncert {
namespace tests {

BOOST_FIXTURE_TEST_SUITE(TestCaMemory, IdentityManagementV2TimeFixture)

BOOST_AUTO_TEST_CASE(Initialization)
{
  BOOST_CHECK_NO_THROW(CaMemory storage);
}

BOOST_AUTO_TEST_CASE(CertificateOperations)
{
  CaMemory storage;

  auto identity1 = addIdentity(Name("/ndn/site1"));
  auto key1 = identity1.getDefaultKey();
  auto cert1 = key1.getDefaultCertificate();

  // add operation
  BOOST_CHECK_NO_THROW(storage.addCertificate("123", cert1));

  // get operation
  BOOST_CHECK_EQUAL(storage.getCertificate("123"), cert1);

  // list operation
  auto allCerts = storage.listAllIssuedCertificates();
  BOOST_CHECK_EQUAL(allCerts.size(), 1);

  auto identity2 = addIdentity(Name("/ndn/site2"));
  auto key2 = identity2.getDefaultKey();
  auto cert2 = key2.getDefaultCertificate();
  storage.addCertificate("456", cert2);

  allCerts = storage.listAllIssuedCertificates();
  BOOST_CHECK_EQUAL(allCerts.size(), 2);

  BOOST_CHECK_NO_THROW(storage.deleteCertificate("123"));

  allCerts = storage.listAllIssuedCertificates();
  BOOST_CHECK_EQUAL(allCerts.size(), 1);

  auto identity3 = addIdentity(Name("/ndn/site3"));
  auto key3 = identity3.getDefaultKey();
  auto cert3 = key3.getDefaultCertificate();

  // update operation
  BOOST_CHECK_NO_THROW(storage.updateCertificate("456", cert3));
  BOOST_CHECK_EQUAL(storage.getCertificate("456"), cert3);
}

BOOST_AUTO_TEST_CASE(RequestOperations)
{
  CaMemory storage;

  auto identity1 = addIdentity(Name("/ndn/site1"));
  auto key1 = identity1.getDefaultKey();
  auto cert1 = key1.getDefaultCertificate();

  // add operation
  CertificateRequest request1(Name("/ndn/site1"), "123", cert1);
  BOOST_CHECK_NO_THROW(storage.addRequest(request1));

  // get operation
  auto result = storage.getRequest("123");
  BOOST_CHECK_EQUAL(request1.getCert(), result.getCert());
  BOOST_CHECK_EQUAL(request1.getStatus(), result.getStatus());
  BOOST_CHECK_EQUAL(request1.getCaName(), result.getCaName());

  JsonSection json;
  json.put("code", "1234");

  // update operation
  CertificateRequest request2(Name("/ndn/site1"), "123", "need-verify", "EMAIL",
                              CaSqlite::convertJson2String(json), cert1);
  storage.updateRequest(request2);
  result = storage.getRequest("123");
  BOOST_CHECK_EQUAL(request2.getCert(), result.getCert());
  BOOST_CHECK_EQUAL(request2.getStatus(), result.getStatus());
  BOOST_CHECK_EQUAL(request2.getCaName(), result.getCaName());

  auto identity2 = addIdentity(Name("/ndn/site2"));
  auto key2 = identity2.getDefaultKey();
  auto cert2 = key2.getDefaultCertificate();
  CertificateRequest request3(Name("/ndn/site2"), "456", cert2);
  storage.addRequest(request3);

  // list operation
  auto allRequests = storage.listAllRequests();
  BOOST_CHECK_EQUAL(allRequests.size(), 2);

  storage.deleteRequest("456");
  allRequests = storage.listAllRequests();
  BOOST_CHECK_EQUAL(allRequests.size(), 1);
}

BOOST_AUTO_TEST_SUITE_END() // TestCaModule

} // namespace tests
} // namespace ndncert
} // namespace ndn
