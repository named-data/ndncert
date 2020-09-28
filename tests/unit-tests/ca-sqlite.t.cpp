/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
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

#include "ca-detail/ca-sqlite.hpp"
#include "test-common.hpp"

namespace ndn {
namespace ndncert {
namespace tests {

BOOST_FIXTURE_TEST_SUITE(TestCaSqlite, DatabaseFixture)

BOOST_AUTO_TEST_CASE(Initialization)
{
  BOOST_CHECK_NO_THROW(CaSqlite storage(dbDir.string()));
}

BOOST_AUTO_TEST_CASE(CertificateOperations)
{
  CaSqlite storage(dbDir.string());

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
  CaSqlite storage(dbDir.string());

  auto identity1 = addIdentity(Name("/ndn/site1"));
  auto key1 = identity1.getDefaultKey();
  auto cert1 = key1.getDefaultCertificate();

  // add operation
  CertificateRequest request1(Name("/ndn/site1"), "123", REQUEST_TYPE_NEW, Status::BEFORE_CHALLENGE, cert1);
  BOOST_CHECK_NO_THROW(storage.addRequest(request1));

  // get operation
  auto result = storage.getRequest("123");
  BOOST_CHECK_EQUAL(request1.m_cert, result.m_cert);
  BOOST_CHECK(request1.m_status == result.m_status);
  BOOST_CHECK_EQUAL(request1.m_caPrefix, result.m_caPrefix);

  // update operation
  JsonSection json;
  json.put("test", "4567");
  CertificateRequest request2(Name("/ndn/site1"), "123", REQUEST_TYPE_NEW, Status::CHALLENGE, CHALLENGE_STATUS_SUCCESS,
                             "Email", time::toIsoString(time::system_clock::now()), 3600, 3, json, cert1);
  storage.updateRequest(request2);
  result = storage.getRequest("123");
  BOOST_CHECK_EQUAL(request2.m_cert, result.m_cert);
  BOOST_CHECK(request2.m_status == result.m_status);
  BOOST_CHECK_EQUAL(request2.m_caPrefix, result.m_caPrefix);

  auto identity2 = addIdentity(Name("/ndn/site2"));
  auto key2 = identity2.getDefaultKey();
  auto cert2 = key2.getDefaultCertificate();
  CertificateRequest request3(Name("/ndn/site2"), "456", REQUEST_TYPE_NEW, Status::BEFORE_CHALLENGE, cert2);
  storage.addRequest(request3);

  // list operation
  auto allRequests = storage.listAllRequests();
  BOOST_CHECK_EQUAL(allRequests.size(), 2);

  storage.deleteRequest("456");
  allRequests = storage.listAllRequests();
  BOOST_CHECK_EQUAL(allRequests.size(), 1);

  storage.deleteRequest("123");
  allRequests = storage.listAllRequests();
  BOOST_CHECK_EQUAL(allRequests.size(), 0);
}

BOOST_AUTO_TEST_SUITE_END() // TestCaModule

} // namespace tests
} // namespace ndncert
} // namespace ndn
