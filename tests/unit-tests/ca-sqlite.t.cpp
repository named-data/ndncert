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

#include "ca-storage-detail/ca-sqlite.hpp"
#include "test-common.hpp"

namespace ndn {
namespace ndncert {
namespace tests {

BOOST_FIXTURE_TEST_SUITE(TestCaSqlite, DatabaseFixture)

BOOST_AUTO_TEST_CASE(RequestOperations)
{
  CaSqlite storage(Name(), dbDir.string() + "TestCaSqlite_RequestOperations.db");

  auto identity1 = addIdentity(Name("/ndn/site1"));
  auto key1 = identity1.getDefaultKey();
  auto cert1 = key1.getDefaultCertificate();

  // add operation
  CaState request1(Name("/ndn/site1"), "123", RequestType::NEW, Status::BEFORE_CHALLENGE, cert1, makeStringBlock(tlv::ContentType_Key, "PretendItIsAKey"));
  storage.addRequest(request1);

  // get operation
  auto result = storage.getRequest("123");
  BOOST_CHECK_EQUAL(request1.m_cert, result.m_cert);
  BOOST_CHECK(request1.m_status == result.m_status);
  BOOST_CHECK_EQUAL(request1.m_caPrefix, result.m_caPrefix);
  BOOST_CHECK_EQUAL(request1.m_encryptionKey, result.m_encryptionKey);

  // update operation
  JsonSection json;
  json.put("test", "4567");
  CaState request2(Name("/ndn/site1"), "123", RequestType::NEW, Status::CHALLENGE, cert1,
                   "email", "test", time::system_clock::now(), 3, time::seconds(3600), std::move(json), makeEmptyBlock(tlv::ContentType_Key));
  storage.updateRequest(request2);
  result = storage.getRequest("123");
  BOOST_CHECK_EQUAL(request2.m_cert, result.m_cert);
  BOOST_CHECK(request2.m_status == result.m_status);
  BOOST_CHECK_EQUAL(request2.m_caPrefix, result.m_caPrefix);

  auto identity2 = addIdentity(Name("/ndn/site2"));
  auto key2 = identity2.getDefaultKey();
  auto cert2 = key2.getDefaultCertificate();
  CaState request3(Name("/ndn/site2"), "456", RequestType::NEW, Status::BEFORE_CHALLENGE, cert2, makeStringBlock(tlv::ContentType_Key, "PretendItIsAKey"));
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

BOOST_AUTO_TEST_CASE(DuplicateAdd)
{
    CaSqlite storage(Name(), dbDir.string() + "TestCaSqlite_DuplicateAdd.db");

    auto identity1 = addIdentity(Name("/ndn/site1"));
    auto key1 = identity1.getDefaultKey();
    auto cert1 = key1.getDefaultCertificate();

    // add operation
    CaState request1(Name("/ndn/site1"), "123", RequestType::NEW, Status::BEFORE_CHALLENGE, cert1, makeEmptyBlock(tlv::ContentType_Key));
    BOOST_CHECK_NO_THROW(storage.addRequest(request1));
    // add again
    BOOST_CHECK_THROW(storage.addRequest(request1), std::runtime_error);
}

BOOST_AUTO_TEST_SUITE_END() // TestCaModule

} // namespace tests
} // namespace ndncert
} // namespace ndn
