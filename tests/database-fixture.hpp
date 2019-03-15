/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/**
 * Copyright (c) 2014-2019, Regents of the University of California,
 *                          Arizona Board of Regents,
 *                          Colorado State University,
 *                          University Pierre & Marie Curie, Sorbonne University,
 *                          Washington University in St. Louis,
 *                          Beijing Institute of Technology,
 *                          The University of Memphis.
 *
 * This file, originally written as part of NFD (Named Data Networking Forwarding Daemon),
 * is a part of ndncert, a certificate management system based on NDN.
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

#ifndef NDNCERT_TESTS_DATABASE_FIXTURE_HPP
#define NDNCERT_TESTS_DATABASE_FIXTURE_HPP

#include "test-common.hpp"
#include "identity-management-fixture.hpp"
#include <boost/filesystem.hpp>

namespace ndn {
namespace ndncert {
namespace tests {

class DatabaseFixture : public IdentityManagementTimeFixture
{
public:
  DatabaseFixture()
  {
    dbDir = boost::filesystem::path(getenv("HOME")) / ".ndn";
  }

  ~DatabaseFixture()
  {
    boost::filesystem::remove_all(dbDir);
  }

public:
  boost::filesystem::path dbDir;
};

} // namespace tests
} // namespace ndncert
} // namespace ndn

#endif // NDNCERT_TESTS_DATABASE_FIXTURE_HPP
