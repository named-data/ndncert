/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/**
 * Copyright (c) 2014-2017, Regents of the University of California,
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

#include "identity-management-fixture.hpp"

#include <ndn-cxx/util/io.hpp>
#include <boost/filesystem.hpp>

namespace ndn {
namespace ndncert {
namespace tests {

IdentityManagementFixture::IdentityManagementFixture()
  : m_keyChain("sqlite3", "file")
{
  m_keyChain.getDefaultCertificate(); // side effect: create a default cert if it doesn't exist
}

IdentityManagementFixture::~IdentityManagementFixture()
{
  for (const auto& id : m_identities) {
    m_keyChain.deleteIdentity(id);
  }

  boost::system::error_code ec;
  for (const auto& certFile : m_certFiles) {
    boost::filesystem::remove(certFile, ec); // ignore error
  }
}

bool
IdentityManagementFixture::addIdentity(const Name& identity, const ndn::KeyParams& params)
{
  try {
    m_keyChain.createIdentity(identity, params);
    m_identities.push_back(identity);
    return true;
  }
  catch (std::runtime_error&) {
    return false;
  }
}

bool
IdentityManagementFixture::saveIdentityCertificate(const Name& identity,
                                                   const std::string& filename, bool wantAdd)
{
  shared_ptr<ndn::IdentityCertificate> cert;
  try {
    cert = m_keyChain.getCertificate(m_keyChain.getDefaultCertificateNameForIdentity(identity));
  }
  catch (const ndn::SecPublicInfo::Error&) {
    if (wantAdd && this->addIdentity(identity)) {
      return this->saveIdentityCertificate(identity, filename, false);
    }
    return false;
  }

  m_certFiles.push_back(filename);
  try {
    ndn::io::save(*cert, filename);
    return true;
  }
  catch (const ndn::io::Error&) {
    return false;
  }
}

} // namespace tests
} // namespace ndncert
} // namespace ndn
