/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2013-2022 Regents of the University of California.
 *
 * This file is part of ndn-cxx library (NDN C++ library with eXperimental eXtensions).
 *
 * ndn-cxx library is free software: you can redistribute it and/or modify it under the
 * terms of the GNU Lesser General Public License as published by the Free Software
 * Foundation, either version 3 of the License, or (at your option) any later version.
 *
 * ndn-cxx library is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
 * PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more details.
 *
 * You should have received copies of the GNU General Public License and GNU Lesser
 * General Public License along with ndn-cxx, e.g., in COPYING.md file.  If not, see
 * <http://www.gnu.org/licenses/>.
 *
 * See AUTHORS.md for complete list of ndn-cxx authors and contributors.
 */

#include "identity-management-fixture.hpp"

#include <ndn-cxx/security/additional-description.hpp>
#include <ndn-cxx/util/io.hpp>

#include <boost/filesystem.hpp>

namespace ndncert::tests {

using namespace ndn::security;

IdentityManagementBaseFixture::~IdentityManagementBaseFixture()
{
  boost::system::error_code ec;
  for (const auto& certFile : m_certFiles) {
    boost::filesystem::remove(certFile, ec); // ignore error
  }
}

bool
IdentityManagementBaseFixture::saveCertToFile(const Data& obj, const std::string& filename)
{
  m_certFiles.insert(filename);
  try {
    ndn::io::save(obj, filename);
    return true;
  }
  catch (const ndn::io::Error&) {
    return false;
  }
}

IdentityManagementFixture::IdentityManagementFixture()
  : m_keyChain("pib-memory:", "tpm-memory:")
{
}

Identity
IdentityManagementFixture::addIdentity(const Name& identityName, const ndn::KeyParams& params)
{
  auto identity = m_keyChain.createIdentity(identityName, params);
  m_identities.insert(identityName);
  return identity;
}

bool
IdentityManagementFixture::saveCertificate(const Identity& identity, const std::string& filename)
{
  try {
    auto cert = identity.getDefaultKey().getDefaultCertificate();
    return saveCertToFile(cert, filename);
  }
  catch (const Pib::Error&) {
    return false;
  }
}

Identity
IdentityManagementFixture::addSubCertificate(const Name& subIdentityName,
                                             const Identity& issuer, const ndn::KeyParams& params)
{
  auto subIdentity = addIdentity(subIdentityName, params);

  Certificate request = subIdentity.getDefaultKey().getDefaultCertificate();
  request.setName(request.getKeyName().append("parent").appendVersion());

  SignatureInfo info;
  auto now = time::system_clock::now();
  info.setValidityPeriod(ValidityPeriod(now, now + 7300_days));

  AdditionalDescription description;
  description.set("type", "sub-certificate");
  info.addCustomTlv(description.wireEncode());

  m_keyChain.sign(request, signingByIdentity(issuer).setSignatureInfo(info));
  m_keyChain.setDefaultCertificate(subIdentity.getDefaultKey(), request);

  return subIdentity;
}

Certificate
IdentityManagementFixture::addCertificate(const Key& key, const std::string& issuer)
{
  Name certificateName = key.getName();
  certificateName
    .append(issuer)
    .appendVersion();
  Certificate certificate;
  certificate.setName(certificateName);

  // set metainfo
  certificate.setContentType(ndn::tlv::ContentType_Key);
  certificate.setFreshnessPeriod(1_h);

  // set content
  certificate.setContent(key.getPublicKey());

  // set signature-info
  SignatureInfo info;
  auto now = time::system_clock::now();
  info.setValidityPeriod(ValidityPeriod(now, now + 10_days));

  m_keyChain.sign(certificate, signingByKey(key).setSignatureInfo(info));
  return certificate;
}

} // namespace ndncert::tests
