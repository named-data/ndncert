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
#include "certificate-request.hpp"
#include <boost/lexical_cast.hpp>
#include <ndn-cxx/util/io.hpp>

namespace ndn {
namespace ndncert {
namespace tests {

BOOST_FIXTURE_TEST_SUITE(TestCertificateRequest, IdentityManagementV2Fixture)

BOOST_AUTO_TEST_CASE(Constructor)
{
  auto identity = addIdentity(Name("/ndn/site1"));
  auto key = identity.getDefaultKey();
  auto cert = key.getDefaultCertificate();

  CertificateRequest request1(Name("/ndn/site1"), "123", cert);
  BOOST_CHECK_EQUAL(request1.getCaName().toUri(), "/ndn/site1");
  BOOST_CHECK_EQUAL(request1.getRequestId(), "123");
  BOOST_CHECK_EQUAL(request1.getStatus(), CertificateRequest::Pending);
  BOOST_CHECK_EQUAL(request1.getChallengeType(), "");
  BOOST_CHECK_EQUAL(request1.getChallengeStatus(), "");
  BOOST_CHECK_EQUAL(request1.getChallengeDefinedField(), "");
  BOOST_CHECK_EQUAL(request1.getChallengeInstruction(), "");
  BOOST_CHECK_EQUAL(request1.getCert(), cert);

  CertificateRequest request2(Name("/ndn/site1"), "123", CertificateRequest::Verifying,
                              "Email", "NEED_CODE", "123456", cert);
  BOOST_CHECK_EQUAL(request2.getCaName().toUri(), "/ndn/site1");
  BOOST_CHECK_EQUAL(request2.getRequestId(), "123");
  BOOST_CHECK_EQUAL(request2.getStatus(), CertificateRequest::Verifying);
  BOOST_CHECK_EQUAL(request2.getChallengeType(), "Email");
  BOOST_CHECK_EQUAL(request2.getChallengeStatus(), "NEED_CODE");
  BOOST_CHECK_EQUAL(request2.getChallengeDefinedField(), "123456");
  BOOST_CHECK_EQUAL(request2.getChallengeInstruction(), "");
  BOOST_CHECK_EQUAL(request2.getCert(), cert);
}

BOOST_AUTO_TEST_CASE(GetStatusOutput)
{
  CertificateRequest::ApplicationStatus status = CertificateRequest::Success;
  BOOST_CHECK_EQUAL(boost::lexical_cast<std::string>(status), "success");
}

BOOST_AUTO_TEST_CASE(GetterSetter)
{
  auto identity = addIdentity(Name("/ndn/site1"));
  auto key = identity.getDefaultKey();
  auto cert = key.getDefaultCertificate();

  CertificateRequest request(Name("/ndn/site1"), "123", cert);
  request.setStatus(CertificateRequest::Verifying);
  request.setChallengeType("Email");
  request.setChallengeDefinedField("456");
  request.setChallengeStatus("NEED_EMAIL");
  request.setChallengeInstruction("Please provide your email address");

  BOOST_CHECK_EQUAL(request.getStatus(), CertificateRequest::Verifying);
  BOOST_CHECK_EQUAL(request.getChallengeType(), "Email");
  BOOST_CHECK_EQUAL(request.getChallengeDefinedField(), "456");
  BOOST_CHECK_EQUAL(request.getChallengeStatus(), "NEED_EMAIL");
  BOOST_CHECK_EQUAL(request.getChallengeInstruction(), "Please provide your email address");
}

BOOST_AUTO_TEST_CASE(GetCertificateRequestOutput)
{
  const std::string certString = R"_CERT_(
Bv0BuwczCANuZG4IBXNpdGUxCANLRVkIEWtzay0xNDE2NDI1Mzc3MDk0CAQwMTIz
CAf9AAABScmLFAkYAQIZBAA27oAVoDCBnTANBgkqhkiG9w0BAQEFAAOBiwAwgYcC
gYEAngY+R4WyNDeqhUesAySDtZyoBTokHuuJAbvpm7LDIqxo4/BsAs5opsTQpwaQ
nKobCB2LQ5ozZ0RtIaMbiJqXXlnEFQvZLL1RB2GCrcG417+bz30kwmPzlxfr/mIl
ultNisJ6vUOKj7jy8cVqMNNQjMia3+/tNed6Yup2fLsIJscCAREWVRsBARwmByQI
A25kbggFc2l0ZTEIA0tFWQgRa3NrLTI1MTY0MjUzNzcwOTT9AP0m/QD+DzIwMTUw
ODE0VDIyMzczOf0A/w8yMDE1MDgxOFQyMjM3MzgXgP//////////////////////
////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////
////////////////////)_CERT_";

  const std::string expectedString = R"_REQUEST_(Request CA name:
  /ndn/site1
Request ID:
  123
Request Status:
  pending
Certificate:
  Certificate name:
    /ndn/site1/KEY/ksk-1416425377094/0123/%FD%00%00%01I%C9%8B
  Validity:
    NotBefore: 20150814T223739
    NotAfter: 20150818T223738
  Public key bits:
    MIGdMA0GCSqGSIb3DQEBAQUAA4GLADCBhwKBgQCeBj5HhbI0N6qFR6wDJIO1nKgF
    OiQe64kBu+mbssMirGjj8GwCzmimxNCnBpCcqhsIHYtDmjNnRG0hoxuImpdeWcQV
    C9ksvVEHYYKtwbjXv5vPfSTCY/OXF+v+YiW6W02Kwnq9Q4qPuPLxxWow01CMyJrf
    7+0153pi6nZ8uwgmxwIBEQ==
  Signature Information:
    Signature Type: SignatureSha256WithRsa
    Key Locator: Name=/ndn/site1/KEY/ksk-2516425377094
)_REQUEST_";

  std::stringstream ss;
  ss << certString;
  auto cert = io::load<security::v2::Certificate>(ss);
  CertificateRequest request(Name("/ndn/site1"), "123", *cert);

  BOOST_CHECK_EQUAL(boost::lexical_cast<std::string>(request), expectedString);
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace tests
} // namespace ndncert
} // namespace ndn
