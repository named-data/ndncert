/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/**
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

#include "ca-sqlite.hpp"
#include <ndn-cxx/util/sqlite3-statement.hpp>

#include <sqlite3.h>
#include <boost/filesystem.hpp>

namespace ndn {
namespace ndncert {

const std::string
CaSqlite::STORAGE_TYPE = "ca-storage-sqlite3";

NDNCERT_REGISTER_CA_STORAGE(CaSqlite);

using namespace ndn::util;

static const std::string INITIALIZATION = R"_DBTEXT_(
CREATE TABLE IF NOT EXISTS
  CertRequests(
    id INTEGER PRIMARY KEY,
    request_id TEXT NOT NULL,
    ca_name BLOB NOT NULL,
    status INTEGER NOT NULL,
    challenge_status TEXT,
    cert_key_name BLOB NOT NULL,
    cert_request BLOB NOT NULL,
    challenge_type TEXT,
    challenge_secrets TEXT,
    challenge_tp TEXT,
    remaining_tries INTEGER,
    remaining_time INTEGER
  );
CREATE UNIQUE INDEX IF NOT EXISTS
  CertRequestIdIndex ON CertRequests(request_id);
CREATE UNIQUE INDEX IF NOT EXISTS
  CertRequestKeyNameIndex ON CertRequests(cert_key_name);

CREATE TABLE IF NOT EXISTS
  IssuedCerts(
    id INTEGER PRIMARY KEY,
    cert_id TEXT NOT NULL,
    cert_key_name BLOB NOT NULL,
    cert BLOB NOT NULL
  );
CREATE UNIQUE INDEX IF NOT EXISTS
  IssuedCertRequestIdIndex ON IssuedCerts(cert_id);
CREATE UNIQUE INDEX IF NOT EXISTS
  IssuedCertKeyNameIndex ON IssuedCerts(cert_key_name);
)_DBTEXT_";

CaSqlite::CaSqlite(const std::string& location)
  : CaStorage()
{
  // Determine the path of sqlite db
  boost::filesystem::path dbDir;
  if (!location.empty()) {
    dbDir = boost::filesystem::path(location);
  }
  else if (getenv("HOME") != nullptr) {
    dbDir = boost::filesystem::path(getenv("HOME")) / ".ndn";
  }
  else {
    dbDir = boost::filesystem::current_path() / ".ndn";
  }
  boost::filesystem::create_directories(dbDir);

  // open and initialize database
  int result = sqlite3_open_v2((dbDir / "ndncert-ca.db").c_str(), &m_database,
                               SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE,
#ifdef NDN_CXX_DISABLE_SQLITE3_FS_LOCKING
                               "unix-dotfile"
#else
                               nullptr
#endif
                               );
  if (result != SQLITE_OK)
    BOOST_THROW_EXCEPTION(Error("CaSqlite DB cannot be opened/created: " + dbDir.string()));

  // initialize database specific tables
  char* errorMessage = nullptr;
  result = sqlite3_exec(m_database, INITIALIZATION.c_str(),
                        nullptr, nullptr, &errorMessage);
  if (result != SQLITE_OK && errorMessage != nullptr) {
    sqlite3_free(errorMessage);
    BOOST_THROW_EXCEPTION(Error("CaSqlite DB cannot be initialized"));
  }
}

CaSqlite::~CaSqlite()
{
  sqlite3_close(m_database);
}

CertificateRequest
CaSqlite::getRequest(const std::string& requestId)
{
  Sqlite3Statement statement(m_database,
                             R"_SQLTEXT_(SELECT *
                             FROM CertRequests where request_id = ?)_SQLTEXT_");
  statement.bind(1, requestId, SQLITE_TRANSIENT);

  if (statement.step() == SQLITE_ROW) {
    Name caName(statement.getBlock(2));
    int status = statement.getInt(3);
    std::string challengeStatus = statement.getString(4);
    security::v2::Certificate cert(statement.getBlock(6));
    std::string challengeType = statement.getString(7);
    std::string challengeSecrets = statement.getString(8);
    std::string challengeTp = statement.getString(9);
    int remainingTries = statement.getInt(10);
    int remainingTime = statement.getInt(11);
    return CertificateRequest(caName, requestId, status, challengeStatus, challengeType,
                              challengeTp, remainingTime, remainingTries,
                              convertString2Json(challengeSecrets), cert);
  }
  else {
    BOOST_THROW_EXCEPTION(Error("Request " + requestId + " cannot be fetched from database"));
  }
}

void
CaSqlite::addRequest(const CertificateRequest& request)
{
  Sqlite3Statement statement1(m_database,
                              R"_SQLTEXT_(SELECT * FROM CertRequests where cert_key_name = ?)_SQLTEXT_");
  statement1.bind(1, request.m_cert.getKeyName().wireEncode(), SQLITE_TRANSIENT);
  if (statement1.step() == SQLITE_ROW) {
    BOOST_THROW_EXCEPTION(Error("Request for " + request.m_cert.getKeyName().toUri() + " already exists"));
    return;
  }

  Sqlite3Statement statement2(m_database,
                              R"_SQLTEXT_(SELECT * FROM IssuedCerts where cert_key_name = ?)_SQLTEXT_");
  statement2.bind(1, request.m_cert.getKeyName().wireEncode(), SQLITE_TRANSIENT);
  if (statement2.step() == SQLITE_ROW) {
    BOOST_THROW_EXCEPTION(Error("Cert for " + request.m_cert.getKeyName().toUri() + " already exists"));
    return;
  }

  Sqlite3Statement statement(m_database,
                             R"_SQLTEXT_(INSERT INTO CertRequests (request_id, ca_name, status,
                             challenge_status, cert_key_name, cert_request, challenge_type, challenge_secrets,
                             challenge_tp, remaining_tries, remaining_time)
                             values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?))_SQLTEXT_");
  statement.bind(1, request.m_requestId, SQLITE_TRANSIENT);
  statement.bind(2, request.m_caName.wireEncode(), SQLITE_TRANSIENT);
  statement.bind(3, request.m_status);
  statement.bind(4, request.m_challengeStatus, SQLITE_TRANSIENT);
  statement.bind(5, request.m_cert.getKeyName().wireEncode(), SQLITE_TRANSIENT);
  statement.bind(6, request.m_cert.wireEncode(), SQLITE_TRANSIENT);
  statement.bind(7, request.m_challengeType, SQLITE_TRANSIENT);
  statement.bind(8, convertJson2String(request.m_challengeSecrets), SQLITE_TRANSIENT);
  statement.bind(9, request.m_challengeTp, SQLITE_TRANSIENT);
  statement.bind(10, request.m_remainingTries);
  statement.bind(11, request.m_remainingTime);

  if (statement.step() != SQLITE_DONE) {
    BOOST_THROW_EXCEPTION(Error("Request " + request.m_requestId + " cannot be added to database"));
  }
}

void
CaSqlite::updateRequest(const CertificateRequest& request)
{
  Sqlite3Statement statement(m_database,
                             R"_SQLTEXT_(UPDATE CertRequests
                             SET status = ?, challenge_status = ?, challenge_type = ?, challenge_secrets = ?,
                             challenge_tp = ?, remaining_tries = ?, remaining_time = ?
                             WHERE request_id = ?)_SQLTEXT_");
  statement.bind(1, request.m_status);
  statement.bind(2, request.m_challengeStatus, SQLITE_TRANSIENT);
  statement.bind(3, request.m_challengeType, SQLITE_TRANSIENT);
  statement.bind(4, convertJson2String(request.m_challengeSecrets), SQLITE_TRANSIENT);
  statement.bind(5, request.m_challengeTp, SQLITE_TRANSIENT);
  statement.bind(6, request.m_remainingTries);
  statement.bind(7, request.m_remainingTime);
  statement.bind(8, request.m_requestId, SQLITE_TRANSIENT);

  if (statement.step() != SQLITE_DONE) {
    addRequest(request);
  }
}

std::list<CertificateRequest>
CaSqlite::listAllRequests()
{
  std::list<CertificateRequest> result;
  Sqlite3Statement statement(m_database, R"_SQLTEXT_(SELECT * FROM CertRequests)_SQLTEXT_");

  while(statement.step() == SQLITE_ROW) {
    std::string requestId = statement.getString(1);
    Name caName(statement.getBlock(2));
    int status = statement.getInt(3);
    std::string challengeStatus = statement.getString(4);
    security::v2::Certificate cert(statement.getBlock(6));
    std::string challengeType = statement.getString(7);
    std::string challengeSecrets = statement.getString(8);
    std::string challengeTp = statement.getString(9);
    int remainingTries = statement.getInt(10);
    int remainingTime = statement.getInt(11);
    CertificateRequest entry(caName, requestId, status, challengeStatus, challengeType,
                             challengeTp, remainingTime, remainingTries,
                             convertString2Json(challengeSecrets), cert);
    result.push_back(entry);
  }
  return result;
}

std::list<CertificateRequest>
CaSqlite::listAllRequests(const Name& caName)
{
  std::list<CertificateRequest> result;
  Sqlite3Statement statement(m_database,
                             R"_SQLTEXT_(SELECT * FROM CertRequests WHERE ca_name = ?)_SQLTEXT_");
  statement.bind(1, caName.wireEncode(), SQLITE_TRANSIENT);

  while(statement.step() == SQLITE_ROW) {
    std::string requestId = statement.getString(1);
    Name caName(statement.getBlock(2));
    int status = statement.getInt(3);
    std::string challengeStatus = statement.getString(4);
    security::v2::Certificate cert(statement.getBlock(6));
    std::string challengeType = statement.getString(7);
    std::string challengeSecrets = statement.getString(8);
    std::string challengeTp = statement.getString(9);
    int remainingTries = statement.getInt(10);
    int remainingTime = statement.getInt(11);
    CertificateRequest entry(caName, requestId, status, challengeStatus, challengeType,
                             challengeTp, remainingTime, remainingTries,
                             convertString2Json(challengeSecrets), cert);
    result.push_back(entry);
  }
  return result;
}

void
CaSqlite::deleteRequest(const std::string& requestId)
{
  Sqlite3Statement statement(m_database,
                             R"_SQLTEXT_(DELETE FROM CertRequests WHERE request_id = ?)_SQLTEXT_");
  statement.bind(1, requestId, SQLITE_TRANSIENT);
  statement.step();
}

security::v2::Certificate
CaSqlite::getCertificate(const std::string& certId)
{
  Sqlite3Statement statement(m_database,
                             R"_SQLTEXT_(SELECT cert FROM IssuedCerts where cert_id = ?)_SQLTEXT_");
  statement.bind(1, certId, SQLITE_TRANSIENT);

  if (statement.step() == SQLITE_ROW) {
    security::v2::Certificate cert(statement.getBlock(0));
    return cert;
  }
  else {
    BOOST_THROW_EXCEPTION(Error("Certificate with ID " + certId + " cannot be fetched from database"));
  }
}

void
CaSqlite::addCertificate(const std::string& certId, const security::v2::Certificate& cert)
{
  Sqlite3Statement statement(m_database,
                             R"_SQLTEXT_(INSERT INTO IssuedCerts (cert_id, cert_key_name, cert)
                             values (?, ?, ?))_SQLTEXT_");
  statement.bind(1, certId, SQLITE_TRANSIENT);
  statement.bind(2, cert.getKeyName().wireEncode(), SQLITE_TRANSIENT);
  statement.bind(3, cert.wireEncode(), SQLITE_TRANSIENT);

  if (statement.step() != SQLITE_DONE) {
    BOOST_THROW_EXCEPTION(Error("Certificate " + cert.getName().toUri() + " cannot be added to database"));
  }
}

void
CaSqlite::updateCertificate(const std::string& certId, const security::v2::Certificate& cert)
{
  Sqlite3Statement statement(m_database,
                             R"_SQLTEXT_(UPDATE IssuedCerts SET cert = ? WHERE cert_id = ?)_SQLTEXT_");
  statement.bind(1, cert.wireEncode(), SQLITE_TRANSIENT);
  statement.bind(2, certId, SQLITE_TRANSIENT);

  if (statement.step() != SQLITE_DONE) {
    addCertificate(certId, cert);
  }
}

void
CaSqlite::deleteCertificate(const std::string& certId)
{
  Sqlite3Statement statement(m_database,
                             R"_SQLTEXT_(DELETE FROM IssuedCerts WHERE cert_id = ?)_SQLTEXT_");
  statement.bind(1, certId, SQLITE_TRANSIENT);
  statement.step();
}

std::list<security::v2::Certificate>
CaSqlite::listAllIssuedCertificates()
{
  std::list<security::v2::Certificate> result;
  Sqlite3Statement statement(m_database, R"_SQLTEXT_(SELECT * FROM IssuedCerts)_SQLTEXT_");

  while (statement.step() == SQLITE_ROW) {
    security::v2::Certificate cert(statement.getBlock(3));
    result.push_back(cert);
  }
  return result;
}

std::list<security::v2::Certificate>
CaSqlite::listAllIssuedCertificates(const Name& caName)
{
  auto allCerts = listAllIssuedCertificates();
  std::list<security::v2::Certificate> result;
  for (const auto& entry : allCerts) {
    if (entry.getSignature().getKeyLocator().getName().getPrefix(-2) == caName) {
      result.push_back(entry);
    }
  }
  return result;
}

std::string
CaSqlite::convertJson2String(const JsonSection& json)
{
  std::stringstream ss;
  boost::property_tree::write_json(ss, json);
  return ss.str();
}

JsonSection
CaSqlite::convertString2Json(const std::string& jsonContent)
{
  std::istringstream ss(jsonContent);
  JsonSection json;
  boost::property_tree::json_parser::read_json(ss, json);
  return json;
}

} // namespace ndncert
} // namespace ndn
