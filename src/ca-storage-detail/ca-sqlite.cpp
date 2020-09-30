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

#include "ca-sqlite.hpp"

#include <sqlite3.h>

#include <boost/filesystem.hpp>
#include <ndn-cxx/security/v2/validation-policy.hpp>
#include <ndn-cxx/util/sqlite3-statement.hpp>

namespace ndn {
namespace ndncert {

const std::string CaSqlite::STORAGE_TYPE = "ca-storage-sqlite3";

NDNCERT_REGISTER_CA_STORAGE(CaSqlite);

using namespace ndn::util;

static const std::string INITIALIZATION = R"_DBTEXT_(
CREATE TABLE IF NOT EXISTS
  CertRequests(
    id INTEGER PRIMARY KEY,
    request_id TEXT NOT NULL,
    ca_name BLOB NOT NULL,
    request_type INTEGER NOT NULL,
    status INTEGER NOT NULL,
    cert_key_name BLOB NOT NULL,
    cert_request BLOB NOT NULL,
    challenge_type TEXT,
    challenge_status TEXT,
    challenge_tp TEXT,
    remaining_tries INTEGER,
    remaining_time INTEGER,
    challenge_secrets TEXT,
    encryption_key BLOB NOT NULL
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
  result = sqlite3_exec(m_database, INITIALIZATION.data(),
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

RequestState
CaSqlite::getRequest(const std::string& requestId)
{
  Sqlite3Statement statement(m_database,
                             R"_SQLTEXT_(SELECT id, ca_name, status,
                             challenge_status, cert_request,
                             challenge_type, challenge_secrets,
                             challenge_tp, remaining_tries, remaining_time, request_type, encryption_key
                             FROM CertRequests where request_id = ?)_SQLTEXT_");
  statement.bind(1, requestId, SQLITE_TRANSIENT);

  if (statement.step() == SQLITE_ROW) {
    Name caName(statement.getBlock(1));
    auto status = static_cast<Status>(statement.getInt(2));
    auto challengeStatus = statement.getString(3);
    security::v2::Certificate cert(statement.getBlock(4));
    auto challengeType = statement.getString(5);
    auto challengeSecrets = statement.getString(6);
    auto challengeTp = statement.getString(7);
    auto remainingTries = statement.getInt(8);
    auto remainingTime = statement.getInt(9);
    auto requestType = static_cast<RequestType>(statement.getInt(10));
    auto encryptionKey = statement.getBlock(11);
    if (challengeType != "") {
      return RequestState(caName, requestId, requestType, status, cert,
                                challengeType, challengeStatus, time::fromIsoString(challengeTp),
                                remainingTries, time::seconds(remainingTime),
                                convertString2Json(challengeSecrets), encryptionKey);
    }
    else {
      return RequestState(caName, requestId, requestType, status, cert, encryptionKey);
    }
  }
  else {
    BOOST_THROW_EXCEPTION(Error("Request " + requestId + " cannot be fetched from database"));
  }
}

void
CaSqlite::addRequest(const RequestState& request)
{
  // check whether request is there already
  auto keyNameTlv = request.m_cert.getKeyName().wireEncode();
  Sqlite3Statement statement1(m_database,
                              R"_SQLTEXT_(SELECT * FROM CertRequests where cert_key_name = ?)_SQLTEXT_");
  statement1.bind(1, keyNameTlv, SQLITE_TRANSIENT);
  if (statement1.step() == SQLITE_ROW) {
    BOOST_THROW_EXCEPTION(Error("Request for " + request.m_cert.getKeyName().toUri() + " already exists"));
  }

  // check whether certificate is already issued
  Sqlite3Statement statement2(m_database,
                              R"_SQLTEXT_(SELECT * FROM IssuedCerts where cert_key_name = ?)_SQLTEXT_");
  statement2.bind(1, keyNameTlv, SQLITE_TRANSIENT);
  if (statement2.step() == SQLITE_ROW) {
    BOOST_THROW_EXCEPTION(Error("Cert for " + request.m_cert.getKeyName().toUri() + " already exists"));
  }

  Sqlite3Statement statement(
      m_database,
      R"_SQLTEXT_(INSERT INTO CertRequests (request_id, ca_name, status, request_type,
                  cert_key_name, cert_request, challenge_type, challenge_status, challenge_secrets,
                  challenge_tp, remaining_tries, remaining_time, encryption_key)
                  values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?))_SQLTEXT_");
  statement.bind(1, request.m_requestId, SQLITE_TRANSIENT);
  statement.bind(2, request.m_caPrefix.wireEncode(), SQLITE_TRANSIENT);
  statement.bind(3, static_cast<int>(request.m_status));
  statement.bind(4, static_cast<int>(request.m_requestType));
  statement.bind(5, keyNameTlv, SQLITE_TRANSIENT);
  statement.bind(6, request.m_cert.wireEncode(), SQLITE_TRANSIENT);
  statement.bind(13, request.m_encryptionKey, SQLITE_TRANSIENT);
  if (request.m_challengeState) {
    statement.bind(7, request.m_challengeType, SQLITE_TRANSIENT);
    statement.bind(8, request.m_challengeState->m_challengeStatus, SQLITE_TRANSIENT);
    statement.bind(9, convertJson2String(request.m_challengeState->m_secrets),
                   SQLITE_TRANSIENT);
    statement.bind(10, time::toIsoString(request.m_challengeState->m_timestamp), SQLITE_TRANSIENT);
    statement.bind(11, request.m_challengeState->m_remainingTries);
    statement.bind(12, request.m_challengeState->m_remainingTime.count());
  }
  if (statement.step() != SQLITE_DONE) {
    BOOST_THROW_EXCEPTION(Error("Request " + request.m_requestId + " cannot be added to database"));
  }
}

void
CaSqlite::updateRequest(const RequestState& request)
{
  Sqlite3Statement statement(m_database,
                             R"_SQLTEXT_(UPDATE CertRequests
                             SET status = ?, challenge_type = ?, challenge_status = ?, challenge_secrets = ?,
                             challenge_tp = ?, remaining_tries = ?, remaining_time = ?
                             WHERE request_id = ?)_SQLTEXT_");
  statement.bind(1, static_cast<int>(request.m_status));
  statement.bind(2, request.m_challengeType, SQLITE_TRANSIENT);
  if (request.m_challengeState) {
    statement.bind(3, request.m_challengeState->m_challengeStatus, SQLITE_TRANSIENT);
    statement.bind(4, convertJson2String(request.m_challengeState->m_secrets),
                   SQLITE_TRANSIENT);
    statement.bind(5, time::toIsoString(request.m_challengeState->m_timestamp), SQLITE_TRANSIENT);
    statement.bind(6, request.m_challengeState->m_remainingTries);
    statement.bind(7, request.m_challengeState->m_remainingTime.count());
  }
  else {
    statement.bind(3, "", SQLITE_TRANSIENT);
    statement.bind(4, "", SQLITE_TRANSIENT);
    statement.bind(5, "", SQLITE_TRANSIENT);
    statement.bind(6, 0);
    statement.bind(7, 0);
  }
  statement.bind(8, request.m_requestId, SQLITE_TRANSIENT);

  if (statement.step() != SQLITE_DONE) {
    addRequest(request);
  }
}

std::list<RequestState>
CaSqlite::listAllRequests()
{
  std::list<RequestState> result;
  Sqlite3Statement statement(m_database, R"_SQLTEXT_(SELECT id, request_id, ca_name, status,
                             challenge_status, cert_key_name, cert_request, challenge_type, challenge_secrets,
                             challenge_tp, remaining_tries, remaining_time, request_type, encryption_key
                             FROM CertRequests)_SQLTEXT_");
  while (statement.step() == SQLITE_ROW) {
    auto requestId = statement.getString(1);
    Name caName(statement.getBlock(2));
    auto status = static_cast<Status>(statement.getInt(3));
    auto challengeStatus = statement.getString(4);
    security::v2::Certificate cert(statement.getBlock(6));
    auto challengeType = statement.getString(7);
    auto challengeSecrets = statement.getString(8);
    auto challengeTp = statement.getString(9);
    auto remainingTries = statement.getInt(10);
    auto remainingTime = statement.getInt(11);
    auto requestType = static_cast<RequestType>(statement.getInt(12));
    auto encryptionKey = statement.getBlock(13);
    if (challengeType != "") {
      result.push_back(RequestState(caName, requestId, requestType, status, cert,
                                          challengeType, challengeStatus, time::fromIsoString(challengeTp),
                                          remainingTries, time::seconds(remainingTime),
                                          convertString2Json(challengeSecrets), encryptionKey));
    }
    else {
      result.push_back(RequestState(caName, requestId, requestType, status, cert, encryptionKey));
    }
  }
  return result;
}

std::list<RequestState>
CaSqlite::listAllRequests(const Name& caName)
{
  std::list<RequestState> result;
  Sqlite3Statement statement(m_database,
                             R"_SQLTEXT_(SELECT id, request_id, ca_name, status,
                             challenge_status, cert_key_name, cert_request, challenge_type, challenge_secrets,
                             challenge_tp, remaining_tries, remaining_time, request_type, encryption_key
                             FROM CertRequests WHERE ca_name = ?)_SQLTEXT_");
  statement.bind(1, caName.wireEncode(), SQLITE_TRANSIENT);

  while (statement.step() == SQLITE_ROW) {
    auto requestId = statement.getString(1);
    Name caName(statement.getBlock(2));
    auto status = static_cast<Status>(statement.getInt(3));
    auto challengeStatus = statement.getString(4);
    security::v2::Certificate cert(statement.getBlock(6));
    auto challengeType = statement.getString(7);
    auto challengeSecrets = statement.getString(8);
    auto challengeTp = statement.getString(9);
    auto remainingTries = statement.getInt(10);
    auto remainingTime = statement.getInt(11);
    auto requestType = static_cast<RequestType>(statement.getInt(12));
    auto encryptionKey = statement.getBlock(13);
    if (challengeType != "") {
      result.push_back(RequestState(caName, requestId, requestType, status, cert,
                                          challengeType, challengeStatus, time::fromIsoString(challengeTp),
                                          remainingTries, time::seconds(remainingTime),
                                          convertString2Json(challengeSecrets), encryptionKey));
    }
    else {
      result.push_back(RequestState(caName, requestId, requestType, status, cert, encryptionKey));
    }
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
    return security::v2::Certificate(statement.getBlock(0));
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
    result.emplace_back(statement.getBlock(3));
  }
  return result;
}

std::list<security::v2::Certificate>
CaSqlite::listAllIssuedCertificates(const Name& caName)
{
  auto allCerts = listAllIssuedCertificates();
  std::list<security::v2::Certificate> result;
  for (const auto& entry : allCerts) {
    const auto& klName = entry.getSignature().getKeyLocator().getName();
    if (security::v2::extractIdentityFromKeyName(klName) == caName) {
      result.push_back(entry);
    }
  }
  return result;
}

}  // namespace ndncert
}  // namespace ndn
