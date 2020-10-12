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
#include <ndn-cxx/security/validation-policy.hpp>
#include <ndn-cxx/util/sqlite3-statement.hpp>

namespace ndn {
namespace ndncert {

using namespace ndn::util;
const std::string CaSqlite::STORAGE_TYPE = "ca-storage-sqlite3";

NDNCERT_REGISTER_CA_STORAGE(CaSqlite);

std::string
convertJson2String(const JsonSection& json)
{
  std::stringstream ss;
  boost::property_tree::write_json(ss, json);
  return ss.str();
}

JsonSection
convertString2Json(const std::string& jsonContent)
{
  std::istringstream ss(jsonContent);
  JsonSection json;
  boost::property_tree::json_parser::read_json(ss, json);
  return json;
}

static const std::string INITIALIZATION = R"_DBTEXT_(
CREATE TABLE IF NOT EXISTS
  CaStates(
    id INTEGER PRIMARY KEY,
    request_id TEXT NOT NULL,
    ca_name BLOB NOT NULL,
    request_type INTEGER NOT NULL,
    status INTEGER NOT NULL,
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
  CaStateIdIndex ON CaStates(request_id);
)_DBTEXT_";

CaSqlite::CaSqlite(const Name& caName, const std::string& path)
    : CaStorage()
{
  // Determine the path of sqlite db
  boost::filesystem::path dbDir;
  if (!path.empty()) {
    dbDir = boost::filesystem::path(path);
  }
  else {
    std::string dbName = caName.toUri();
    std::replace(dbName.begin(), dbName.end(), '/', '_');
    dbName += ".db";
    if (getenv("HOME") != nullptr) {
      dbDir = boost::filesystem::path(getenv("HOME")) / ".ndncert";
    }
    else {
      dbDir = boost::filesystem::current_path() / ".ndncert";
    }
    boost::filesystem::create_directories(dbDir);
    dbDir /= dbName;
  }

  // open and initialize database
  int result = sqlite3_open_v2(dbDir.c_str(), &m_database,
                               SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE,
#ifdef NDN_CXX_DISABLE_SQLITE3_FS_LOCKING
                               "unix-dotfile"
#else
                               nullptr
#endif
  );
  if (result != SQLITE_OK)
    NDN_THROW(std::runtime_error("CaSqlite DB cannot be opened/created: " + dbDir.string()));

  // initialize database specific tables
  char* errorMessage = nullptr;
  result = sqlite3_exec(m_database, INITIALIZATION.data(),
                        nullptr, nullptr, &errorMessage);
  if (result != SQLITE_OK && errorMessage != nullptr) {
    sqlite3_free(errorMessage);
    NDN_THROW(std::runtime_error("CaSqlite DB cannot be initialized"));
  }
}

CaSqlite::~CaSqlite()
{
  sqlite3_close(m_database);
}

CaState
CaSqlite::getRequest(const std::string& requestId)
{
  Sqlite3Statement statement(m_database,
                             R"_SQLTEXT_(SELECT id, ca_name, status,
                             challenge_status, cert_request,
                             challenge_type, challenge_secrets,
                             challenge_tp, remaining_tries, remaining_time, request_type, encryption_key
                             FROM CaStates where request_id = ?)_SQLTEXT_");
  statement.bind(1, requestId, SQLITE_TRANSIENT);

  if (statement.step() == SQLITE_ROW) {
    Name caName(statement.getBlock(1));
    auto status = static_cast<Status>(statement.getInt(2));
    auto challengeStatus = statement.getString(3);
    security::Certificate cert(statement.getBlock(4));
    auto challengeType = statement.getString(5);
    auto challengeSecrets = statement.getString(6);
    auto challengeTp = statement.getString(7);
    auto remainingTries = statement.getInt(8);
    auto remainingTime = statement.getInt(9);
    auto requestType = static_cast<RequestType>(statement.getInt(10));
    auto encryptionKey = statement.getBlock(11);
    if (challengeType != "") {
      return CaState(caName, requestId, requestType, status, cert,
                     challengeType, challengeStatus, time::fromIsoString(challengeTp),
                     remainingTries, time::seconds(remainingTime),
                     convertString2Json(challengeSecrets), encryptionKey);
    }
    else {
      return CaState(caName, requestId, requestType, status, cert, encryptionKey);
    }
  }
  else {
    NDN_THROW(std::runtime_error("Request " + requestId + " cannot be fetched from database"));
  }
}

void
CaSqlite::addRequest(const CaState& request)
{
  Sqlite3Statement statement(
      m_database,
      R"_SQLTEXT_(INSERT OR ABORT INTO CaStates (request_id, ca_name, status, request_type,
                  cert_request, challenge_type, challenge_status, challenge_secrets,
                  challenge_tp, remaining_tries, remaining_time, encryption_key)
                  values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?))_SQLTEXT_");
  statement.bind(1, request.m_requestId, SQLITE_TRANSIENT);
  statement.bind(2, request.m_caPrefix.wireEncode(), SQLITE_TRANSIENT);
  statement.bind(3, static_cast<int>(request.m_status));
  statement.bind(4, static_cast<int>(request.m_requestType));
  statement.bind(5, request.m_cert.wireEncode(), SQLITE_TRANSIENT);
  statement.bind(12, request.m_encryptionKey, SQLITE_TRANSIENT);
  if (request.m_challengeState) {
    statement.bind(6, request.m_challengeType, SQLITE_TRANSIENT);
    statement.bind(7, request.m_challengeState->m_challengeStatus, SQLITE_TRANSIENT);
    statement.bind(8, convertJson2String(request.m_challengeState->m_secrets),
                   SQLITE_TRANSIENT);
    statement.bind(9, time::toIsoString(request.m_challengeState->m_timestamp), SQLITE_TRANSIENT);
    statement.bind(10, request.m_challengeState->m_remainingTries);
    statement.bind(11, request.m_challengeState->m_remainingTime.count());
  }
  if (statement.step() != SQLITE_DONE) {
    NDN_THROW(std::runtime_error("Request " + request.m_requestId + " cannot be added to database"));
  }
}

void
CaSqlite::updateRequest(const CaState& request)
{
  Sqlite3Statement statement(m_database,
                             R"_SQLTEXT_(UPDATE CaStates
                             SET status = ?, challenge_type = ?, challenge_status = ?, challenge_secrets = ?,
                             challenge_tp = ?, remaining_tries = ?, remaining_time = ?
                             WHERE request_id = ?)_SQLTEXT_");
  statement.bind(1, static_cast<int>(request.m_status));
  statement.bind(2, request.m_challengeType, SQLITE_TRANSIENT);
  if (request.m_challengeState) {
    statement.bind(3, request.m_challengeState->m_challengeStatus, SQLITE_TRANSIENT);
    statement.bind(4, convertJson2String(request.m_challengeState->m_secrets), SQLITE_TRANSIENT);
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

std::list<CaState>
CaSqlite::listAllRequests()
{
  std::list<CaState> result;
  Sqlite3Statement statement(m_database, R"_SQLTEXT_(SELECT id, request_id, ca_name, status,
                             challenge_status, cert_request, challenge_type, challenge_secrets,
                             challenge_tp, remaining_tries, remaining_time, request_type, encryption_key
                             FROM CaStates)_SQLTEXT_");
  while (statement.step() == SQLITE_ROW) {
    auto requestId = statement.getString(1);
    Name caName(statement.getBlock(2));
    auto status = static_cast<Status>(statement.getInt(3));
    auto challengeStatus = statement.getString(4);
    security::Certificate cert(statement.getBlock(5));
    auto challengeType = statement.getString(6);
    auto challengeSecrets = statement.getString(7);
    auto challengeTp = statement.getString(8);
    auto remainingTries = statement.getInt(9);
    auto remainingTime = statement.getInt(10);
    auto requestType = static_cast<RequestType>(statement.getInt(11));
    auto encryptionKey = statement.getBlock(12);
    if (challengeType != "") {
      result.push_back(CaState(caName, requestId, requestType, status, cert,
                               challengeType, challengeStatus, time::fromIsoString(challengeTp),
                               remainingTries, time::seconds(remainingTime),
                               convertString2Json(challengeSecrets), encryptionKey));
    }
    else {
      result.push_back(CaState(caName, requestId, requestType, status, cert, encryptionKey));
    }
  }
  return result;
}

std::list<CaState>
CaSqlite::listAllRequests(const Name& caName)
{
  std::list<CaState> result;
  Sqlite3Statement statement(m_database,
                             R"_SQLTEXT_(SELECT id, request_id, ca_name, status,
                             challenge_status, cert_request, challenge_type, challenge_secrets,
                             challenge_tp, remaining_tries, remaining_time, request_type, encryption_key
                             FROM CaStates WHERE ca_name = ?)_SQLTEXT_");
  statement.bind(1, caName.wireEncode(), SQLITE_TRANSIENT);

  while (statement.step() == SQLITE_ROW) {
    auto requestId = statement.getString(1);
    Name caName(statement.getBlock(2));
    auto status = static_cast<Status>(statement.getInt(3));
    auto challengeStatus = statement.getString(4);
    security::Certificate cert(statement.getBlock(5));
    auto challengeType = statement.getString(6);
    auto challengeSecrets = statement.getString(7);
    auto challengeTp = statement.getString(8);
    auto remainingTries = statement.getInt(9);
    auto remainingTime = statement.getInt(10);
    auto requestType = static_cast<RequestType>(statement.getInt(11));
    auto encryptionKey = statement.getBlock(12);
    if (challengeType != "") {
      result.push_back(CaState(caName, requestId, requestType, status, cert,
                               challengeType, challengeStatus, time::fromIsoString(challengeTp),
                               remainingTries, time::seconds(remainingTime),
                               convertString2Json(challengeSecrets), encryptionKey));
    }
    else {
      result.push_back(CaState(caName, requestId, requestType, status, cert, encryptionKey));
    }
  }
  return result;
}

void
CaSqlite::deleteRequest(const std::string& requestId)
{
  Sqlite3Statement statement(m_database,
                             R"_SQLTEXT_(DELETE FROM CaStates WHERE request_id = ?)_SQLTEXT_");
  statement.bind(1, requestId, SQLITE_TRANSIENT);
  statement.step();
}

} // namespace ndncert
} // namespace ndn
