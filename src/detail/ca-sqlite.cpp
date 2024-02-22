/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2017-2024, Regents of the University of California.
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

#include "detail/ca-sqlite.hpp"

#include <sqlite3.h>

#include <ndn-cxx/security/validation-policy.hpp>
#include <ndn-cxx/util/sqlite3-statement.hpp>

#include <boost/filesystem/operations.hpp>
#include <boost/filesystem/path.hpp>
#include <boost/property_tree/json_parser.hpp>

namespace ndncert::ca {

using ndn::util::Sqlite3Statement;

const std::string CaSqlite::STORAGE_TYPE = "ca-storage-sqlite3";
NDNCERT_REGISTER_CA_STORAGE(CaSqlite);

static std::string
convertJson2String(const JsonSection& json)
{
  std::stringstream ss;
  boost::property_tree::write_json(ss, json);
  return ss.str();
}

static JsonSection
convertString2Json(const std::string& jsonContent)
{
  std::istringstream ss(jsonContent);
  JsonSection json;
  boost::property_tree::json_parser::read_json(ss, json);
  return json;
}

const std::string INITIALIZATION = R"SQL(
CREATE TABLE IF NOT EXISTS
  RequestStates(
    id INTEGER PRIMARY KEY,
    request_id BLOB NOT NULL,
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
    encryption_key BLOB NOT NULL,
    encryption_iv BLOB,
    decryption_iv BLOB
  );
CREATE UNIQUE INDEX IF NOT EXISTS
  RequestStateIdIndex ON RequestStates(request_id);
)SQL";

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

RequestState
CaSqlite::getRequest(const RequestId& requestId)
{
  Sqlite3Statement statement(m_database,
                             R"_SQLTEXT_(SELECT id, ca_name, status,
                             challenge_status, cert_request,
                             challenge_type, challenge_secrets,
                             challenge_tp, remaining_tries, remaining_time,
                             request_type, encryption_key, encryption_iv, decryption_iv
                             FROM RequestStates where request_id = ?)_SQLTEXT_");
  statement.bind(1, requestId.data(), requestId.size(), SQLITE_TRANSIENT);

  if (statement.step() == SQLITE_ROW) {
    RequestState state;
    state.requestId = requestId;
    state.caPrefix = Name(statement.getBlock(1));
    state.status = static_cast<Status>(statement.getInt(2));
    state.cert = Certificate(statement.getBlock(4));
    state.challengeType = statement.getString(5);
    state.requestType = static_cast<RequestType>(statement.getInt(10));
    std::memcpy(state.encryptionKey.data(), statement.getBlob(11), statement.getSize(11));
    state.encryptionIv = std::vector<uint8_t>(statement.getBlob(12), statement.getBlob(12) + statement.getSize(12));
    state.decryptionIv = std::vector<uint8_t>(statement.getBlob(13), statement.getBlob(13) + statement.getSize(13));
    if (!state.challengeType.empty()) {
      ChallengeState challengeState(statement.getString(3), time::fromIsoString(statement.getString(7)),
                                    statement.getInt(8), time::seconds(statement.getInt(9)),
                                    convertString2Json(statement.getString(6)));
      state.challengeState = challengeState;
    }
    return state;
  }
  else {
    NDN_THROW(std::runtime_error("Request " + ndn::toHex(requestId) + " cannot be fetched from database"));
  }
}

void
CaSqlite::addRequest(const RequestState& request)
{
  Sqlite3Statement statement(
      m_database,
      R"_SQLTEXT_(INSERT OR ABORT INTO RequestStates (request_id, ca_name, status, request_type,
                  cert_request, challenge_type, challenge_status, challenge_secrets,
                  challenge_tp, remaining_tries, remaining_time, encryption_key, encryption_iv, decryption_iv)
                  values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?))_SQLTEXT_");
  statement.bind(1, request.requestId.data(), request.requestId.size(), SQLITE_TRANSIENT);
  statement.bind(2, request.caPrefix.wireEncode(), SQLITE_TRANSIENT);
  statement.bind(3, static_cast<int>(request.status));
  statement.bind(4, static_cast<int>(request.requestType));
  statement.bind(5, request.cert.wireEncode(), SQLITE_TRANSIENT);
  statement.bind(12, request.encryptionKey.data(), request.encryptionKey.size(), SQLITE_TRANSIENT);
  statement.bind(13, request.encryptionIv.data(), request.encryptionIv.size(), SQLITE_TRANSIENT);
  statement.bind(14, request.decryptionIv.data(), request.decryptionIv.size(), SQLITE_TRANSIENT);
  if (request.challengeState) {
    statement.bind(6, request.challengeType, SQLITE_TRANSIENT);
    statement.bind(7, request.challengeState->challengeStatus, SQLITE_TRANSIENT);
    statement.bind(8, convertJson2String(request.challengeState->secrets), SQLITE_TRANSIENT);
    statement.bind(9, time::toIsoString(request.challengeState->timestamp), SQLITE_TRANSIENT);
    statement.bind(10, request.challengeState->remainingTries);
    statement.bind(11, request.challengeState->remainingTime.count());
  }
  if (statement.step() != SQLITE_DONE) {
    NDN_THROW(std::runtime_error("Request " + ndn::toHex(request.requestId) +
                                 " cannot be added to the database"));
  }
}

void
CaSqlite::updateRequest(const RequestState& request)
{
  Sqlite3Statement statement(m_database,
                             R"_SQLTEXT_(UPDATE RequestStates
                             SET status = ?, challenge_type = ?, challenge_status = ?, challenge_secrets = ?,
                             challenge_tp = ?, remaining_tries = ?, remaining_time = ?, encryption_iv = ?, decryption_iv = ?
                             WHERE request_id = ?)_SQLTEXT_");
  statement.bind(1, static_cast<int>(request.status));
  statement.bind(2, request.challengeType, SQLITE_TRANSIENT);
  if (request.challengeState) {
    statement.bind(3, request.challengeState->challengeStatus, SQLITE_TRANSIENT);
    statement.bind(4, convertJson2String(request.challengeState->secrets), SQLITE_TRANSIENT);
    statement.bind(5, time::toIsoString(request.challengeState->timestamp), SQLITE_TRANSIENT);
    statement.bind(6, request.challengeState->remainingTries);
    statement.bind(7, request.challengeState->remainingTime.count());
  }
  else {
    statement.bind(3, "", SQLITE_TRANSIENT);
    statement.bind(4, "", SQLITE_TRANSIENT);
    statement.bind(5, "", SQLITE_TRANSIENT);
    statement.bind(6, 0);
    statement.bind(7, 0);
  }
  statement.bind(8, request.encryptionIv.data(), request.encryptionIv.size(), SQLITE_TRANSIENT);
  statement.bind(9, request.decryptionIv.data(), request.decryptionIv.size(), SQLITE_TRANSIENT);
  statement.bind(10, request.requestId.data(), request.requestId.size(), SQLITE_TRANSIENT);

  if (statement.step() != SQLITE_DONE) {
    addRequest(request);
  }
}

std::list<RequestState>
CaSqlite::listAllRequests()
{
  std::list<RequestState> result;
  Sqlite3Statement statement(m_database, R"_SQLTEXT_(SELECT id, request_id, ca_name, status,
                             challenge_status, cert_request, challenge_type, challenge_secrets,
                             challenge_tp, remaining_tries, remaining_time, request_type,
                             encryption_key, encryption_iv, decryption_iv
                             FROM RequestStates)_SQLTEXT_");
  while (statement.step() == SQLITE_ROW) {
    RequestState state;
    std::memcpy(state.requestId.data(), statement.getBlob(1), statement.getSize(1));
    state.caPrefix = Name(statement.getBlock(2));
    state.status = static_cast<Status>(statement.getInt(3));
    state.challengeType = statement.getString(6);
    state.cert = Certificate(statement.getBlock(5));
    state.requestType = static_cast<RequestType>(statement.getInt(11));
    std::memcpy(state.encryptionKey.data(), statement.getBlob(12), statement.getSize(12));
    state.encryptionIv = std::vector<uint8_t>(statement.getBlob(13), statement.getBlob(13) + statement.getSize(13));
    state.decryptionIv = std::vector<uint8_t>(statement.getBlob(14), statement.getBlob(14) + statement.getSize(14));
    if (state.challengeType != "") {
      ChallengeState challengeState(statement.getString(4), time::fromIsoString(statement.getString(8)),
                                    statement.getInt(9), time::seconds(statement.getInt(10)),
                                    convertString2Json(statement.getString(7)));
      state.challengeState = challengeState;
    }
    result.push_back(state);
  }
  return result;
}

std::list<RequestState>
CaSqlite::listAllRequests(const Name& caName)
{
  std::list<RequestState> result;
  Sqlite3Statement statement(m_database,
                             R"_SQLTEXT_(SELECT id, request_id, ca_name, status,
                             challenge_status, cert_request, challenge_type, challenge_secrets,
                             challenge_tp, remaining_tries, remaining_time, request_type,
                             encryption_key, encryption_iv, decryption_iv
                             FROM RequestStates WHERE ca_name = ?)_SQLTEXT_");
  statement.bind(1, caName.wireEncode(), SQLITE_TRANSIENT);

  while (statement.step() == SQLITE_ROW) {
    RequestState state;
    std::memcpy(state.requestId.data(), statement.getBlob(1), statement.getSize(1));
    state.caPrefix = Name(statement.getBlock(2));
    state.status = static_cast<Status>(statement.getInt(3));
    state.challengeType = statement.getString(6);
    state.cert = Certificate(statement.getBlock(5));
    state.requestType = static_cast<RequestType>(statement.getInt(11));
    std::memcpy(state.encryptionKey.data(), statement.getBlob(12), statement.getSize(12));
    state.encryptionIv = std::vector<uint8_t>(statement.getBlob(13), statement.getBlob(13) + statement.getSize(13));
    state.decryptionIv = std::vector<uint8_t>(statement.getBlob(14), statement.getBlob(14) + statement.getSize(14));
    if (!state.challengeType.empty()) {
      ChallengeState challengeState(statement.getString(4), time::fromIsoString(statement.getString(8)),
                                    statement.getInt(9), time::seconds(statement.getInt(10)),
                                    convertString2Json(statement.getString(7)));
      state.challengeState = challengeState;
    }
    result.push_back(state);
  }
  return result;
}

void
CaSqlite::deleteRequest(const RequestId& requestId)
{
  Sqlite3Statement statement(m_database,
                             R"_SQLTEXT_(DELETE FROM RequestStates WHERE request_id = ?)_SQLTEXT_");
  statement.bind(1, requestId.data(), requestId.size(), SQLITE_TRANSIENT);
  statement.step();
}

} // namespace ndncert::ca
