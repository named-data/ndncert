/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/**
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

#include "ca-module.hpp"
#include "ca-detail/ca-sqlite.hpp"
#include <iostream>
#include <boost/program_options/options_description.hpp>
#include <boost/program_options/variables_map.hpp>
#include <boost/program_options/parsers.hpp>

namespace ndn {
namespace ndncert {

std::string
convertJson2String(const JsonSection& json)
{
  std::stringstream ss;
  boost::property_tree::write_json(ss, json);
  return ss.str();
}

int
main(int argc, char* argv[])
{
  namespace po = boost::program_options;
  std::string caNameString = "";
  po::options_description description("General Usage\n  ndncert-ca [-h] [-f] configFilePath-file\n");
  description.add_options()
    ("help,h", "produce help message")
    ("CAName,c", po::value<std::string>(&caNameString), "ca name");
  po::positional_options_description p;
  po::variables_map vm;
  try {
    po::store(po::command_line_parser(argc, argv).options(description).positional(p).run(), vm);
    po::notify(vm);
  }
  catch (const std::exception& e) {
    std::cerr << "ERROR: " << e.what() << std::endl;
    return 1;
  }
  if (vm.count("help") != 0) {
    std::cerr << description << std::endl;
    return 0;
  }

  CaSqlite storage;
  std::list<CertificateRequest> requestList;
  std::list<security::v2::Certificate> certList;
  if (caNameString != "") {
    requestList = storage.listAllRequests(Name(caNameString));
    certList = storage.listAllIssuedCertificates(Name(caNameString));
  }
  else {
    requestList = storage.listAllRequests();
    certList = storage.listAllIssuedCertificates();
  }

  std::cerr << "The pending requests :" << std::endl;

  for (const auto& entry : requestList) {
    std::cerr << "Request ID: " << entry.m_requestId << "\t"
              << "Request Type" << entry.m_requestType << "\t"
              << "Current Status: " << entry.m_status << std::endl
              << "Applying CA: " << entry.m_caPrefix << std::endl
              << "Applying for key: " << entry.m_cert.getName() << std::endl
              << "Challenge remaining tries: " << entry.m_remainingTries << std::endl
              << "Challenge Secret: " << convertJson2String(entry.m_challengeSecrets) << std::endl;
  }

  std::cerr << "\n\n" << "The issued certs :" << std::endl;

  for (const auto& entry : certList) {
    std::cerr << entry.getName().toUri() << std::endl;
  }

  return 0;
}

} // namespace ndncert
} // namespace ndn

int
main(int argc, char* argv[])
{
  return ndn::ndncert::main(argc, argv);
}
