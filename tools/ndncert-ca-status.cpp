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
#include "detail/ca-sqlite.hpp"
#include <iostream>
#include <boost/program_options/options_description.hpp>
#include <boost/program_options/variables_map.hpp>
#include <boost/program_options/parsers.hpp>

namespace ndn {
namespace ndncert {
namespace ca {

int
main(int argc, char* argv[])
{
  namespace po = boost::program_options;
  std::string caNameString = "";
  po::options_description description(
    "Usage: ndncert-ca-status [-h] caName\n"
    "\n"
    "Options");
  description.add_options()
    ("help,h", "produce help message")
    ("caName", po::value<std::string>(&caNameString), "CA Identity Name, e.g., /example");
  po::positional_options_description p;
  p.add("caName", 1);
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
  if (vm.count("caName") == 0) {
    std::cerr << "ERROR: you must specify a CA identity." << std::endl;
    return 2;
  }

  CaSqlite storage(Name(caNameString), "");
  std::list<RequestState> requestList;
  requestList = storage.listAllRequests();
  std::cerr << "The pending requests are :" << std::endl;
  for (const auto& entry : requestList) {
    std::cerr << "***************************************\n"
              << entry
              << "***************************************\n";
  }
  return 0;
}

} // namespace ca
} // namespace ndncert
} // namespace ndn

int
main(int argc, char* argv[])
{
  return ndn::ndncert::ca::main(argc, argv);
}
