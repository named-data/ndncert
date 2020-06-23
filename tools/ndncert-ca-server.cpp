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

#include "ca-module.hpp"
#include "challenge-module.hpp"

#include <ndn-cxx/face.hpp>
#include <ndn-cxx/security/key-chain.hpp>

#include <boost/asio/ip/tcp.hpp>
#if BOOST_VERSION < 106700
#include <boost/date_time/posix_time/posix_time_duration.hpp>
#endif
#include <boost/program_options/options_description.hpp>
#include <boost/program_options/parsers.hpp>
#include <boost/program_options/variables_map.hpp>

#include <iostream>

namespace ndn {
namespace ndncert {

static int
main(int argc, char* argv[])
{
  std::string configFilePath(SYSCONFDIR "/ndncert/ca.conf");
  std::string repoHost("localhost");
  std::string repoPort("7376");
  bool wantRepoOut = false;

  namespace po = boost::program_options;
  po::options_description optsDesc("Options");
  optsDesc.add_options()
    ("help,h",        "print this help message and exit")
    ("config-file,c", po::value<std::string>(&configFilePath)->default_value(configFilePath),
                      "path to configuration file")
    ("repo-output,r", po::bool_switch(&wantRepoOut),
                      "when enabled, all issued certificates will be published to repo-ng")
    ("repo-host,H",   po::value<std::string>(&repoHost)->default_value(repoHost), "repo-ng host")
    ("repo-port,P",   po::value<std::string>(&repoPort)->default_value(repoPort), "repo-ng port");

  po::variables_map vm;
  try {
    po::store(po::parse_command_line(argc, argv, optsDesc), vm);
    po::notify(vm);
  }
  catch (const po::error& e) {
    std::cerr << "ERROR: " << e.what() << std::endl;
    return 2;
  }
  catch (const boost::bad_any_cast& e) {
    std::cerr << "ERROR: " << e.what() << std::endl;
    return 2;
  }

  if (vm.count("help") != 0) {
    std::cout << "Usage: " << argv[0] << " [options]\n"
              << "\n"
              << optsDesc;
    return 0;
  }

  Face face;
  security::v2::KeyChain keyChain;
  CaModule ca(face, keyChain, configFilePath);

  if (wantRepoOut) {
      ca.setStatusUpdateCallback([&] (const CaState& request) {
          if (request.m_status == Status::SUCCESS && request.m_requestType == RequestType::NEW) {
            auto issuedCert = request.m_cert;
            boost::asio::ip::tcp::iostream requestStream;
            requestStream.expires_after(std::chrono::seconds(3));
            requestStream.connect(repoHost, repoPort);
            if (!requestStream) {
              std::cerr << "ERROR: Cannot publish certificate to repo-ng"
                        << " (" << requestStream.error().message() << ")" << std::endl;
              return;
            }
            requestStream.write(reinterpret_cast<const char*>(issuedCert.wireEncode().wire()),
                                issuedCert.wireEncode().size());
          }
      });
  }

  face.processEvents();
  return 0;
}

} // namespace ndncert
} // namespace ndn

int
main(int argc, char* argv[])
{
  return ndn::ndncert::main(argc, argv);
}
