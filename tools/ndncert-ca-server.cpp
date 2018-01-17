/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/**
 * Copyright (c) 2017-2018, Regents of the University of California.
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

#include <iostream>
#include <sstream>
#include <string>
#include <ndn-cxx/util/io.hpp>
#include <boost/program_options/options_description.hpp>
#include <boost/program_options/variables_map.hpp>
#include <boost/program_options/parsers.hpp>
#include <boost/date_time/posix_time/posix_time_duration.hpp>
#include <boost/asio.hpp>

namespace ndn {
namespace ndncert {

int
main(int argc, char* argv[])
{
  std::string configFilePath = std::string(SYSCONFDIR) + "/ndncert/ca.conf";
  std::string repoPrefix;
  std::string repoCaIdentity;
  std::string repoHost;
  std::string repoPort;
  bool isRepoOut = false;

  namespace po = boost::program_options;
  po::options_description description("General Usage\n  ndncert-ca [-h] [-f] [-r] [-c]\n");
  description.add_options()
    ("help,h",
     "produce help message")
    ("config-file,f", po::value<std::string>(&configFilePath),
     "config file name")
    ("repo-output,r",
     "when enabled, all issued certificates will be published to repo-ng")
    ("repo-host,H", po::value<std::string>(&repoHost)->default_value("localhost"),
     "repo-ng host")
    ("repo-port,P", po::value<std::string>(&repoPort)->default_value("7376"),
     "repo-ng port");

  po::positional_options_description p;
  po::variables_map vm;
  try {
    po::store(po::command_line_parser(argc, argv).options(description).positional(p).run(), vm);
    po::notify(vm);
  }
  catch (const std::exception& e) {
    std::cerr << "ERROR: " << e.what()
              << "\n" << description << std::endl;
    return 1;
  }
  if (vm.count("help") != 0) {
    std::cerr << description << std::endl;
    return 0;
  }
  if (vm.count("repo-ng-output") != 0) {
    isRepoOut = true;
  }

  Face face;
  security::v2::KeyChain keyChain;
  CaModule ca(face, keyChain, configFilePath);

  ca.setRecommendCaHandler(Name("/ndn"),
    [] (const std::string& input, const std::list<Name>& list) -> std::tuple<Name, std::string> {
      Name recommendedCa;
      std::string identity;
      for (auto caName : list) {
        std::string univName = readString(caName.get(-1));
        if (input.find(univName) != std::string::npos) {
          recommendedCa = caName;
          identity = input.substr(0, input.find("@"));
          break;
        }
      }
      return std::make_tuple(recommendedCa, identity);
    });

  if (isRepoOut) {
    auto config = ca.getCaConf();
    for (const auto& caItem : config.m_caItems) {
      ca.setStatusUpdateCallback(caItem.m_caName,
        [&] (const CertificateRequest& request) {
          if (request.getStatus() == ChallengeModule::SUCCESS) {
            auto issuedCert = request.getCert();
            using namespace boost::asio::ip;
            tcp::iostream requestStream;
            requestStream.expires_from_now(boost::posix_time::seconds(3));
            requestStream.connect(repoHost, repoPort);
            if (!requestStream) {
              std::cerr << "ERROR: Cannot publish certificate to repo-ng"
                        << " (" << requestStream.error().message() << ")"
                        << std::endl;
              return;
            }
            requestStream.write(reinterpret_cast<const char*>(issuedCert.wireEncode().wire()),
                                issuedCert.wireEncode().size());
          }
        });
    }
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
