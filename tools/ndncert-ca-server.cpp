/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2017-2023, Regents of the University of California.
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

#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/signal_set.hpp>
#include <boost/program_options/options_description.hpp>
#include <boost/program_options/parsers.hpp>
#include <boost/program_options/variables_map.hpp>

#include <chrono>
#include <deque>
#include <iostream>

#include <ndn-cxx/face.hpp>
#include <ndn-cxx/security/key-chain.hpp>

namespace ndncert::ca {

static ndn::Face face;
static ndn::KeyChain keyChain;
static std::string repoHost = "localhost";
static std::string repoPort = "7376";
constexpr size_t MAX_CACHED_CERT_NUM = 100;

static bool
writeDataToRepo(const Data& data)
{
  boost::asio::ip::tcp::iostream requestStream;
  requestStream.expires_after(std::chrono::seconds(5));
  requestStream.connect(repoHost, repoPort);
  if (!requestStream) {
    std::cerr << "ERROR: Cannot publish the certificate to repo-ng"
              << " (" << requestStream.error().message() << ")" << std::endl;
    return false;
  }
  requestStream.write(reinterpret_cast<const char*>(data.wireEncode().data()),
                      data.wireEncode().size());
  return true;
}

static void
handleSignal(const boost::system::error_code& error, int signalNum)
{
  if (error) {
    return;
  }
  const char* signalName = ::strsignal(signalNum);
  std::cerr << "Exiting on signal ";
  if (signalName == nullptr) {
    std::cerr << signalNum;
  }
  else {
    std::cerr << signalName;
  }
  std::cerr << std::endl;
  face.getIoContext().stop();
  exit(1);
}

static int
main(int argc, char* argv[])
{
  boost::asio::signal_set terminateSignals(face.getIoContext());
  terminateSignals.add(SIGINT);
  terminateSignals.add(SIGTERM);
  terminateSignals.async_wait(handleSignal);

  std::string configFilePath(NDNCERT_SYSCONFDIR "/ndncert/ca.conf");
  bool wantRepoOut = false;

  namespace po = boost::program_options;
  po::options_description optsDesc("Options");
  optsDesc.add_options()
  ("help,h", "print this help message and exit")
  ("config-file,c", po::value<std::string>(&configFilePath)->default_value(configFilePath), "path to configuration file")
  ("repo-output,r", po::bool_switch(&wantRepoOut), "when enabled, all issued certificates will be published to repo-ng")
  ("repo-host,H", po::value<std::string>(&repoHost)->default_value(repoHost), "repo-ng host")
  ("repo-port,P", po::value<std::string>(&repoPort)->default_value(repoPort), "repo-ng port");

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

  CaModule ca(face, keyChain, configFilePath);
  std::deque<Data> cachedCertificates;
  auto profileData = ca.getCaProfileData();

  if (wantRepoOut) {
    writeDataToRepo(profileData);
    ca.setStatusUpdateCallback([&](const RequestState& request) {
      if (request.status == Status::SUCCESS && request.requestType == RequestType::NEW) {
        writeDataToRepo(request.cert);
      }
    });
  }
  else {
    ca.setStatusUpdateCallback([&](const RequestState& request) {
      if (request.status == Status::SUCCESS && request.requestType == RequestType::NEW) {
        cachedCertificates.push_front(request.cert);
        if (cachedCertificates.size() > MAX_CACHED_CERT_NUM) {
          cachedCertificates.pop_back();
        }
      }
    });
    face.setInterestFilter(
        ndn::InterestFilter(ca.getCaConf().caProfile.caPrefix),
        [&](const auto&, const auto& interest) {
          const auto& interestName = interest.getName();
          if (interestName.isPrefixOf(profileData.getName())) {
            face.put(profileData);
            return;
          }
          for (const auto& item : cachedCertificates) {
            if (interestName.isPrefixOf(item.getFullName())) {
              face.put(item);
              return;
            }
          }
        });
  }

  face.processEvents();
  return 0;
}

} // namespace ndncert::ca

int
main(int argc, char* argv[])
{
  return ndncert::ca::main(argc, argv);
}
