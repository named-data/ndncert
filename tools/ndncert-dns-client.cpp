/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2017-2025, Regents of the University of California.
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

#include "requester-request.hpp"
#include "challenge/challenge-dns.hpp"

#include <ndn-cxx/face.hpp>
#include <ndn-cxx/security/key-chain.hpp>
#include <ndn-cxx/security/signing-helpers.hpp>
#include <ndn-cxx/security/verification-helpers.hpp>

#include <boost/algorithm/string/case_conv.hpp>
#include <boost/asio/signal_set.hpp>
#include <boost/program_options/options_description.hpp>
#include <boost/program_options/parsers.hpp>
#include <boost/program_options/variables_map.hpp>

#include <iostream>

namespace ndncert::requester {

static void
handleSignal(const boost::system::error_code& error, int signalNum, ndn::Face& face)
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

static ndn::Face face;
static ndn::KeyChain keyChain;
static std::shared_ptr<Request> requesterState;
static size_t nStep = 1;
static std::string identityName;
static int validityPeriod;

static void onNewResponse(const Data& reply);

static void
onCertFetchResponse(const Data& reply)
{
  auto item = Request::onCertFetchResponse(reply);
  if (item) {
    keyChain.addCertificate(keyChain.getPib().getIdentity(item->getIdentity()).getKey(item->getKeyName()), *item);
  }
  std::cerr << "\n***************************************\n"
            << "Step " << nStep++
            << ": DONE\nCertificate with Name: " << reply.getName()
            << " has been installed to your local keychain\n"
            << "Exit now" << std::endl;
  face.getIoContext().stop();
}

static void
onChallengeResponse(const Data& reply)
{
  try {
    requesterState->onChallengeResponse(reply);
  }
  catch (const std::exception& e) {
    std::cerr << "Error when decoding challenge step: " << e.what() << std::endl;
    exit(1);
  }

  if (requesterState->m_status == Status::SUCCESS) {
    std::cerr << "Certificate has already been issued, downloading certificate..." << std::endl;
    face.expressInterest(*requesterState->genCertFetchInterest(),
                         [] (const auto&, const auto& data) { onCertFetchResponse(data); },
                         [] (auto&&...) { std::cerr << "Got NACK\n"; exit(1); },
                         [] (auto&&...) { std::cerr << "Interest timeout\n"; });
    return;
  }

  std::cerr << "\n***************************************\n"
            << "Step " << nStep++ << ": DNS Challenge Setup" << std::endl;

  // Check if challenge status contains DNS record information
  if (!requesterState->m_challengeStatus.empty()) {
    std::cerr << "Challenge Status: " << requesterState->m_challengeStatus << std::endl;
  }

  // Handle different challenge statuses
  if (requesterState->m_challengeStatus == "need-record") {
    std::cerr << "\n=== DNS CHALLENGE SETUP ===\n";
    
    // Parse the challenge status JSON to extract DNS record information
    try {
      // The challenge status contains JSON with record details
      // Let's parse it and display properly formatted information
      std::string status = requesterState->m_challengeStatus;
      
      // Look for record-name and expected-value in the status string
      std::string recordName, expectedValue;
      
      // Simple parsing - look for the patterns
      size_t recordNamePos = status.find("\"record-name\":");
      size_t expectedValuePos = status.find("\"expected-value\":");
      
      if (recordNamePos != std::string::npos && expectedValuePos != std::string::npos) {
        // Extract record name
        size_t nameStart = status.find("\"", recordNamePos + 14) + 1;
        size_t nameEnd = status.find("\"", nameStart);
        if (nameStart != std::string::npos && nameEnd != std::string::npos) {
          recordName = status.substr(nameStart, nameEnd - nameStart);
        }
        
        // Extract expected value
        size_t valueStart = status.find("\"", expectedValuePos + 17) + 1;
        size_t valueEnd = status.find("\"", valueStart);
        if (valueStart != std::string::npos && valueEnd != std::string::npos) {
          expectedValue = status.substr(valueStart, valueEnd - valueStart);
        }
        
        if (!recordName.empty() && !expectedValue.empty()) {
          std::cerr << "Please create the following DNS TXT record:\n\n";
          std::cerr << "Record Name: " << recordName << "\n";
          std::cerr << "Record Type: TXT\n";
          std::cerr << "Record Value: " << expectedValue << "\n\n";
          std::cerr << "Example DNS configuration:\n";
          std::cerr << recordName << " IN TXT \"" << expectedValue << "\"\n\n";
        } else {
          std::cerr << "Could not parse DNS record details from status.\n";
          std::cerr << "Full status: " << status << "\n\n";
        }
      } else {
        // Check if DNS record info is available from the challenge response
        if (!requesterState->m_dnsRecordName.empty() && !requesterState->m_dnsExpectedValue.empty()) {
          std::cerr << "Please create the following DNS TXT record:\n\n";
          std::cerr << "Record Name: " << requesterState->m_dnsRecordName << "\n";
          std::cerr << "Record Type: TXT\n";
          std::cerr << "Record Value: " << requesterState->m_dnsExpectedValue << "\n\n";
          std::cerr << "Example DNS configuration:\n";
          std::cerr << requesterState->m_dnsRecordName << " IN TXT \"" << requesterState->m_dnsExpectedValue << "\"\n\n";
        } else {
          std::cerr << "Challenge response received but DNS record details not accessible.\n";
          std::cerr << "The CA has generated a challenge token but it's encrypted.\n\n";
          
          // We can at least show the record name format
          std::cerr << "You need to create a DNS TXT record with:\n";
          std::cerr << "Record Name: _ndncert-challenge.<your-domain>\n";
          std::cerr << "Record Type: TXT\n";
          std::cerr << "Record Value: <challenge-token-from-CA>\n\n";
          std::cerr << "Note: The exact challenge token should be provided by the CA.\n";
          std::cerr << "This appears to be a limitation in the current client implementation.\n\n";
        }
      }
    }
    catch (const std::exception& e) {
      std::cerr << "Error parsing challenge status: " << e.what() << "\n";
      std::cerr << "Raw status: " << requesterState->m_challengeStatus << "\n\n";
    }
    
    std::cerr << "After creating the DNS TXT record, press ENTER to continue verification...";
    std::string input;
    getline(std::cin, input);
    
    // Send confirmation
    auto requirement = requesterState->selectOrContinueChallenge("dns");
    requirement.clear();
    requirement.emplace("confirmation", "ready");
    
    face.expressInterest(*requesterState->genChallengeInterest(std::move(requirement)),
                         [] (const auto&, const auto& data) { onChallengeResponse(data); },
                         [] (auto&&...) { std::cerr << "Got NACK\n"; exit(1); },
                         [] (auto&&...) { std::cerr << "Interest timeout\n"; });
  }
  else if (requesterState->m_challengeStatus == "ready-for-validation" || 
           requesterState->m_challengeStatus == "wrong-record") {
    if (requesterState->m_challengeStatus == "wrong-record") {
      std::cerr << "\nDNS verification failed. Please check that:\n";
      std::cerr << "1. The TXT record exists and has the correct value\n";
      std::cerr << "2. DNS propagation has completed (may take a few minutes)\n";
      std::cerr << "Press ENTER to retry verification...";
      std::string input;
      getline(std::cin, input);
    }
    
    // Send validation request
    auto requirement = requesterState->selectOrContinueChallenge("dns");
    if (requesterState->m_challengeStatus == "wrong-record") {
      requirement.clear();
      requirement.emplace("confirmation", "ready");
    }
    
    face.expressInterest(*requesterState->genChallengeInterest(std::move(requirement)),
                         [] (const auto&, const auto& data) { onChallengeResponse(data); },
                         [] (auto&&...) { std::cerr << "Got NACK\n"; exit(1); },
                         [] (auto&&...) { std::cerr << "Interest timeout\n"; });
  }
  else {
    // Automatic validation for other statuses
    auto requirement = requesterState->selectOrContinueChallenge("dns");
    face.expressInterest(*requesterState->genChallengeInterest(std::move(requirement)),
                         [] (const auto&, const auto& data) { onChallengeResponse(data); },
                         [] (auto&&...) { std::cerr << "Got NACK\n"; exit(1); },
                         [] (auto&&...) { std::cerr << "Interest timeout\n"; });
  }
}

static void
onCaProfileResponse(const Data& reply)
{
  try {
    auto profile = Request::onCaProfileResponse(reply);
    if (!profile) {
      std::cerr << "Failed to parse CA profile" << std::endl;
      exit(1);
    }

    std::cerr << "\n***************************************\n"
              << "Step " << nStep++ << ": CA Profile Retrieved" << std::endl;
    std::cerr << "CA Info: " << profile->caInfo << std::endl;

    // Initialize request state with the retrieved profile
    requesterState = std::make_shared<Request>(keyChain, *profile, RequestType::NEW);

    // For DNS challenges, ensure identity is under the CA prefix
    std::string fullIdentityName = identityName;
    if (!profile->caPrefix.isPrefixOf(Name(identityName))) {
      fullIdentityName = profile->caPrefix.toUri() + identityName;
    }

    // Create or get identity
    const auto& pib = keyChain.getPib();
    ndn::security::pib::Identity identity;
    try {
      identity = pib.getIdentity(Name(fullIdentityName));
    }
    catch (const ndn::security::Pib::Error&) {
      identity = keyChain.createIdentity(Name(fullIdentityName));
    }

    // Create or get key
    ndn::security::pib::Key key;
    try {
      key = identity.getDefaultKey();
    }
    catch (const ndn::security::Pib::Error&) {
      key = keyChain.createKey(identity);
    }

    auto now = time::system_clock::now();
    auto interest = requesterState->genNewInterest(key.getName(), now, now + time::hours(validityPeriod));

    if (interest != nullptr) {
      std::cerr << "\n***************************************\n"
                << "Step " << nStep++ << ": Sending NEW request" << std::endl;
      std::cerr << "Identity: " << fullIdentityName << std::endl;

      face.expressInterest(*interest,
                           [] (const auto&, const auto& data) { onNewResponse(data); },
                           [] (auto&&...) { std::cerr << "Got NACK\n"; exit(1); },
                           [] (auto&&...) { std::cerr << "Interest timeout\n"; });
    }
    else {
      std::cerr << "Cannot generate new interest" << std::endl;
      exit(1);
    }
  }
  catch (const std::exception& e) {
    std::cerr << "Error when processing CA profile: " << e.what() << std::endl;
    exit(1);
  }
}

static void
onCaProfileDiscoveryResponse(const Data& reply)
{
  try {
    auto interest = Request::genCaProfileInterestFromDiscoveryResponse(reply);
    std::cerr << "\n***************************************\n"
              << "Step " << nStep++ << ": Requesting CA Profile" << std::endl;
    
    face.expressInterest(*interest,
                         [] (const auto&, const auto& data) { onCaProfileResponse(data); },
                         [] (auto&&...) { std::cerr << "Got NACK\n"; exit(1); },
                         [] (auto&&...) { std::cerr << "Interest timeout\n"; });
  }
  catch (const std::exception& e) {
    std::cerr << "Error when processing CA profile discovery: " << e.what() << std::endl;
    exit(1);
  }
}

static void
onNewResponse(const Data& reply)
{
  try {
    requesterState->onNewRenewRevokeResponse(reply);
  }
  catch (const std::exception& e) {
    std::cerr << "Error when decoding NEW step: " << e.what() << std::endl;
    exit(1);
  }

  std::cerr << "\n***************************************\n"
            << "Step " << nStep++ << ": Starting DNS Challenge" << std::endl;

  // Start DNS challenge directly
  std::cerr << "Please provide the domain name you want to verify: ";
  std::string domain;
  getline(std::cin, domain);
  
  auto requirement = requesterState->selectOrContinueChallenge("dns");
  requirement.clear(); // Clear placeholder parameters
  requirement.emplace("domain", domain);

  face.expressInterest(*requesterState->genChallengeInterest(std::move(requirement)),
                       [] (const auto&, const auto& data) { onChallengeResponse(data); },
                       [] (auto&&...) { std::cerr << "Got NACK\n"; exit(1); },
                       [] (auto&&...) { std::cerr << "Interest timeout\n"; });
}

int
main(int argc, char* argv[])
{
  boost::asio::signal_set terminateSignals(face.getIoContext());
  terminateSignals.add(SIGINT);
  terminateSignals.add(SIGTERM);
  terminateSignals.async_wait([&] (const auto& error, int signalNum) {
    handleSignal(error, signalNum, face);
  });

  std::string caName = "/example";
  identityName = "";
  validityPeriod = 1; // 1 hour

  namespace po = boost::program_options;
  po::options_description optsDesc("Options");
  optsDesc.add_options()
    ("help,h", "print this help message and exit")
    ("ca-name,c", po::value<std::string>(&caName)->default_value(caName), "CA name")
    ("identity,i", po::value<std::string>(&identityName), "identity name for certificate")
    ("validity,v", po::value<int>(&validityPeriod)->default_value(validityPeriod), "validity period in hours");

  po::variables_map vm;
  try {
    po::store(po::parse_command_line(argc, argv, optsDesc), vm);
    po::notify(vm);
  }
  catch (const po::error& e) {
    std::cerr << "ERROR: " << e.what() << std::endl;
    return 2;
  }

  if (vm.count("help") != 0) {
    std::cout << "Usage: " << argv[0] << " [options]\n"
              << "\n"
              << optsDesc;
    return 0;
  }

  if (identityName.empty()) {
    std::cerr << "Please specify identity name with --identity option" << std::endl;
    return 1;
  }

  try {
    std::cerr << "Starting DNS Challenge Client for CA: " << caName << std::endl;
    std::cerr << "Discovering CA profile..." << std::endl;

    // Start with CA profile discovery
    auto discoveryInterest = Request::genCaProfileDiscoveryInterest(Name(caName));
    std::cerr << "\n***************************************\n"
              << "Step " << nStep++ << ": Discovering CA Profile" << std::endl;

    face.expressInterest(*discoveryInterest,
                         [] (const auto&, const auto& data) { onCaProfileDiscoveryResponse(data); },
                         [] (auto&&...) { std::cerr << "Got NACK\n"; exit(1); },
                         [] (auto&&...) { std::cerr << "Interest timeout\n"; });

    face.processEvents();
  }
  catch (const std::exception& e) {
    std::cerr << "ERROR: " << e.what() << std::endl;
    return 1;
  }

  return 0;
}

} // namespace ndncert::requester

int
main(int argc, char* argv[])
{
  return ndncert::requester::main(argc, argv);
}
