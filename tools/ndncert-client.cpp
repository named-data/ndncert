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

#include "challenge-module.hpp"
#include "client-module.hpp"
#include "protocol-detail/info.hpp"
#include <ndn-cxx/security/verification-helpers.hpp>
#include <boost/asio.hpp>
#include <boost/program_options/options_description.hpp>
#include <boost/program_options/parsers.hpp>
#include <boost/program_options/variables_map.hpp>
#include <iostream>
#include <string>

namespace ndn {
namespace ndncert {

static void
startApplication();

int nStep;
Face face;
security::v2::KeyChain keyChain;
std::string challengeType;
int validityPeriod = -1;
ClientModule client(keyChain);

static void
captureParams(std::vector<std::tuple<std::string, std::string>>& requirement)
{
  std::list<std::string> results;
  for (auto& item : requirement) {
    std::cerr << std::get<1>(item) << std::endl;
    std::string captured;
    getline(std::cin, captured);
    std::get<1>(item) = captured;
  }
  std::cerr << "Got it. This is what you've provided:" << std::endl;
  for (const auto& item : requirement) {
    std::cerr << std::get<0>(item) << " : " << std::get<1>(item) << std::endl;
  }
}

static std::vector<std::tuple<std::string, std::string>>
captureParams(const std::list<std::string>& requirement)
{
  std::vector<std::tuple<std::string, std::string>> results;
  for (const auto& item : requirement) {
    std::cerr << "Please provide the argument: " << item << " : " << std::endl;
    std::string captured;
    getline(std::cin, captured);
    results.push_back(std::make_tuple(item, captured));
  }
  std::cerr << "Got it. This is what you've provided:" << std::endl;
  for (const auto& item : results) {
    std::cerr << std::get<0>(item) << " : " << std::get<1>(item) << std::endl;
  }
  return results;
}

static void
captureValidityPeriod()
{
  if (validityPeriod > 0) {
    return;
  }
  std::cerr << "Step " << nStep++
            << ": Please type in your expected validity period of your certificate."
            << " Type the number of hours (168 for week, 730 for month, 8760 for year)."
            << " The CA may reject your application if your expected period is too long." << std::endl;
  std::string periodStr = "";
  getline(std::cin, periodStr);
  try {
    validityPeriod = std::stoi(periodStr);
  }
  catch (const std::exception& e) {
    validityPeriod = -1;
  }
}

static void
onNackCb()
{
  std::cerr << "Got NACK\n";
}

static void
timeoutCb()
{
  std::cerr << "Interest sent time out\n";
}

static void
certFetchCb(const Data& reply)
{
  client.onCertFetchResponse(reply);
  std::cerr << "Step " << nStep++
            << ": DONE! Certificate has already been installed to local keychain\n"
            << "Certificate Name: " << reply.getName().toUri() << std::endl;
}

static void
challengeCb(const Data& reply)
{
  client.onChallengeResponse(reply);
  if (client.getApplicationStatus() == Status::SUCCESS) {
    std::cerr << "DONE! Certificate has already been issued \n";
    face.expressInterest(*client.generateCertFetchInterest(), bind(&certFetchCb, _2),
                         bind(&onNackCb), bind(&timeoutCb));
    return;
  }

  auto challenge = ChallengeModule::createChallengeModule(challengeType);
  auto requirement = challenge->getRequestedParameterList(client.getApplicationStatus(),
                                                          client.getChallengeStatus());
  if (requirement.size() > 0) {
    std::cerr << "Step " << nStep++ << ": Please satisfy following instruction(s)\n";
    captureParams(requirement);
  }
  face.expressInterest(*client.generateChallengeInterest(challenge->genChallengeRequestTLV(client.getApplicationStatus(),
                                                                                           client.getChallengeStatus(),
                                                                                           std::move(requirement))),
                       bind(&challengeCb, _2), bind(&onNackCb), bind(&timeoutCb));
}

static void
newCb(const Data& reply)
{
  int challengeIndex = 0;
  auto challengeList = client.onNewRenewRevokeResponse(reply);
  if (challengeList.size() < 1) {
    std::cerr << "There is no available challenge provided by the CA. Exit" << std::endl;
    return;
  }
  else if (challengeList.size() > 1) {
    int count = 0;
    std::string choice = "";
    std::cerr << "Step " << nStep++ << ": Please type in the challenge index that you want to perform\n";
    count = 0;
    for (auto item : challengeList) {
      std::cerr << "\t" << count++ << " : " << item << std::endl;
    }
    getline(std::cin, choice);
    try {
      challengeIndex = std::stoi(choice);
    }
    catch (const std::exception& e) {
      challengeIndex = -1;
    }
    if (challengeIndex < 0 || challengeIndex >= count) {
      std::cerr << "Your input index is out of range. Exit." << std::endl;
      return;
    }
  }
  auto it = challengeList.begin();
  std::advance(it, challengeIndex);
  unique_ptr<ChallengeModule> challenge = ChallengeModule::createChallengeModule(*it);
  if (challenge != nullptr) {
    challengeType = *it;
    std::cerr << "The challenge has been selected: " << challengeType << std::endl;
  }
  else {
    std::cerr << "Error. Cannot load selected Challenge Module. Exit." << std::endl;
    return;
  }
  auto requirement = challenge->getRequestedParameterList(client.getApplicationStatus(),
                                                          client.getChallengeStatus());
  if (requirement.size() > 0) {
    std::cerr << "Step " << nStep++ << ": Please provide parameters used for Identity Verification Challenge\n";
    captureParams(requirement);
  }
  face.expressInterest(*client.generateChallengeInterest(challenge->genChallengeRequestTLV(client.getApplicationStatus(),
                                                                                           client.getChallengeStatus(),
                                                                                           std::move(requirement))),
                       bind(&challengeCb, _2), bind(&onNackCb), bind(&timeoutCb));
}

static void
InfoCb(const Data& reply)
{
  const Block& contentBlock = reply.getContent();

  if (!client.verifyInfoResponse(reply)) {
    std::cerr << "The fetched CA information cannot be trusted because its integrity is broken" << std::endl;
    return;
  }
  auto caItem = INFO::decodeDataContent(contentBlock);

  std::cerr << "Will use a new trust anchor, please double check the identity info: \n"
            << "This trust anchor information is signed by " << reply.getSignature().getKeyLocator()
            << std::endl
            << "The certificate is " << *caItem.m_cert << std::endl
            << "Do you trust the information? Type in YES or NO" << std::endl;

  std::string answer;
  getline(std::cin, answer);
  boost::algorithm::to_lower(answer);
  if (answer == "yes") {
    std::cerr << "You answered YES: new CA will be used" << std::endl;
    client.addCaFromInfoResponse(reply);
    // client.getClientConf().save(std::string(SYSCONFDIR) + "/ndncert/client.conf");
    startApplication();
  }
  else {
    std::cerr << "You answered NO: new CA will not be used" << std::endl;
    return;
  }
}

static void
probeCb(const Data& reply)
{
  client.onProbeResponse(reply);
  captureValidityPeriod();
  if (validityPeriod <= 0) {
    std::cerr << "Invalid period time. Exit." << std::endl;
    return;
  }
  auto now = time::system_clock::now();
  std::cerr << "The validity period of your certificate will be: " << validityPeriod << " hours" << std::endl;
  auto interest = client.generateNewInterest(now, now + time::hours(validityPeriod), Name());
  if (interest != nullptr) {
    face.expressInterest(*interest, bind(&newCb, _2), bind(&onNackCb), bind(&timeoutCb));
  }
  else {
    std::cerr << "Cannot generate the Interest for NEW step. Exit" << std::endl;
  }
}

static void
startApplication()
{
  nStep = 0;
  auto caList = client.getClientConf().m_caItems;
  int count = 0;
  for (auto item : caList) {
    std::cerr << "***************************************\n"
              << "Index: " << count++ << "\n"
              << "CA prefix:" << item.m_caPrefix << "\n"
              << "Introduction: " << item.m_caInfo << "\n"
              << "***************************************\n";
  }
  std::vector<CaConfigItem> caVector{std::begin(caList), std::end(caList)};
  std::cerr << "Step "
            << nStep++ << ": Please type in the CA INDEX that you want to apply"
            << " or type in NONE if your expected CA is not in the list\n";

  std::string caIndexS, caIndexSLower;
  getline(std::cin, caIndexS);
  caIndexSLower = caIndexS;
  boost::algorithm::to_lower(caIndexSLower);
  if (caIndexSLower == "none") {
    std::cerr << "Step " << nStep << ": Please type in the CA Name\n";
    std::string expectedCAName;
    getline(std::cin, expectedCAName);
    face.expressInterest(*client.generateInfoInterest(Name(expectedCAName)),
                         bind(&InfoCb, _2), bind(&onNackCb), bind(&timeoutCb));
  }
  else {
    int caIndex;
    try {
      caIndex = std::stoi(caIndexS);
    }
    catch (const std::exception& e) {
      std::cerr << "Your input is neither NONE nor a valid index. Exit" << std::endl;
      return;
    }
    if (caIndex < 0 || caIndex >= count) {
      std::cerr << "Your input is not an existing index. Exit" << std::endl;
      return;
    }
    auto targetCaItem = caVector[caIndex];

    if (!targetCaItem.m_probeParameterKeys.empty()) {
      std::cerr << "Step " << nStep++ << ": Please provide information for name assignment" << std::endl;
      auto capturedParams = captureParams(targetCaItem.m_probeParameterKeys);
      face.expressInterest(*client.generateProbeInterest(targetCaItem, std::move(capturedParams)),
                           bind(&probeCb, _2), bind(&onNackCb), bind(&timeoutCb));
    }
    else {
      std::cerr << "Step " << nStep++ << ": Please type in the full identity name you want to get (with CA prefix)\n";
      std::string identityNameStr;
      getline(std::cin, identityNameStr);
      captureValidityPeriod();
      if (validityPeriod <= 0) {
        std::cerr << "Invalid period time. Exit." << std::endl;
        return;
      }
      Name idName(identityNameStr);
      std::cerr << "The validity period of your certificate will be: " << validityPeriod << " hours" << std::endl;
      auto now = time::system_clock::now();
      auto interest = client.generateNewInterest(now, now + time::hours(validityPeriod), idName);
      if (interest != nullptr) {
        face.expressInterest(*interest, bind(&newCb, _2), bind(&onNackCb), bind(&timeoutCb));
      }
      else {
        std::cerr << "Cannot generate the Interest for NEW step. Exit" << std::endl;
      }
    }
  }
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
  client.endSession();
  face.getIoService().stop();
}

int
main(int argc, char* argv[])
{
  boost::asio::signal_set terminateSignals(face.getIoService());
  terminateSignals.add(SIGINT);
  terminateSignals.add(SIGTERM);
  terminateSignals.async_wait(handleSignal);

  namespace po = boost::program_options;
  std::string configFilePath = std::string(SYSCONFDIR) + "/ndncert/client.conf";
  po::options_description description("General Usage\n ndncert-client [-h] [-c] [-v]\n");
  description.add_options()("help,h", "produce help message")("config-file,c", po::value<std::string>(&configFilePath), "configuration file name")("validity-period,v", po::value<int>(&validityPeriod)->default_value(-1),
                                                                                                                                                   "desired validity period (hours) of the certificate being requested");
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
  try {
    client.getClientConf().load(configFilePath);
  }
  catch (const std::exception& e) {
    std::cerr << "Cannot load the configuration file: " << e.what() << std::endl;
    return 1;
  }
  startApplication();
  face.processEvents();
  return 0;
}

}  // namespace ndncert
}  // namespace ndn

int
main(int argc, char* argv[])
{
  return ndn::ndncert::main(argc, argv);
}
