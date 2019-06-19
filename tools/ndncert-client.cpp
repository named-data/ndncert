/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/**
 * Copyright (c) 2017-2019, Regents of the University of California.
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

#include "client-module.hpp"
#include "challenge-module.hpp"
#include <iostream>
#include <string>
#include <algorithm>
#include <boost/program_options/options_description.hpp>
#include <boost/program_options/variables_map.hpp>
#include <boost/program_options/parsers.hpp>
#include <ndn-cxx/security/verification-helpers.hpp>

namespace ndn {
namespace ndncert {

static void startApplication();

int nStep;
Face face;
security::v2::KeyChain keyChain;
std::string challengeType;
ClientModule client(keyChain);

static std::list<std::string>
captureParams(const JsonSection& requirement)
{
  std::list<std::string> results;
  for (const auto& item : requirement) {
    std::cerr << item.second.get<std::string>("") << std::endl;
    std::cerr << "Please provide the argument: " << item.first << " : " << std::endl;
    std::string tempParam;
    getline(std::cin, tempParam);
    results.push_back(tempParam);
  }
  std::cerr << "Got it. This is what you've provided:" << std::endl;
  auto it1 = results.begin();
  auto it2 = requirement.begin();
  for (; it1 != results.end() && it2 != requirement.end(); it1++, it2++) {
    std::cerr << it2->first << " : " << *it1 << std::endl;
  }
  return results;
}

static std::list<std::string>
captureParams(const std::vector<std::string>& requirement)
{
  std::list<std::string> results;
  for (const auto& item : requirement) {
    std::cerr << "Please provide the argument: " << item << " : " << std::endl;
    std::string tempParam;
    getline(std::cin, tempParam);
    results.push_back(tempParam);
  }
  std::cerr << "Got it. This is what you've provided:" << std::endl;
  auto it1 = results.begin();
  auto it2 = requirement.begin();
  for (; it1 != results.end() && it2 != requirement.end(); it1++, it2++) {
    std::cerr << *it2 << " : " << *it1 << std::endl;
  }
  return results;
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
downloadCb(const Data& reply)
{
  client.onDownloadResponse(reply);
  std::cerr << "Step " << nStep++
            << ": DONE! Certificate has already been installed to local keychain\n";
  return;
}

static void
challengeCb(const Data& reply)
{
  client.onChallengeResponse(reply);
  if (client.getApplicationStatus() == STATUS_SUCCESS) {
    std::cerr << "DONE! Certificate has already been issued \n";
    face.expressInterest(*client.generateDownloadInterest(), bind(&downloadCb, _2),
                         bind(&onNackCb), bind(&timeoutCb));
    return;
  }

  auto challenge = ChallengeModule::createChallengeModule(challengeType);
  auto requirement = challenge->getRequirementForChallenge(client.getApplicationStatus(), client.getChallengeStatus());
  if (requirement.size() > 0) {
    std::cerr << "Step " << nStep++ << ": Please satisfy following instruction(s)\n";
    std::string redo = "";
    std::list<std::string> capturedParams;
    do {
      capturedParams = captureParams(requirement);
      std::cerr << "If everything is right, please type in OK; otherwise, type in REDO" << std::endl;
      getline(std::cin, redo);
      std::transform(redo.begin(), redo.end(), redo.begin(), ::toupper);
    } while (redo == "REDO");
    auto it1 = capturedParams.begin();
    auto it2 = requirement.begin();
    for (; it1 != capturedParams.end() && it2 != requirement.end(); it1++, it2++) {
      it2->second.put("", *it1);
    }
  }
  face.expressInterest(*client.generateChallengeInterest(
                        challenge->genChallengeRequestJson(
                                   client.getApplicationStatus(),
                                   client.getChallengeStatus(),
                                   requirement)),
                       bind(&challengeCb, _2),
                       bind(&onNackCb),
                       bind(&timeoutCb));
}

static void
newCb(const Data& reply)
{
  auto challengeList = client.onNewResponse(reply);
  std::cerr << "Step " << nStep++ << ": Please type in the challenge ID from the following challenges\n";
  for (auto item : challengeList) {
    std::cerr << "\t" << item << std::endl;
  }
  std::string choice;
  getline(std::cin, choice);

  auto challenge = ChallengeModule::createChallengeModule(choice);
  if (challenge != nullptr) {
    challengeType = choice;
  }
  else {
    std::cerr << "Cannot recognize the specified challenge. Exit";
    return;
  }
  auto requirement = challenge->getRequirementForChallenge(client.getApplicationStatus(),
                                                           client.getChallengeStatus());
  if (requirement.size() > 0) {
    std::cerr << "Step " << nStep++ << ": Please satisfy following instruction(s)\n";
    std::string redo = "";
    std::list<std::string> capturedParams;
    do {
      capturedParams = captureParams(requirement);
      std::cerr << "If everything is right, please type in OK; otherwise, type in REDO" << std::endl;
      getline(std::cin, redo);
      std::transform(redo.begin(), redo.end(), redo.begin(), ::toupper);
    } while (redo == "REDO");
    auto it1 = capturedParams.begin();
    auto it2 = requirement.begin();
    for (; it1 != capturedParams.end() && it2 != requirement.end(); it1++, it2++) {
      it2->second.put("", *it1);
    }
  }
  face.expressInterest(*client.generateChallengeInterest(
                               challenge->genChallengeRequestJson(
                                          client.getApplicationStatus(),
                                          client.getChallengeStatus(),
                                          requirement)),
                       bind(&challengeCb, _2),
                       bind(&onNackCb),
                       bind(&timeoutCb));
}

static void
probeInfoCb(const Data& reply)
{
  auto contentJson = ClientModule::getJsonFromData(reply);
  auto caItem = ClientConfig::extractCaItem(contentJson);

  std::cerr << "Will install new trust anchor, please double check the identity info: \n"
            << "This trust anchor packet is signed by " << reply.getSignature().getKeyLocator() << std::endl
            << "The signing certificate is " << caItem.m_anchor << std::endl;
  std::cerr << "Do you trust the information? Type in YES or NO" << std::endl;

  std::string answer;
  getline(std::cin, answer);
  std::transform(answer.begin(), answer.end(), answer.begin(), ::toupper);
  if (answer == "YES") {
    client.onProbeInfoResponse(reply);
    std::cerr << "You answered YES: new CA installed" << std::endl;
    startApplication();
  }
  else {
    std::cerr << "New CA not installed" << std::endl;
    return;
  }
}

static void
probeCb(const Data& reply)
{
  std::cerr << "Step " << nStep++
            << ": Please type in your expected validity period of your certificate."
            << " Type in a number in unit of hour. The CA may change the validity"
            << " period if your expected period is too long." << std::endl;
  std::string periodStr;
  getline(std::cin, periodStr);
  int hours = std::stoi(periodStr);
  face.expressInterest(*client.generateNewInterest(time::system_clock::now(),
                                                   time::system_clock::now() + time::hours(hours)),
                       bind(&newCb, _2),
                       bind(&onNackCb),
                       bind(&timeoutCb));
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
              << "CA prefix:" << item.m_caName << "\n"
              << "Introduction: " << item.m_caInfo << "\n"
              << "***************************************\n";
  }
  std::vector<ClientCaItem> caVector{std::begin(caList), std::end(caList)};
  std::cerr << "Step "
            << nStep++ << ": Please type in the CA INDEX that you want to apply"
            << " or type in NONE if your expected CA is not in the list\n";

  std::string caIndexS, caIndexSUpper;
  getline(std::cin, caIndexS);
  caIndexSUpper = caIndexS;
  std::transform(caIndexSUpper.begin(), caIndexSUpper.end(), caIndexSUpper.begin(), ::toupper);
  if (caIndexSUpper == "NONE") {
    std::cerr << "Step " << nStep << ": Please type in the CA Name\n";
    face.expressInterest(*client.generateProbeInfoInterest(Name(caIndexS)),
                         bind(&probeInfoCb, _2),
                         bind(&onNackCb),
                         bind(&timeoutCb));
  }
  else {
    int caIndex = std::stoi(caIndexS);
    BOOST_ASSERT(caIndex <= count);
    auto targetCaItem = caVector[caIndex];

    if (targetCaItem.m_probe != "") {
      std::cerr << "Step " << nStep++ << ": Please provide information for name assignment" << std::endl;
      std::vector<std::string> probeFields = ClientModule::parseProbeComponents(targetCaItem.m_probe);
      std::string redo = "";
      std::list<std::string> capturedParams;
      do {
        capturedParams = captureParams(probeFields);
        std::cerr << "If everything is right, please type in OK; otherwise, type in REDO" << std::endl;
        getline(std::cin, redo);
        std::transform(redo.begin(), redo.end(), redo.begin(), ::toupper);
      } while (redo == "REDO");
      std::string probeInfo;
      for (const auto& item : capturedParams) {
        probeInfo += item;
        probeInfo += ":";
      }
      probeInfo = probeInfo.substr(0, probeInfo.size() - 1);
      face.expressInterest(*client.generateProbeInterest(targetCaItem, probeInfo),
                           bind(&probeCb, _2),
                           bind(&onNackCb),
                           bind(&timeoutCb));
    }
    else {
      std::cerr << "Step " << nStep++ << ": Please type in the identity name you want to get (with CA prefix)\n";
      std::string identityNameStr;
      getline(std::cin, identityNameStr);
      std::cerr << "Step "
                << nStep++ << ": Please type in your expected validity period of your certificate."
                << "Type in a number in unit of hour."
                << " The CA may change the validity period if your expected period is too long.\n";
      std::string periodStr;
      getline(std::cin, periodStr);
      int hours = std::stoi(periodStr);
      face.expressInterest(*client.generateNewInterest(time::system_clock::now(),
                                                       time::system_clock::now() + time::hours(hours),
                                                       Name(identityNameStr)),
                           bind(&newCb, _2),
                           bind(&onNackCb),
                           bind(&timeoutCb));
    }
  }
}


int
main(int argc, char* argv[])
{
  namespace po = boost::program_options;
  std::string configFilePath = std::string(SYSCONFDIR) + "/ndncert/client.conf";
  po::options_description description("General Usage\n ndncert-client [-h] [-f]\n");
  description.add_options()
    ("help,h", "produce help message")
    ("config-file,f", po::value<std::string>(&configFilePath), "config file name");
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
  client.getClientConf().load(configFilePath);
  startApplication();
  face.processEvents();
  return 0;
}

} // namespace ndncert
} // namespace ndn

int main(int argc, char* argv[])
{
  return ndn::ndncert::main(argc, argv);
}
