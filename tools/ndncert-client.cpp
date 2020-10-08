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

#include "identity-challenge/challenge-module.hpp"
#include "protocol-detail/info.hpp"
#include "requester.hpp"
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
selectCaProfile(std::string configFilePath);
static void
runProbe(CaProfile profile);
static void
runNew(CaProfile profile, Name identityName);
static void
runChallenge(const std::string& challengeType);

size_t nStep = 1;
Face face;
security::v2::KeyChain keyChain;
shared_ptr<RequesterState> requesterState = nullptr;

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
  for (const auto& r : requirement) {
    results.emplace_back(r, "Please input: " + r);
  }
  captureParams(results);
  return results;
}

static int
captureValidityPeriod()
{
  std::cerr << "\n***************************************\n"
            << "Step " << nStep++
            << ": Please type in your expected validity period of your certificate."
            << " Type the number of hours (168 for week, 730 for month, 8760 for year)."
            << " The CA may reject your application if your expected period is too long." << std::endl;
  while (true) {
    std::string periodStr = "";
    getline(std::cin, periodStr);
    try {
      return std::stoul(periodStr);
    }
    catch (const std::exception& e) {
      std::cerr << "Your input is invalid. Try again: " << std::endl;
    }
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
  auto item = Requester::onCertFetchResponse(reply);
  if (item) {
    keyChain.addCertificate(keyChain.getPib().getIdentity(item->getIdentity()).getKey(item->getKeyName()), *item);
  }
  std::cerr << "\n***************************************\n"
            << "Step " << nStep++
            << ": DONE\nCertificate with Name: " << reply.getName().toUri()
            << "has already been installed to your local keychain" << std::endl
            << "Exit now";
  face.getIoService().stop();
}

static void
challengeCb(const Data& reply)
{
  try {
    Requester::onChallengeResponse(*requesterState, reply);
  }
  catch (const std::exception& e) {
    std::cerr << "Error when decoding challenge step: " << e.what() << std::endl;
    exit(1);
  }
  if (requesterState->m_status == Status::SUCCESS) {
    std::cerr << "Certificate has already been issued, downloading certificate..." << std::endl;
    face.expressInterest(*Requester::genCertFetchInterest(*requesterState), bind(&certFetchCb, _2),
                         bind(&onNackCb), bind(&timeoutCb));
    return;
  }

  runChallenge(requesterState->m_challengeType);
}

static void
newCb(const Data& reply)
{
  std::list<std::string> challengeList;
  try {
    challengeList = Requester::onNewRenewRevokeResponse(*requesterState, reply);
  }
  catch (const std::exception& e) {
    std::cerr << "Error on decoding NEW step reply because: " << e.what() << std::endl;
    exit(1);
  }

  size_t challengeIndex = 0;
  if (challengeList.size() < 1) {
    std::cerr << "There is no available challenge provided by the CA. Exit" << std::endl;
    exit(1);
  }
  else if (challengeList.size() > 1) {
    std::cerr << "\n***************************************\n"
              << "Step " << nStep++
              << ": CHALLENGE SELECTION" << std::endl;
    size_t count = 0;
    std::string choice = "";
    for (auto item : challengeList) {
      std::cerr << "> Index: " << count++ << std::endl
                << ">> Challenge:" << item << std::endl;
    }
    std::cerr << "Please type in the challenge index that you want to perform:" << std::endl;
    while (true) {
      getline(std::cin, choice);
      try {
        challengeIndex = std::stoul(choice);
      }
      catch (const std::exception& e) {
        std::cerr << "Your input is not valid. Try again:" << std::endl;
        continue;
      }
      if (challengeIndex >= count) {
        std::cerr << "Your input index is out of range. Try again:" << std::endl;
        continue;
      }
      break;
    }
  }
  auto it = challengeList.begin();
  std::advance(it, challengeIndex);
  unique_ptr<ChallengeModule> challenge = ChallengeModule::createChallengeModule(*it);
  if (challenge != nullptr) {
    std::cerr << "The challenge has been selected: " << *it << std::endl;
    runChallenge(*it);
  }
  else {
    std::cerr << "Error. Cannot load selected Challenge Module. Exit." << std::endl;
    exit(1);
  }
}

static void
InfoCb(const Data& reply, const Name& certFullName)
{
  boost::optional<CaProfile> profile;
  try {
    if (certFullName.empty()) {
      profile = Requester::onCaProfileResponse(reply);
    }
    else {
      profile = Requester::onCaProfileResponseAfterRedirection(reply, certFullName);
    }
  }
  catch (const std::exception& e) {
    std::cerr << "The fetched CA information cannot be used because: " << e.what() << std::endl;
    return;
  }
  std::cerr << "\n***************************************\n"
            << "Step " << nStep++
            << ": Will use a new trust anchor, please double check the identity info:" << std::endl
            << "> New CA name: " << profile->m_caPrefix.toUri() << std::endl
            << "> This trust anchor information is signed by: " << reply.getSignature().getKeyLocator() << std::endl
            << "> The certificate: " << profile->m_cert << std::endl
            << "Do you trust the information? Type in YES or NO" << std::endl;

  std::string answer;
  getline(std::cin, answer);
  boost::algorithm::to_lower(answer);
  if (answer == "yes") {
    std::cerr << "You answered YES: new CA " << profile->m_caPrefix.toUri() << " will be used" << std::endl;
    runProbe(*profile);
    // client.getClientConf().save(std::string(SYSCONFDIR) + "/ndncert/client.conf");
  }
  else {
    std::cerr << "You answered NO: new CA " << profile->m_caPrefix.toUri() << " will not be used" << std::endl;
    exit(0);
  }
}

static void
probeCb(const Data& reply, CaProfile profile)
{
  std::vector<Name> names;
  std::vector<Name> redirects;
  Requester::onProbeResponse(reply, profile, names, redirects);
  size_t count = 0;
  std::cerr << "\n***************************************\n"
            << "Step " << nStep++
            << ": You can either select one of the following names suggested by the CA: " << std::endl;
  for (const auto& name : names) {
    std::cerr << "> Index: " << count++ << std::endl
              << ">> Suggested name: " << name.toUri() << std::endl;
  }
  std::cerr << "\nOr choose another trusted CA suggested by the CA: " << std::endl;
  for (const auto& redirect : redirects) {
    std::cerr << "> Index: " << count++ << std::endl
              << ">> Suggested CA: " << security::v2::extractIdentityFromCertName(redirect.getPrefix(-1)) << std::endl;
  }
  std::cerr << "Please type in the index of your choice:" << std::endl;
  size_t index = 0;
  try {
    std::string input;
    getline(std::cin, input);
    index = std::stoul(input);
  }
  catch (const std::exception& e) {
    std::cerr << "Your input is Invalid. Exit" << std::endl;
    exit(0);
  }
  if (index >= names.size() + redirects.size()) {
    std::cerr << "Your input is not an existing index. Exit" << std::endl;
    return;
  }
  if (index < names.size()) {
    //names
    std::cerr << "You selected name: " << names[index].toUri() << std::endl;
    runNew(profile, names[index]);
  }
  else {
    //redirects
    auto redirectedCaFullName = redirects[index - names.size()];
    auto redirectedCaName = security::v2::extractIdentityFromCertName(redirectedCaFullName.getPrefix(-1));
    std::cerr << "You selected to be redirected to CA: " << redirectedCaName.toUri() << std::endl;
    face.expressInterest(
        *Requester::genCaProfileDiscoveryInterest(redirectedCaName),
        [&](const Interest&, const Data& data) {
          auto fetchingInterest = Requester::genCaProfileInterestFromDiscoveryResponse(data);
          face.expressInterest(*fetchingInterest,
                               bind(&InfoCb, _2, redirectedCaFullName),
                               bind(&onNackCb),
                               bind(&timeoutCb));
        },
        bind(&onNackCb),
        bind(&timeoutCb));
  }
}

static void
selectCaProfile(std::string configFilePath)
{
  RequesterCaCache caCache;
  try {
    caCache.load(configFilePath);
  }
  catch (const std::exception& e) {
    std::cerr << "Cannot load the configuration file: " << e.what() << std::endl;
    exit(1);
  }
  size_t count = 0;
  std::cerr << "***************************************\n"
            << "Step " << nStep++ << ": CA SELECTION" << std::endl;
  for (auto item : caCache.m_caItems) {
    std::cerr << "> Index: " << count++ << std::endl
              << ">> CA prefix:" << item.m_caPrefix << std::endl
              << ">> Introduction: " << item.m_caInfo << std::endl;
  }
  std::cerr << "Please type in the CA's index that you want to apply or type in NONE if your expected CA is not in the list:\n";

  std::string caIndexS, caIndexSLower;
  getline(std::cin, caIndexS);
  caIndexSLower = caIndexS;
  boost::algorithm::to_lower(caIndexSLower);
  if (caIndexSLower == "none") {
    std::cerr << "\n***************************************\n"
              << "Step " << nStep << ": ADD NEW CA\nPlease type in the CA's Name:" << std::endl;
    std::string expectedCAName;
    getline(std::cin, expectedCAName);
    face.expressInterest(
        *Requester::genCaProfileDiscoveryInterest(Name(expectedCAName)),
        [&](const Interest&, const Data& data) {
          auto fetchingInterest = Requester::genCaProfileInterestFromDiscoveryResponse(data);
          face.expressInterest(*fetchingInterest,
                               bind(&InfoCb, _2, Name()),
                               bind(&onNackCb),
                               bind(&timeoutCb));
        },
        bind(&onNackCb),
        bind(&timeoutCb));
  }
  else {
    size_t caIndex;
    try {
      caIndex = std::stoul(caIndexS);
    }
    catch (const std::exception& e) {
      std::cerr << "Your input is neither NONE nor a valid index. Exit" << std::endl;
      return;
    }
    if (caIndex >= count) {
      std::cerr << "Your input is not an existing index. Exit" << std::endl;
      return;
    }
    auto itemIterator = caCache.m_caItems.cbegin();
    std::advance(itemIterator, caIndex);
    auto targetCaItem = *itemIterator;
    runProbe(targetCaItem);
  }
}

static void
runProbe(CaProfile profile)
{
  std::cerr << "\n***************************************\n"
            << "Step " << nStep++
            << ": Do you know your identity name to be certified by CA "
            << profile.m_caPrefix.toUri()
            << " already? Type in YES or NO" << std::endl;
  bool validAnswer = false;
  while (!validAnswer) {
    std::string answer;
    getline(std::cin, answer);
    boost::algorithm::to_lower(answer);
    if (answer == "yes") {
      validAnswer = true;
      std::cerr << "You answered YES" << std::endl;
      std::cerr << "\n***************************************\n"
                << "Step " << nStep++
                << ": Please type in the full identity name you want to get (with CA prefix "
                << profile.m_caPrefix.toUri()
                << "):" << std::endl;
      std::string identityNameStr;
      getline(std::cin, identityNameStr);
      runNew(profile, Name(identityNameStr));
    }
    else if (answer == "no") {
      validAnswer = true;
      std::cerr << "You answered NO" << std::endl;
      std::cerr << "\n***************************************\n"
                << "Step " << nStep++ << ": Please provide information for name assignment" << std::endl;
      auto capturedParams = captureParams(profile.m_probeParameterKeys);
      face.expressInterest(*Requester::genProbeInterest(profile, std::move(capturedParams)),
                           bind(&probeCb, _2, profile), bind(&onNackCb), bind(&timeoutCb));
    }
    else {
      std::cerr << "Invalid answer. Type in YES or NO" << std::endl;
    }
  }
}

static void
runNew(CaProfile profile, Name identityName)
{
  int validityPeriod = captureValidityPeriod();
  auto now = time::system_clock::now();
  std::cerr << "The validity period of your certificate will be: " << validityPeriod << " hours" << std::endl;
  requesterState = make_shared<RequesterState>(keyChain, profile, RequestType::NEW);
  auto interest = Requester::genNewInterest(*requesterState, identityName, now, now + time::hours(validityPeriod));
  if (interest != nullptr) {
    face.expressInterest(*interest, bind(&newCb, _2), bind(&onNackCb), bind(&timeoutCb));
  }
  else {
    std::cerr << "Cannot generate the Interest for NEW step. Exit" << std::endl;
  }
}

static void
runChallenge(const std::string& challengeType)
{
  auto requirement = Requester::selectOrContinueChallenge(*requesterState, challengeType);
  if (requirement.size() > 0) {
    std::cerr << "\n***************************************\n"
              << "Step " << nStep
              << ": Please provide parameters used for Identity Verification Challenge" << std::endl;
    captureParams(requirement);
  }
  face.expressInterest(*Requester::genChallengeInterest(*requesterState, std::move(requirement)),
                       bind(&challengeCb, _2), bind(&onNackCb), bind(&timeoutCb));
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
  if (requesterState) {
    Requester::endSession(*requesterState);
  }
  face.getIoService().stop();
  exit(1);
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
  description.add_options()("help,h", "produce help message")("config-file,c", po::value<std::string>(&configFilePath), "configuration file name");
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
  selectCaProfile(configFilePath);
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
