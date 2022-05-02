/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2017-2022, Regents of the University of California.
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

#include <ndn-cxx/face.hpp>
#include <ndn-cxx/security/key-chain.hpp>
#include <ndn-cxx/security/verification-helpers.hpp>

#include <boost/asio.hpp>
#include <boost/program_options/options_description.hpp>
#include <boost/program_options/parsers.hpp>
#include <boost/program_options/variables_map.hpp>

#include <iostream>

namespace ndncert::requester {

static void
selectCaProfile(const std::string& configFilePath);

static void
runProbe(CaProfile profile);

static void
runNew(CaProfile profile, Name identityName);

static void
runChallenge(const std::string& challengeType);

static size_t nStep = 1;
static const std::string defaultChallenge = "email";
static ndn::Face face;
static ndn::KeyChain keyChain;
static std::shared_ptr<Request> requesterState;
static std::shared_ptr<std::multimap<std::string, std::string>> capturedProbeParams;
static std::shared_ptr<Certificate> trustedCert;
static Name newlyCreatedIdentityName;
static Name newlyCreatedKeyName;

static void
captureParams(std::multimap<std::string, std::string>& requirement)
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

static std::multimap<std::string, std::string>
captureParams(const std::vector<std::string>& requirement)
{
  std::multimap<std::string, std::string> results;
  for (const auto& r : requirement) {
    results.emplace(r, "Please input: " + r);
  }
  captureParams(results);
  return results;
}

static int
captureValidityPeriod(time::hours maxValidityPeriod)
{
  std::cerr << "\n***************************************\n"
            << "Step " << nStep++
            << ": Please type in your expected validity period of your certificate."
            << " Type the number of hours (168 for week, 730 for month, 8760 for year)."
            << " The CA may reject your application if your expected period is too long."
            << " The maximum validity period allowed by this CA is " << maxValidityPeriod << "."<< std::endl;
  size_t count = 0;
  while (count < 3) {
    std::string periodStr = "";
    getline(std::cin, periodStr);
    try {
      return std::stoul(periodStr);
    }
    catch (const std::exception&) {
      std::cerr << "Your input is invalid. Try again: " << std::endl;
      count++;
    }
  }
  std::cerr << "Invalid input for too many times, exit. " << std::endl;
  exit(1);
}

static Name
captureKeyName(ndn::security::pib::Identity& identity, ndn::security::pib::Key& defaultKey)
{
  size_t count = 0;
  std::cerr << "***************************************\n"
            << "Step " << nStep++ << ": KEY SELECTION" << std::endl;
  for (const auto& key : identity.getKeys()) {
    std::cerr << "> Index: " << count++ << std::endl
              << ">> Key Name:";
    if (key == defaultKey) {
      std::cerr << "  +->* ";
    }
    else {
      std::cerr << "  +->  ";
    }
    std::cerr << key.getName() << std::endl;
  }

  std::cerr << "Please type in the key's index that you want to certify or type in NEW if you want to certify a new key:\n";
  std::string indexStr = "";
  std::string indexStrLower = "";
  size_t keyIndex;
  getline(std::cin, indexStr);

  indexStrLower = indexStr;
  boost::algorithm::to_lower(indexStrLower);
  if (indexStrLower == "new") {
    auto newlyCreatedKey = keyChain.createKey(identity);
    newlyCreatedKeyName = newlyCreatedKey.getName();
    std::cerr << "New key generated: " << newlyCreatedKeyName << std::endl;
    return newlyCreatedKeyName;
  }
  else {
    try {
      keyIndex = std::stoul(indexStr);
    }
    catch (const std::exception&) {
      std::cerr << "Your input is neither NEW nor a valid index. Exit" << std::endl;
      exit(1);
    }

    if (keyIndex >= count) {
      std::cerr << "Your input is not an existing index. Exit" << std::endl;
      exit(1);
    }
    else {
      auto itemIterator = identity.getKeys().begin();
      std::advance(itemIterator, keyIndex);
      auto targetKeyItem = *itemIterator;
      return targetKeyItem.getName();
    }
  }
}

[[noreturn]] static void
onNackCb()
{
  std::cerr << "Got NACK\n";
  exit(1);
}

static void
timeoutCb()
{
  std::cerr << "Interest timeout\n";
}

static void
certFetchCb(const Data& reply)
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
  face.getIoService().stop();
}

static void
challengeCb(const Data& reply)
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
                         [] (const auto&, const auto& data) { certFetchCb(data); },
                         [] (auto&&...) { onNackCb(); },
                         [] (auto&&...) { timeoutCb(); });
    return;
  }
  runChallenge(requesterState->m_challengeType);
}

static void
newCb(const Data& reply)
{
  std::list<std::string> challengeList;
  try {
    challengeList = requesterState->onNewRenewRevokeResponse(reply);
  }
  catch (const std::exception& e) {
    std::cerr << "Error on decoding NEW step reply because: " << e.what() << std::endl;
    exit(1);
  }

  size_t challengeIndex = 0;
  if (challengeList.empty()) {
    std::cerr << "There is no available challenge provided by the CA. Exit" << std::endl;
    exit(1);
  }

  auto item = std::find(challengeList.begin(), challengeList.end(), defaultChallenge);
  if (item != challengeList.end()) {
    runChallenge(defaultChallenge);
  }
  else {
    // default challenge not available
    std::cerr << "\n***************************************\n"
              << "Step " << nStep++
              << ": CHALLENGE SELECTION" << std::endl;
    size_t count = 0;
    std::string choice = "";
    for (const auto& item : challengeList) {
      std::cerr << "> Index: " << count++ << std::endl
                << ">> Challenge: " << item << std::endl;
    }
    std::cerr << "Please type in the index of the challenge that you want to perform:" << std::endl;
    size_t inputCount = 0;
    while (inputCount < 3) {
      getline(std::cin, choice);
      try {
        challengeIndex = std::stoul(choice);
      }
      catch (const std::exception&) {
        std::cerr << "Your input is not valid. Try again:" << std::endl;
        inputCount++;
        continue;
      }
      if (challengeIndex >= count) {
        std::cerr << "Your input index is out of range. Try again:" << std::endl;
        inputCount++;
        continue;
      }
      break;
    }
    if (inputCount == 3) {
      std::cerr << "Invalid input for too many times, exit. " << std::endl;
      exit(1);
    }

    auto it = challengeList.begin();
    std::advance(it, challengeIndex);
    std::cerr << "The challenge has been selected: " << *it << std::endl;
    runChallenge(*it);
  }
}

static void
infoCb(const Data& reply, const Name& certFullName)
{
  std::optional<CaProfile> profile;
  try {
    if (certFullName.empty()) {
      if (trustedCert && !ndn::security::verifySignature(reply, *trustedCert)) {
        NDN_THROW(std::runtime_error("Cannot verify replied Data packet signature."));
      }
      profile = Request::onCaProfileResponse(reply);
    }
    else {
      profile = Request::onCaProfileResponseAfterRedirection(reply, certFullName);
    }
  }
  catch (const std::exception& e) {
    std::cerr << "The fetched CA information cannot be used because: " << e.what() << std::endl;
    return;
  }
  if (!trustedCert)
  {
    std::cerr << "\n***************************************\n"
              << "Step " << nStep++
              << ": Will use the following CA, please double check the identity info:" << std::endl
              << "> CA name: " << profile->caPrefix << std::endl
              << "> This CA information is signed by: " << reply.getSignatureInfo().getKeyLocator() << std::endl
              << "> The certificate:" << std::endl << *profile->cert << std::endl
              << "Do you trust the information? Type in YES or NO" << std::endl;

    std::string answer;
    getline(std::cin, answer);
    boost::algorithm::to_lower(answer);
    if (answer == "yes") {
      std::cerr << "You answered YES: new CA " << profile->caPrefix << " will be used" << std::endl;
      trustedCert = profile->cert;
      runProbe(*profile);
    }
    else {
      std::cerr << "You answered NO: new CA " << profile->caPrefix << " will not be used" << std::endl;
      exit(0);
    }
  }
  else {
    runProbe(*profile);
  }
}

static void
probeCb(const Data& reply, CaProfile profile)
{
  std::vector<std::pair<Name, int>> names;
  std::vector<Name> redirects;
  try {
    Request::onProbeResponse(reply, profile, names, redirects);
  }
  catch (const std::exception& e) {
    std::cerr << "The probed CA response cannot be used because: " << e.what() << std::endl;
    exit(1);
  }

  size_t count = 0;
  Name selectedName;
  Name redirectedCaFullName;
  // always prefer redirection over direct assignment
  if (!redirects.empty()) {
    if (redirects.size() < 2) {
      redirectedCaFullName = redirects.front();
    }
    else {
      std::cerr << "\n***************************************\n"
                << "Step " << nStep++
                << " Choose another trusted CA suggested by the CA: " << std::endl;
      for (const auto& redirect : redirects) {
        std::cerr << "> Index: " << count++ << std::endl
                  << ">> Suggested CA: " << ndn::security::extractIdentityFromCertName(redirect.getPrefix(-1))
                  << std::endl;
      }
      std::cerr << "Please type in the index of your choice:" << std::endl;
      size_t index = 0;
      try {
        std::string input;
        getline(std::cin, input);
        index = std::stoul(input);
      }
      catch (const std::exception&) {
        std::cerr << "Your input is Invalid. Exit" << std::endl;
        exit(1);
      }
      if (index >= redirects.size()) {
        std::cerr << "Your input is not an existing index. Exit" << std::endl;
        exit(1);
      }
      redirectedCaFullName = redirects[index];
    }
    auto redirectedCaName = ndn::security::extractIdentityFromCertName(redirectedCaFullName.getPrefix(-1));
    std::cerr << "You will be redirected to CA: " << redirectedCaName << std::endl;
    face.expressInterest(
        *Request::genCaProfileDiscoveryInterest(redirectedCaName),
        [&, redirectedCaFullName] (const auto&, const auto& data) {
          auto fetchingInterest = Request::genCaProfileInterestFromDiscoveryResponse(data);
          face.expressInterest(*fetchingInterest,
                              [=] (const auto&, const auto& data2) { infoCb(data2, redirectedCaFullName); },
                              [] (auto&&...) { onNackCb(); },
                              [] (auto&&...) { timeoutCb(); });
        },
        [] (auto&&...) { onNackCb(); },
        [] (auto&&...) { timeoutCb(); });
  }
  else if (!names.empty()) {
    if (names.size() < 2) {
      selectedName = names.front().first;
    }
    else {
      std::cerr << "\n***************************************\n"
                << "Step " << nStep++
                << ": You can either select one of the following names suggested by the CA: " << std::endl;
      for (const auto& name : names) {
        std::cerr << "> Index: " << count++ << std::endl
                  << ">> Suggested name: " << name.first << std::endl
                  << ">> Corresponding max suffix length: " << name.second << std::endl;
      }
      std::cerr << "Please type in the index of your choice:" << std::endl;
      size_t index = 0;
      try {
        std::string input;
        getline(std::cin, input);
        index = std::stoul(input);
      }
      catch (const std::exception&) {
        std::cerr << "Your input is invalid. Exit" << std::endl;
        exit(1);
      }
      if (index >= names.size()) {
        std::cerr << "Your input is not an existing index. Exit" << std::endl;
        exit(1);
      }
      selectedName = names[index].first;
    }
    std::cerr << "You are applying for name: " << selectedName << std::endl;
    runNew(profile, selectedName);
  }
  else {
    std::cerr << "Neither name assignment nor redirection is available, exit." << std::endl;
    exit(1);
  }
}

static void
selectCaProfile(const std::string& configFilePath)
{
  ProfileStorage profileStorage;
  try {
    profileStorage.load(configFilePath);
  }
  catch (const std::exception& e) {
    std::cerr << "Cannot load the configuration file: " << e.what() << std::endl;
    exit(1);
  }
  size_t count = 0;
  std::cerr << "***************************************\n"
            << "Step " << nStep++ << ": CA SELECTION" << std::endl;
  for (const auto& item : profileStorage.getKnownProfiles()) {
    std::cerr << "> Index: " << count++ << std::endl
              << ">> CA prefix:" << item.caPrefix << std::endl
              << ">> Introduction: " << item.caInfo << std::endl;
  }
  std::cerr << "Please type in the CA's index that you want to apply or type in NONE if your expected CA is not in the list:\n";

  std::string caIndexS, caIndexSLower;
  getline(std::cin, caIndexS);
  caIndexSLower = caIndexS;
  boost::algorithm::to_lower(caIndexSLower);
  Name selectedCaName;
  if (caIndexSLower == "none") {
    std::cerr << "\n***************************************\n"
              << "Step " << nStep << ": ADD NEW CA\nPlease type in the CA's Name:" << std::endl;
    std::string targetCaName;
    getline(std::cin, targetCaName);
    try {
      selectedCaName = Name(targetCaName);
    }
    catch (const std::exception&) {
      std::cerr << "Your input is not a valid name. Exit" << std::endl;
      exit(1);
    }
  }
  else {
    size_t caIndex;
    try {
      caIndex = std::stoul(caIndexS);
    }
    catch (const std::exception&) {
      std::cerr << "Your input is neither NONE nor a valid index. Exit" << std::endl;
      exit(1);
    }
    if (caIndex >= count) {
      std::cerr << "Your input is not an existing index. Exit" << std::endl;
      exit(1);
    }
    auto itemIterator = profileStorage.getKnownProfiles().cbegin();
    std::advance(itemIterator, caIndex);
    auto targetCaItem = *itemIterator;
    trustedCert = targetCaItem.cert;
    selectedCaName = targetCaItem.caPrefix;
  }
  face.expressInterest(
    *Request::genCaProfileDiscoveryInterest(selectedCaName),
    [&] (const auto&, const auto& data) {
      auto fetchingInterest = Request::genCaProfileInterestFromDiscoveryResponse(data);
      face.expressInterest(*fetchingInterest,
                            [] (const auto&, const auto& data2) { infoCb(data2, {}); },
                            [] (auto&&...) { onNackCb(); },
                            [] (auto&&...) { timeoutCb(); });
    },
    [] (auto&&...) { onNackCb(); },
    [] (auto&&...) { timeoutCb(); });
}

static void
runProbe(CaProfile profile)
{
  if (!capturedProbeParams) {
    std::cerr << "\n***************************************\n"
          << "Step " << nStep++ << ": Please provide information for name assignment" << std::endl;
    auto captured = captureParams(profile.probeParameterKeys);
    auto it = captured.find(defaultChallenge);
    if (it != captured.end()) {
      it->second = boost::algorithm::to_lower_copy(it->second);
    }
    capturedProbeParams = std::make_shared<std::multimap<std::string, std::string>>(captured);
  }
  face.expressInterest(*Request::genProbeInterest(profile, std::move(*capturedProbeParams)),
                        [profile] (const auto&, const auto& data) { probeCb(data, profile); },
                        [] (auto&&...) { onNackCb(); },
                        [] (auto&&...) { timeoutCb(); });
}

static void
runNew(CaProfile profile, Name identityName)
{
  int validityPeriod = captureValidityPeriod(time::duration_cast<time::hours>(profile.maxValidityPeriod));
  auto now = time::system_clock::now();
  std::cerr << "The validity period of your certificate will be: " << validityPeriod << " hours" << std::endl;
  requesterState = std::make_shared<Request>(keyChain, profile, RequestType::NEW);

  // generate a newly key pair or choose an existing key
  const auto& pib = keyChain.getPib();
  ndn::security::pib::Identity identity;
  ndn::security::pib::Key defaultKey;
  try {
    identity = pib.getIdentity(identityName);
  }
  catch (const ndn::security::Pib::Error&) {
    identity = keyChain.createIdentity(identityName);
    newlyCreatedIdentityName = identity.getName();
  }
  try {
    defaultKey = identity.getDefaultKey();
  }
  catch (const ndn::security::Pib::Error&) {
    defaultKey = keyChain.createKey(identity);
    newlyCreatedKeyName = defaultKey.getName();
  }

  Name keyName;
  if (newlyCreatedIdentityName.empty()) {
    keyName = captureKeyName(identity, defaultKey);
  }
  else {
    keyName = defaultKey.getName();
  }
  auto interest = requesterState->genNewInterest(keyName, now, now + time::hours(validityPeriod));
  if (interest != nullptr) {
    face.expressInterest(*interest,
                         [] (const auto&, const auto& data) { newCb(data); },
                         [] (auto&&...) { onNackCb(); },
                         [] (auto&&...) { timeoutCb(); });
  }
  else {
    std::cerr << "Cannot generate the Interest for NEW step. Exit" << std::endl;
  }
}

static void
runChallenge(const std::string& challengeType)
{
  std::multimap<std::string, std::string> requirement;
  try {
    requirement = requesterState->selectOrContinueChallenge(challengeType);
  }
  catch (const std::exception& e) {
    std::cerr << "Error. Cannot successfully load the Challenge Module with error: " << e.what()
              << "\nExit." << std::endl;
    exit(1);
  }
  if (!requirement.empty()) {
    if (requesterState->m_status == Status::BEFORE_CHALLENGE && challengeType == defaultChallenge) {
      requirement.find(challengeType)->second = capturedProbeParams->find(defaultChallenge)->second;
    }
    else {
      std::cerr << "\n***************************************\n"
          << "Step " << nStep
          << ": Please provide parameters used for Identity Verification Challenge" << std::endl;
      captureParams(requirement);
    }
  }
  face.expressInterest(*requesterState->genChallengeInterest(std::move(requirement)),
                       [] (const auto&, const auto& data) { challengeCb(data); },
                       [] (auto&&...) { onNackCb(); },
                       [] (auto&&...) { timeoutCb(); });
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
    if (!newlyCreatedIdentityName.empty()) {
      auto identity = keyChain.getPib().getIdentity(newlyCreatedIdentityName);
      keyChain.deleteIdentity(identity);
    }
    else if (!newlyCreatedKeyName.empty()) {
      auto identity = keyChain.getPib().getIdentity(ndn::security::extractIdentityFromKeyName(newlyCreatedKeyName));
      keyChain.deleteKey(identity, identity.getKey(newlyCreatedKeyName));
    }
  }
  face.getIoService().stop();
  exit(1);
}

static int
main(int argc, char* argv[])
{
  boost::asio::signal_set terminateSignals(face.getIoService());
  terminateSignals.add(SIGINT);
  terminateSignals.add(SIGTERM);
  terminateSignals.async_wait(handleSignal);

  namespace po = boost::program_options;
  std::string configFilePath = std::string(NDNCERT_SYSCONFDIR) + "/ndncert/client.conf";
  po::options_description description("Usage: ndncert-client [-h] [-c FILE]\n");
  description.add_options()
    ("help,h", "produce help message")
    ("config-file,c", po::value<std::string>(&configFilePath), "configuration file name")
    ;
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

} // namespace ndncert::requester

int
main(int argc, char* argv[])
{
  return ndncert::requester::main(argc, argv);
}
