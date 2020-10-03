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
#include "requester.hpp"
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
selectCaProfile(std::string configFilePath);
static void
runProbe(CaProfile profile);
static void
runNew(CaProfile profile, Name identityName);
static void
runChallenge(const std::string& challengeType);
static void
startApplication(std::string configFilePath);

int nStep;
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
  std::cerr << "Step " << nStep++
            << ": Please type in your expected validity period of your certificate."
            << " Type the number of hours (168 for week, 730 for month, 8760 for year)."
            << " The CA may reject your application if your expected period is too long." << std::endl;
  while (true) {
    std::string periodStr = "";
    getline(std::cin, periodStr);
    try {
      int validityPeriod = std::stoi(periodStr);
      if (validityPeriod < 0) {
          BOOST_THROW_EXCEPTION(std::runtime_error(""));
      }
      return validityPeriod;
    }
    catch (const std::exception &e) {
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
  std::cerr << "Step " << nStep++
            << ": DONE! Certificate has already been installed to local keychain\n"
            << "Certificate Name: " << reply.getName().toUri() << std::endl;
}

static void
challengeCb(const Data& reply)
{
  try {
    Requester::onChallengeResponse(*requesterState, reply);
  } catch (const std::exception& e) {
    std::cerr << "Error when decoding challenge step: " << e.what() << std::endl;
    exit(1);
  }
  if (requesterState->m_status == Status::SUCCESS) {
    std::cerr << "Certificate has already been issued, downloading certificate... \n";
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
  } catch (const std::exception& e) {
    std::cerr << "Error on decoding NEW step reply because: " << e.what() << std::endl;
    exit(1);
  }

  int challengeIndex = 0;
  if (challengeList.size() < 1) {
    std::cerr << "There is no available challenge provided by the CA. Exit" << std::endl;
    exit(1);
  }
  else if (challengeList.size() > 1) {
    int count = 0;
    std::string choice = "";
    std::cerr << "Step " << nStep++ << ": Please type in the challenge index that you want to perform\n";
    count = 0;
    for (auto item : challengeList) {
      std::cerr << "\t" << count++ << " : " << item << std::endl;
    }
    while (true) {
        getline(std::cin, choice);
        try {
            challengeIndex = std::stoi(choice);
        }
        catch (const std::exception &e) {
            std::cerr << "Your input is not valid. Try again:" << std::endl;
            continue;
        }
        if (challengeIndex < 0 || challengeIndex >= count) {
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
InfoCb(const Data& reply)
{
  CaProfile profile;
  try {
    auto profileOpt = Requester::onCaProfileResponse(reply);
    if (!profileOpt) {
        BOOST_THROW_EXCEPTION(std::runtime_error("Invalid reply"));
    }
    profile = *profileOpt;
  } catch(const std::exception& e) {
      std::cerr << "The fetched CA information cannot be used because: "<< e.what() << std::endl;
      return;
  }

  std::cerr << "Will use a new trust anchor, please double check the identity info: \n"
            << "This trust anchor information is signed by " << reply.getSignature().getKeyLocator()
            << std::endl
            << "The certificate is " << profile.m_cert << std::endl
            << "Do you trust the information? Type in YES or NO" << std::endl;

  std::string answer;
  getline(std::cin, answer);
  boost::algorithm::to_lower(answer);
  if (answer == "yes") {
    std::cerr << "You answered YES: new CA will be used" << std::endl;
    runProbe(profile);
    // client.getClientConf().save(std::string(SYSCONFDIR) + "/ndncert/client.conf");
  }
  else {
    std::cerr << "You answered NO: new CA will not be used" << std::endl;
    exit(0);
  }
}

static void
probeCb(const Data& reply, CaProfile profile)
{
  std::vector<Name> names;
  std::vector<Name> redirects;
  Requester::onProbeResponse(reply, profile, names, redirects);
  int count = 0;
  std::cerr << "Here is CA's suggested names: " << std::endl;
  for (const auto& name : names) {
      std::cerr << count ++ << ": " << name.toUri() << std::endl;
  }
  std::cerr << "Here is CA's suggested redirects to other CAs: " << std::endl;
  for (const auto& redirect : redirects) {
      std::cerr << count ++ << ": " << redirect.toUri() << std::endl;
  }
  int index;
  try {
    std::string input;
    getline(std::cin, input);
    index = std::stoi(input);
  }
  catch (const std::exception& e) {
    std::cerr << "Your input is Invalid. Exit" << std::endl;
    exit(0);
  }
  if (index < 0 || index >= names.size() + redirects.size()) {
    std::cerr << "Your input is not an existing index. Exit" << std::endl;
    return;
  }
  if (index < names.size()) {
      //names
      std::cerr << "You selected name: " << names[index].toUri() << std::endl;
      runNew(profile, names[index]);
  } else {
      //redirects
      std::cerr << "You selected redirects with certificate: " << redirects[index - names.size()].toUri() << std::endl;
      face.expressInterest(*Requester::genCaProfileInterest(redirects[index - names.size()]),
                           bind(&InfoCb, _2), bind(&onNackCb), bind(&timeoutCb));
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
  int count = 0;
  for (auto item : caCache.m_caItems) {
    std::cerr << "***************************************\n"
              << "Index: " << count++ << "\n"
              << "CA prefix:" << item.m_caPrefix << "\n"
              << "Introduction: " << item.m_caInfo << "\n"
              << "***************************************\n";
  }
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
    face.expressInterest(*Requester::genCaProfileInterest(Name(expectedCAName)),
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
    auto itemIterator = caCache.m_caItems.cbegin();
    std::advance(itemIterator, caIndex);
    auto targetCaItem = *itemIterator;
    runProbe(targetCaItem);
  }
}

static void runProbe(CaProfile profile)
{
    std::cerr << "Do you have the identity name already? Type in YES or NO" << std::endl;
    bool validAnswer = false;
    while (!validAnswer) {
        std::string answer;
        getline(std::cin, answer);
        boost::algorithm::to_lower(answer);
        if (answer == "yes") {
            validAnswer = true;
            std::cerr << "You answered YES: " << std::endl;
            std::cerr << "Step " << nStep++ << ": Please type in the full identity name you want to get (with CA prefix)\n";
            std::string identityNameStr;
            getline(std::cin, identityNameStr);
            runNew(profile, Name(identityNameStr));
        } else if (answer == "no") {
            validAnswer = true;
            std::cerr << "You answered NO: new CA will not be used" << std::endl;
            std::cerr << "Step " << nStep++ << ": Please provide information for name assignment" << std::endl;
            auto capturedParams = captureParams(profile.m_probeParameterKeys);
            face.expressInterest(*Requester::genProbeInterest(profile, std::move(capturedParams)),
                                 bind(&probeCb, _2, profile), bind(&onNackCb), bind(&timeoutCb));
        } else {
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
      std::cerr << "Step " << nStep++ << ": Please provide parameters used for Identity Verification Challenge\n";
      captureParams(requirement);
  }
  face.expressInterest(*Requester::genChallengeInterest(*requesterState, std::move(requirement)),
                         bind(&challengeCb, _2), bind(&onNackCb), bind(&timeoutCb));

}


static void
startApplication(std::string configFilePath)
{
  selectCaProfile(configFilePath);
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
  description.add_options()
      ("help,h", "produce help message")
      ("config-file,c", po::value<std::string>(&configFilePath), "configuration file name");
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
  startApplication(configFilePath);
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
