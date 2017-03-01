/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/**
 * Copyright (c) 2017, Regents of the University of California.
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
#include "logging.hpp"

#include <boost/program_options/options_description.hpp>
#include <boost/program_options/variables_map.hpp>
#include <boost/program_options/parsers.hpp>

namespace ndn {
namespace ndncert {

_LOG_INIT(ndncert.clientTool);

class ClientTool
{
public:
  ClientTool(ClientModule& clientModule)
    : client(clientModule)
  {
  }

  void
  errorCb(const std::string& errorInfo)
  {
    _LOG_TRACE("Error: " << errorInfo);
  }

  void
  validateCb(const shared_ptr<RequestState> state, int& nStep)
  {
    if (state->m_status == ChallengeModule::SUCCESS) {
      _LOG_TRACE("Certificate has already been issued");
      return;
    }

    auto challenge = ChallengeModule::createChallengeModule(state->m_challengeType);
    auto requirementList = challenge->getRequirementForValidate(state->m_status);

    std::cerr << "Step" << nStep++ << ": Please satisfy following instruction(s)" << std::endl;
    for (auto requirement : requirementList) {
      std::cerr << "\t" << requirement << std::endl;
    }
    std::list<std::string> paraList;
    for (size_t i = 0; i < requirementList.size(); i++) {
      std::string tempParam;
      std::cin >> tempParam;
      paraList.push_back(tempParam);
    }
    auto paramJson = challenge->genValidateParamsJson(state->m_status, paraList);
    client.sendValidate(state, paramJson,
                        bind(&ClientTool::validateCb, this, _1, nStep),
                        bind(&ClientTool::errorCb, this, _1));
  }

  void
  selectCb(const shared_ptr<RequestState> state, int& nStep)
  {
    auto challenge = ChallengeModule::createChallengeModule(state->m_challengeType);
    auto requirementList = challenge->getRequirementForValidate(state->m_status);

    std::cerr << "Step" << nStep++ << ": Please satisfy following instruction(s)" << std::endl;
    for (auto item : requirementList) {
      std::cerr << "\t" << item << std::endl;
    }
    std::list<std::string> paraList;
    for (size_t i = 0; i < requirementList.size(); i++) {
      std::string tempParam;
      std::cin >> tempParam;
      paraList.push_back(tempParam);
    }

    auto paramJson = challenge->genValidateParamsJson(state->m_status, paraList);
    client.sendValidate(state, paramJson,
                        bind(&ClientTool::validateCb, this, _1, nStep),
                        bind(&ClientTool::errorCb, this, _1));
  }

  void
  newCb(const shared_ptr<RequestState> state, int& nStep)
  {
    std::cerr << "Step" << nStep++ << ": Please select one challenge from following types." << std::endl;
    for (auto item : state->m_challengeList) {
      std::cerr << "\t" << item << std::endl;
    }
    std::string choice;
    std::cin >> choice;

    auto challenge = ChallengeModule::createChallengeModule(choice);
    auto requirementList = challenge->getRequirementForSelect();
    std::list<std::string> paraList;
    if (requirementList.size() != 0) {
      std::cerr << "Step" << nStep++ << ": Please satisfy following instruction(s)" << std::endl;
      for (auto item : requirementList) {
        std::cerr << "\t" << item << std::endl;
      }
      for (size_t i = 0; i < requirementList.size(); i++) {
        std::string tempParam;
        std::cin >> tempParam;
        paraList.push_back(tempParam);
      }
    }
    auto paramJson = challenge->genSelectParamsJson(state->m_status, paraList);
    client.sendSelect(state, choice, paramJson,
                      bind(&ClientTool::selectCb, this, _1, nStep),
                      bind(&ClientTool::errorCb, this, _1));
  }

public:
  ClientModule& client;
};

int
main(int argc, char* argv[])
{
  namespace po = boost::program_options;
  std::string configFilePath = std::string(SYSCONFDIR) + "/ndncert/client.conf";
  po::options_description description("General Usage\n  ndncert-client [-h] [-f] configFilePath-file\n");
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

  Face face;
  security::v2::KeyChain keyChain;
  ClientModule client(face, keyChain);
  client.getClientConf().load(configFilePath);

  ClientTool tool(client);

  auto caList = client.getClientConf().m_caItems;
  std::cerr << "Index \t CA Namespace \t CA Introduction" << std::endl;
  int count = 0;
  for (auto item : caList) {
    std::cerr << count++ << "\t"
              << item.m_caName << "\t"
              << item.m_caInfo << std::endl;
  }
  std::vector<ClientCaItem> caVector{std::begin(caList), std::end(caList)};
  int nStep = 0;
  std::cerr << "Step" << nStep++ << ": Please type in the CA namespace index that you want to apply" << std::endl;
  std::string caIndexS;
  std::cin >> caIndexS;
  int caIndex = std::stoi(caIndexS);

  BOOST_ASSERT(caIndex <= count);

  auto targetCaItem = caVector[caIndex];
  if (targetCaItem.m_probe != "") {
    std::cerr <<"Step" << nStep++ << ": Probe Requirement-" << targetCaItem.m_probe << std::endl;
    std::string probeInfo;
    std::cin >> probeInfo;
    client.sendProbe(targetCaItem, probeInfo,
                     bind(&ClientTool::newCb, &tool, _1, nStep),
                     bind(&ClientTool::errorCb, &tool, _1));
  }
  else {
    std::cerr <<"Step" << nStep++ << ": Please type in the identity name" << std::endl;
    std::string nameComponent;
    std::cin >> nameComponent;
    Name identityName(targetCaItem.m_caName);
    identityName.append(nameComponent);
    client.sendNew(targetCaItem, identityName,
                   bind(&ClientTool::newCb, &tool, _1, nStep),
                   bind(&ClientTool::errorCb, &tool, _1));
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
