//
// Created by Tyler on 10/6/20.
//

#include "assignment-hash.hpp"
#include <ndn-cxx/util/sha256.hpp>

namespace ndn {
namespace ndncert {

_LOG_INIT(ndncert.assignment.hash);

NDNCERT_REGISTER_FUNCFACTORY(AssignmentHash, "hash");

AssignmentHash::AssignmentHash()
    : NameAssignmentFuncFactory("hash")
{
}

NameAssignmentFunc
AssignmentHash::getFunction(const std::string &factoryParam) {
    std::list<std::string> paramList;
    size_t index = 0, startIndex = 0;
    while ((index = factoryParam.find("/", startIndex)) != std::string::npos) {
        auto component = factoryParam.substr(startIndex, index - startIndex);
        if (!component.empty()) {
            paramList.push_back(component);
        }
        startIndex = index + 1;
    }
    if (startIndex != factoryParam.size()) {
        paramList.push_back(factoryParam.substr(startIndex));
    }
    return HashAssignmentFunc(paramList);
}

AssignmentHash::HashAssignmentFunc::HashAssignmentFunc(std::list<std::string> paramList)
    : m_paramList(std::move(paramList))
{}

std::vector<PartialName>
AssignmentHash::HashAssignmentFunc::operator() (const std::vector<std::tuple<std::string, std::string>> params)
{
  if (params.size() > m_paramList.size() * 8) { // might be attack
      BOOST_THROW_EXCEPTION(std::runtime_error("Too many extra parameters given"));
  }
  std::map<std::string, std::string> paramMap;
  for (const auto& param : params) {
      paramMap[std::get<0>(param)] = std::get<1>(param);
  }

  //construct name
  PartialName name;
  for (const auto& field : m_paramList) {
      auto it = paramMap.find(field);
      if (it == paramMap.end()) {
          return std::vector<PartialName>();
      } else {
          name.append(it->second);
      }
  }
  std::vector<PartialName> nameList;
  util::Sha256 digest;
  digest << name.wireEncode();
  nameList.emplace_back(digest.toString());

  return nameList;
}

}
}
