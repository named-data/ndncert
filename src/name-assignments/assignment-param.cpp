//
// Created by Tyler on 10/6/20.
//

#include "assignment-param.hpp"

namespace ndn {
namespace ndncert {

_LOG_INIT(ndncert.assignment.param);
NDNCERT_REGISTER_FUNCFACTORY(AssignmentParam, "param");

AssignmentParam::AssignmentParam()
    : NameAssignmentFuncFactory("param")
{
}

NameAssignmentFunc
AssignmentParam::getFunction(const std::string &factoryParam) {
    std::list<std::string> paramList;
    size_t index = 0, startIndex = 0;
    while ((index = factoryParam.find(":", startIndex)) != factoryParam.npos) {
        paramList.push_back(factoryParam.substr(startIndex, index));
        startIndex = index + 1;
    }
    if (startIndex != factoryParam.size()) {
        paramList.push_back(factoryParam.substr(startIndex));
    }
    return ParamAssignmentFunc(paramList);
}

AssignmentParam::ParamAssignmentFunc::ParamAssignmentFunc(std::list<std::string> paramList)
    : m_paramList(std::move(paramList))
{}

std::vector<PartialName>
AssignmentParam::ParamAssignmentFunc::operator() (const std::vector<std::tuple<std::string, std::string>> params)
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
  nameList.push_back(name);
  return nameList;
}

}
}
