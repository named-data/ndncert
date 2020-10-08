//
// Created by Tyler on 10/6/20.
//

#include "assignment-param.hpp"

namespace ndn {
namespace ndncert {

NDNCERT_REGISTER_FUNCFACTORY(AssignmentParam, "param");

AssignmentParam::AssignmentParam(const std::string& format)
  : NameAssignmentFuncFactory("param", format)
{}

std::vector<PartialName>
AssignmentParam::assignName(const std::vector<std::tuple<std::string, std::string>>& params)
{
  std::vector<PartialName> resultList;
  Name result;
  for (const auto& item : m_nameFormat) {
    auto it = std::find_if(params.begin(), params.end(),
                           [&](const std::tuple<std::string, std::string>& e) { return std::get<0>(e) == item; });
    if (it != params.end()) {
      result.append(std::get<1>(*it));
    }
    else {
      return resultList;
    }
  }
  resultList.push_back(std::move(result));
  return resultList;
}

}  // namespace ndncert
}  // namespace ndn
