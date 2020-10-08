//
// Created by Tyler on 10/6/20.
//

#include "assignment-hash.hpp"
#include <ndn-cxx/util/sha256.hpp>

namespace ndn {
namespace ndncert {

NDNCERT_REGISTER_FUNCFACTORY(AssignmentHash, "hash");

AssignmentHash::AssignmentHash(const std::string& format)
  : NameAssignmentFuncFactory("hash", format)
{}

std::vector<PartialName>
AssignmentHash::assignName(const std::vector<std::tuple<std::string, std::string>>& params)
{
  std::vector<PartialName> resultList;
  Name result;
  for (const auto& item : m_nameFormat) {
    auto it = std::find_if(params.begin(), params.end(),
                           [&](const std::tuple<std::string, std::string>& e) { return std::get<0>(e) == item; });
    if (it != params.end()) {
      util::Sha256 digest;
      digest << std::get<1>(*it);
      result.append(digest.toString());
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
