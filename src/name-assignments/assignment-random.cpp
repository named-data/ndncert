//
// Created by Tyler on 10/6/20.
//

#include "assignment-random.hpp"
#include <ndn-cxx/util/random.hpp>

namespace ndn {
namespace ndncert {

NDNCERT_REGISTER_FUNCFACTORY(AssignmentRandom, "random");

AssignmentRandom::AssignmentRandom(const std::string& format)
  : NameAssignmentFuncFactory("random", format)
{}

std::vector<PartialName>
AssignmentRandom::assignName(const std::vector<std::tuple<std::string, std::string>>& params)
{
  std::vector<PartialName> resultList;
  resultList.emplace_back(to_string(random::generateSecureWord64()));
  return resultList;
}

}
}
