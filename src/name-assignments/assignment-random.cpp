//
// Created by Tyler on 10/6/20.
//

#include "assignment-random.hpp"
#include <ndn-cxx/util/random.hpp>

namespace ndn {
namespace ndncert {

_LOG_INIT(ndncert.assignment.random);

NDNCERT_REGISTER_FUNCFACTORY(AssignmentRandom, "random");

AssignmentRandom::AssignmentRandom()
    : NameAssignmentFuncFactory("random")
{
}

NameAssignmentFunc
AssignmentRandom::getFunction(const std::string &factoryParam) {
  return [](const std::vector<std::tuple<std::string, std::string>>){
        std::vector<PartialName> names;
        names.emplace_back(to_string(random::generateSecureWord64()));
        return names;
  };
}

}
}
