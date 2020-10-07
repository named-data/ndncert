//
// Created by Tyler on 10/6/20.
//

#ifndef NDNCERT_ASSIGNMENT_HASH_HPP
#define NDNCERT_ASSIGNMENT_HASH_HPP

#include "assignment-funcs.hpp"

namespace ndn {
namespace ndncert {

/**
 * assign names base on client probe parameter
 */
class AssignmentHash: public NameAssignmentFuncFactory{
public:
  AssignmentHash();

  NameAssignmentFunc getFunction(const std::string &factoryParam) override;

};
}
}



#endif //NDNCERT_ASSIGNMENT_HASH_HPP
