//
// Created by Tyler on 10/6/20.
//

#ifndef NDNCERT_ASSIGNMENT_OR_HPP
#define NDNCERT_ASSIGNMENT_OR_HPP

#include "assignment-funcs.hpp"

namespace ndn {
namespace ndncert {

/**
 * assign names base on client probe parameter
 */
class AssignmentOr: public NameAssignmentFuncFactory{
public:
  AssignmentOr();

  NameAssignmentFunc getFunction(std::list<NameAssignmentFunc> funcs);

  NameAssignmentFunc getFunction(const std::string &factoryParam) override;

};
}
}



#endif //NDNCERT_ASSIGNMENT_OR_HPP
