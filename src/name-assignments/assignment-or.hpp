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

  class OrAssignmentFunc {
  public:
    OrAssignmentFunc(std::list<NameAssignmentFunc> funcList);

    std::vector<PartialName>
    operator() (const std::vector<std::tuple<std::string, std::string>> params);
  private:
    std::list<NameAssignmentFunc> m_funcList;
  };

};
}
}



#endif //NDNCERT_ASSIGNMENT_OR_HPP
