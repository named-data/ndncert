//
// Created by Tyler on 10/6/20.
//

#ifndef NDNCERT_ASSIGNMENT_PARAM_HPP
#define NDNCERT_ASSIGNMENT_PARAM_HPP

#include "assignment-funcs.hpp"

namespace ndn {
namespace ndncert {

/**
 * assign names base on client probe parameter
 */
class AssignmentParam: public NameAssignmentFuncFactory{
public:
  AssignmentParam();

  NameAssignmentFunc getFunction(const std::string &factoryParam) override;

  class ParamAssignmentFunc {
  public:
    ParamAssignmentFunc(std::list<std::string> paramList);

    std::vector<PartialName>
    operator() (const std::vector<std::tuple<std::string, std::string>> params);
  private:
    std::list<std::string> m_paramList;
  };

};
}
}



#endif //NDNCERT_ASSIGNMENT_PARAM_HPP
