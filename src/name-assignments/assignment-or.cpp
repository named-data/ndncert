//
// Created by Tyler on 10/6/20.
//

#include <iosfwd>
#include "assignment-or.hpp"

namespace ndn {
namespace ndncert {

NDNCERT_REGISTER_FUNCFACTORY(AssignmentOr, "or");

AssignmentOr::AssignmentOr()
    : NameAssignmentFuncFactory("or")
{
}

NameAssignmentFunc
AssignmentOr::getFunction(std::list<NameAssignmentFunc> funcs){
    if (funcs.size() == 1) return *funcs.begin();
    return OrAssignmentFunc(funcs);
}

NameAssignmentFunc
AssignmentOr::getFunction(const std::string &factoryParam) {
    std::list<NameAssignmentFunc> paramList;
    std::stringstream ss;
    ss << factoryParam;
    JsonSection section;
    try {
        boost::property_tree::read_json(ss, section);
    }
    catch (const std::exception& error) {
        BOOST_THROW_EXCEPTION(std::runtime_error(std::string("Failed to parse configuration for name assignment function or, ") + error.what()));
    }
    if (section.begin() == section.end()) {
        BOOST_THROW_EXCEPTION(std::runtime_error("No JSON configuration found for name assignment function"));
    }
    for (const auto& item: section) {
        auto factory = NameAssignmentFuncFactory::createNameAssignmentFuncFactory(item.first);
        if (!factory) {
            BOOST_THROW_EXCEPTION(std::runtime_error("Invalid assignment factory type"));
        }
        try {
            paramList.push_back(factory->getFunction(item.second.data()));
        } catch (const std::exception& e) {
            BOOST_THROW_EXCEPTION(std::runtime_error("Error on creating function"));
        }
    }

    return getFunction(paramList);
}

AssignmentOr::OrAssignmentFunc::OrAssignmentFunc(std::list<NameAssignmentFunc> funcList)
    : m_funcList(std::move(funcList))
{}

std::vector<PartialName>
AssignmentOr::OrAssignmentFunc::operator() (const std::vector<std::tuple<std::string, std::string>> params)
{
  std::vector<PartialName> nameList;
  for (const auto& func : m_funcList) {
      auto result = func(params);
      nameList.insert(nameList.end(), result.begin(), result.end());
  }

  return nameList;
}

}
}
