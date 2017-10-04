#ifndef __LINE_CONFIG_H_
#define __LINE_CONFIG_H_

#include <yaml-cpp/yaml.h>

#include <string>
#include <vector>
#include <map>

class Config
{
 private:
    std::string m_containerBase;
    YAML::Node m_config;

 public:
    Config();
    virtual ~Config();

    bool load(std::string base);

    std::vector<std::pair<std::string, std::string> > getMounts();
};

#endif
