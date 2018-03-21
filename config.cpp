
#include "config.h"

using namespace std;

Config::Config() : Logger("Config")
{
}

Config::~Config()
{
}

bool Config::load(string base)
{
    m_containerBase = base;
    string configpath = m_containerBase + "/config.yaml";
    log("load: configpath=%s", configpath.c_str());
    m_config = YAML::LoadFile(configpath.c_str());
    if (!m_config)
    {
        error("load: Failed to load config!");
        return false;
    }

    return true;
}

vector<pair<string, string> > Config::getMounts()
{
    vector<pair<string, string> > mounts;

    YAML::Node fileSystemNode = m_config["filesystem"];
    if (fileSystemNode)
    {
        YAML::Node mountsNode = fileSystemNode["mounts"];

        YAML::const_iterator mountIt;
        for (mountIt = mountsNode.begin(); mountIt != mountsNode.end(); ++mountIt)
        {
            string mount = mountIt->first.as<std::string>();
            string dest = mountIt->second.as<std::string>();
            if (dest.length() > 0 && dest.at(0) != '/')
            {
                dest = m_containerBase + "/" + dest;
            }
            mounts.push_back(make_pair(mount, dest));
            log("getMounts: mount: %s -> %s", mount.c_str(), dest.c_str());
        }

    }

    return mounts;
}

