#include <exception>
#include <fstream>
#include <map>
#include <set>

#include "config.h"
#include "nlohmann/json.hpp"

using json = nlohmann::json;


int Config::load(const char *path) {
    std::ifstream config_fstream(path);
    json j;
    try {
        config_fstream >> j;
    } catch (std::exception& e) {
        return 1;
    }

    try {
        client_id = j.at("oauth").at("client").at("id").get<std::string>();
        client_secret = j.at("oauth").at("client").at("secret").get<std::string>();
        scope = j.at("oauth").at("scope").get<std::string>();
        device_endpoint = j.at("oauth").at("device_endpoint").get<std::string>();
        token_endpoint = j.at("oauth").at("token_endpoint").get<std::string>();
        userinfo_endpoint = j.at("oauth").at("userinfo_endpoint").get<std::string>();
    } catch (std::exception& e) {
        return 1;
    }
    if (j.find("ldap") != j.end()) {
        try {
            ldap_host = j.at("ldap").at("host").get<std::string>();
            ldap_basedn = j.at("ldap").at("basedn").get<std::string>();
            ldap_user = j.at("ldap").at("user").get<std::string>();
            ldap_passwd = j.at("ldap").at("passwd").get<std::string>();
            ldap_filter = j.at("ldap").at("filter").get<std::string>();
            ldap_attr = j.at("ldap").at("attr").get<std::string>();
        } catch (std::exception& e) {
            return 1;
        }
    }
    if (j.find("users") != j.end()) {
        for (auto& element: j["users"].items()) {
            for (auto& local_user: element.value()) {
                if (usermap.find(element.key()) == usermap.end()) {
                    std::set<std::string> userset;
                    userset.insert((std::string) local_user);
                    usermap[element.key()] = userset;
                } else {
                    usermap[element.key()].insert((std::string) local_user);
                }
            }
        }
    }
    return 0;
} 