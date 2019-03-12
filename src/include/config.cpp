#include <stdlib.h>
#include <string.h>

#include <fstream>
#include <iostream>
#include <exception>

#include "nlohmann/json.hpp"
#include "config.h"

using json = nlohmann::json;

int load_config(struct Config *config, const char *path) {
    std::ifstream config_fstream(path);
    json j;
    config_fstream >> j;

    config->client_id = NULL;
    config->client_secret = NULL;
    config->scope = NULL;
    config->device_endpoint = NULL;
    config->token_endpoint = NULL;
    config->userinfo_endpoint = NULL;
    config->ldap_host = NULL;
    config->ldap_basedn = NULL;
    config->ldap_user = NULL;
    config->ldap_passwd = NULL;
    config->ldap_filter = NULL;
    config->ldap_attr = NULL;

    try {
        if ((config->client_id = strdup(j.at("oauth").at("client").at("id").get<std::string>().c_str())) == NULL) return -1;
        if ((config->client_secret = strdup(j.at("oauth").at("client").at("secret").get<std::string>().c_str())) == NULL) return -1;
        if ((config->scope = strdup(j.at("oauth").at("scope").get<std::string>().c_str())) == NULL) return -1;
        if ((config->device_endpoint = strdup(j.at("oauth").at("device_endpoint").get<std::string>().c_str())) == NULL) return -1;
        if ((config->token_endpoint = strdup(j.at("oauth").at("token_endpoint").get<std::string>().c_str())) == NULL) return -1;
        if ((config->userinfo_endpoint = strdup(j.at("oauth").at("userinfo_endpoint").get<std::string>().c_str())) == NULL) return -1;
    } catch (std::exception& e) {
        std::cout << e.what() << std::endl;
        return -1;
    }
    if (j.find("ldap") != j.end()) {
        try {
            if ((config->ldap_host = strdup(j.at("ldap").at("host").get<std::string>().c_str())) == NULL) return -1;
            if ((config->ldap_basedn = strdup(j.at("ldap").at("basedn").get<std::string>().c_str())) == NULL) return -1;
            if ((config->ldap_user = strdup(j.at("ldap").at("user").get<std::string>().c_str())) == NULL) return -1;
            if ((config->ldap_passwd = strdup(j.at("ldap").at("passwd").get<std::string>().c_str())) == NULL) return -1;
            if ((config->ldap_filter = strdup(j.at("ldap").at("filter").get<std::string>().c_str())) == NULL) return -1;
            if ((config->ldap_attr = strdup(j.at("ldap").at("attr").get<std::string>().c_str())) == NULL) return -1;
        } catch (std::exception& e) {
            std::cout << e.what() << std::endl;
            return -1;
        }
    }
    return 0;
}


void free_config(struct Config *config) {
    if (config->client_id) free(config->client_id);
    if (config->client_secret) free(config->client_secret);
    if (config->scope) free(config->scope);
    if (config->device_endpoint) free(config->device_endpoint);
    if (config->token_endpoint) free(config->token_endpoint);
    if (config->userinfo_endpoint) free(config->userinfo_endpoint);
    if (config->ldap_host) free(config->ldap_host);
    if (config->ldap_basedn) free(config->ldap_basedn);
    if (config->ldap_user) free(config->ldap_user);
    if (config->ldap_passwd) free(config->ldap_passwd);
    if (config->ldap_filter) free(config->ldap_filter);
    if (config->ldap_attr) free(config->ldap_attr);
}

