#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <security/pam_appl.h>
#include <security/pam_modules.h>

#include <chrono>
#include <fstream>
#include <iostream>
#include <map>
#include <set>
#include <sstream>
#include <string>
#include <thread>
#include <curl/curl.h>
#include "include/nlohmann/json.hpp"

using json = nlohmann::json;


struct Userinfo {
    std::string sub, username, name;
};


struct Config {
    char *client_id, *client_secret, *scope,
         *device_endpoint, *token_endpoint, *userinfo_endpoint;
};


int load_config(struct Config *config, const char *path) {
    json j;
    std::string tmp;

    std::ifstream config_fstream(path);
    config_fstream >> j;

    tmp = j["oauth"]["client"]["id"];
    config->client_id = (char *) malloc(strlen(tmp.c_str()) + 1);
    strcpy(config->client_id, tmp.c_str());

    tmp = j["oauth"]["client"]["secret"];
    config->client_secret = (char *) malloc(strlen(tmp.c_str()) + 1);
    strcpy(config->client_secret, tmp.c_str());

    tmp = j["oauth"]["scope"];
    config->scope = (char *) malloc(strlen(tmp.c_str()) + 1);
    strcpy(config->scope, tmp.c_str());

    tmp = j["oauth"]["device_endpoint"];
    config->device_endpoint = (char *) malloc(strlen(tmp.c_str()) + 1);
    strcpy(config->device_endpoint, tmp.c_str());

    tmp = j["oauth"]["token_endpoint"];
    config->token_endpoint = (char *) malloc(strlen(tmp.c_str()) + 1);
    strcpy(config->token_endpoint, tmp.c_str());

    tmp = j["oauth"]["userinfo_endpoint"];
    config->userinfo_endpoint = (char *) malloc(strlen(tmp.c_str()) + 1);
    strcpy(config->userinfo_endpoint, tmp.c_str());
}


void free_config(struct Config *config) {
    free(config->client_id);
    free(config->client_secret);
    free(config->scope);
    free(config->device_endpoint);
    free(config->token_endpoint);
    free(config->userinfo_endpoint);
}


std::map<std::string,std::set<std::string>> get_user_map(const char *path) {
    json j;
    std::string tmp;

    std::ifstream config_fstream(path);
    config_fstream >> j;

    std::map<std::string,std::set<std::string>> usermap;

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
    return usermap;
}


static size_t WriteCallback(void *contents, size_t size, size_t nmemb, void *userp) {
    ((std::string*)userp)->append((char*)contents, size * nmemb);
    return size * nmemb;
}


std::string make_authorization_request(struct Config *config, std::string &device_code) {
    CURL *curl;
    CURLcode res;

    std::string readBuffer;
    std::ostringstream prompt;

    curl = curl_easy_init();
    if(curl) {
        curl_easy_setopt(curl, CURLOPT_URL, config->device_endpoint);
        std::ostringstream oss;
        oss << "client_id=" << config->client_id << "&scope=" << config->scope;
        auto params_str = oss.str();
        char* params_char = new char[params_str.length() + 1];
        strcpy(params_char, params_str.c_str());
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, params_char);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);
    
        res = curl_easy_perform(curl);
        delete params_char; // Free space
        if(res != CURLE_OK)
        fprintf(stderr, "curl_easy_perform() failed: %s\n",
                curl_easy_strerror(res));
        curl_easy_cleanup(curl);
        auto data = json::parse(readBuffer);
        device_code = data["device_code"];
        prompt << "Authenticate at\n-----------------\n"
            << ((std::string) data["verification_uri_complete"]) << std::endl
            << "-----------------\nHit enter when you authenticate\n";
    }
    return prompt.str();
}

void poll_for_token(struct Config *config, std::string &device_code, std::string &token) {
    CURL *curl;
    CURLcode res;

    json data;
    std::ostringstream oss;
    oss << "grant_type=urn:ietf:params:oauth:grant-type:device_code" 
        << "&device_code=" << device_code
        << "&client_id=" << config->client_id;
    auto params_str = oss.str();
    char* params_char = new char[params_str.length() + 1];
    strcpy(params_char, params_str.c_str());

    int timeout = 300;
    int interval = 3;

    while (true) {
        std::string readBuffer;
        std::this_thread::sleep_for(std::chrono::seconds(interval));
        timeout -= interval;

        // Token request
        curl = curl_easy_init();
        if(curl) {
            curl_easy_setopt(curl, CURLOPT_URL, config->token_endpoint);
            struct curl_slist *headers = NULL;
            curl_slist_append(headers, "Accept: application/json");
            curl_slist_append(headers, "Content-Type: application/json");
            curl_slist_append(headers, "charsets: utf-8");
            curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
            curl_easy_setopt(curl, CURLOPT_USERNAME, config->client_id);
            curl_easy_setopt(curl, CURLOPT_PASSWORD, config->client_secret);
            curl_easy_setopt(curl, CURLOPT_POSTFIELDS, params_char);
            curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
            curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);
        
            res = curl_easy_perform(curl);
            if(res != CURLE_OK)
            fprintf(stderr, "curl_easy_perform() failed: %s\n",
                    curl_easy_strerror(res));
        
            curl_easy_cleanup(curl);

            data = json::parse(readBuffer);
            if (data["error"].empty()) {
                break;
            } else {
                if (data["error"] == "authorization_pending") { 
                    // Do nothing
                } else if (data["error"] == "slow_down") { 
                    ++interval;
                } else {
                    //FIXME Raise an exception
                    break;
                }
            }

            if (timeout < 0) {
                std::cout << "Timeout, please try again" << std::endl;
            }
        }
        // End token request 
    }
    delete params_char; // Free space
    token = data["access_token"];
}

Userinfo get_userinfo(struct Config *config, std::string token) {
    CURL *curl;
    CURLcode res;
    std::string readBuffer;
    Userinfo userinfo;

    curl = curl_easy_init();
    if(curl) {
        curl_easy_setopt(curl, CURLOPT_URL, config->userinfo_endpoint);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);

        std::ostringstream oss;
        oss << "Authorization: Bearer " << token;
        auto auth_header_str = oss.str();
        char* auth_header_char = new char[auth_header_str.length() + 1];
        strcpy(auth_header_char, auth_header_str.c_str());
        struct curl_slist *headers = NULL;
        headers = curl_slist_append(headers, auth_header_char);
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    
        res = curl_easy_perform(curl);
        if(res != CURLE_OK)
        fprintf(stderr, "curl_easy_perform() failed: %s\n",
                curl_easy_strerror(res));
        curl_easy_cleanup(curl);
        auto data = json::parse(readBuffer);
        userinfo.sub = data["sub"];
        userinfo.username = data["preferred_username"];
        userinfo.name = data["name"];
    }
    return userinfo;
}

/* expected hook */
PAM_EXTERN int pam_sm_setcred( pam_handle_t *pamh, int flags, int argc, const char **argv ) {
    return PAM_SUCCESS;
}

/* expected hook */
PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    printf("Acct mgmt\n");
    return PAM_SUCCESS;
}

/* expected hook, custom logic */
PAM_EXTERN int pam_sm_authenticate( pam_handle_t *pamh, int flags,int argc, const char **argv ) {
    int retval;

    const char* pUsername;
    retval = pam_get_user(pamh, &pUsername, "Username: ");

    struct Config config;
    if (load_config(&config, "/etc/pam_oauth2_device/config.json") != 0) {
        return PAM_AUTH_ERR;
    }
    auto usermap = get_user_map("/etc/pam_oauth2_device/config.json");

    std::string device_code;
    std::string token;
    auto prompt = make_authorization_request(&config, device_code);

    char *prompt_msg;
    prompt_msg = new char[prompt.length() + 1];
    strcpy(prompt_msg, prompt.c_str());
    char *response;
    struct pam_conv *conv;
	struct pam_message msg;
	const struct pam_message *msgp;
	struct pam_response *resp;
    int pam_err;
    pam_err = pam_get_item(pamh, PAM_CONV, (const void **)&conv);
	if (pam_err != PAM_SUCCESS) {
        free_config(&config);
		return (PAM_SYSTEM_ERR);
    }
	msg.msg_style = PAM_PROMPT_ECHO_OFF;
	msg.msg = prompt_msg;
	msgp = &msg;
    pam_err = (*conv->conv)(1, &msgp, &resp, conv->appdata_ptr);
    if (resp != NULL) {
        if (pam_err == PAM_SUCCESS)
            response = resp->resp;
        else
            free(resp->resp);
        free(resp);
    }

    poll_for_token(&config, device_code, token);
    struct Userinfo userinfo = get_userinfo(&config, token);

    free_config(&config);

    if (usermap.count(userinfo.username) > 0) {
        if (usermap[userinfo.username].count(pUsername) > 0) {
            return PAM_SUCCESS;
        }
    }
    return PAM_AUTH_ERR;
}

