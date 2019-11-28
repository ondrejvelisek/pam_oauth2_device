#include <curl/curl.h>
#include <security/pam_appl.h>
#include <security/pam_modules.h>

#include <chrono>
#include <sstream>
#include <thread>

#include "include/config.hpp"
#include "include/ldapquery.h"
#include "include/nayuki/QrCode.hpp"
#include "include/nlohmann/json.hpp"
#include "pam_oauth2_device.hpp"

using json = nlohmann::json;

class BaseError : public std::exception
{
public:
    const char *what() const throw()
    {
        return "Base Error";
    }
};

class PamError : public BaseError
{
public:
    const char *what() const throw()
    {
        return "PAM Error";
    }
};

class NetworkError : public BaseError
{
public:
    const char *what() const throw()
    {
        return "Network Error";
    }
};

class TimeoutError : public NetworkError
{
public:
    const char *what() const throw()
    {
        return "Timeout Error";
    }
};

class ResponseError : public NetworkError
{
public:
    const char *what() const throw()
    {
        return "Response Error";
    }
};

std::string getQr(const char *text, const int ecc = 0, const int border = 1)
{
    qrcodegen::QrCode::Ecc error_correction_level;
    switch (ecc)
    {
    case 1:
        error_correction_level = qrcodegen::QrCode::Ecc::MEDIUM;
        break;
    case 2:
        error_correction_level = qrcodegen::QrCode::Ecc::HIGH;
        break;
    default:
        error_correction_level = qrcodegen::QrCode::Ecc::LOW;
        break;
    }
    qrcodegen::QrCode qr = qrcodegen::QrCode::encodeText(
        text, error_correction_level);

    std::ostringstream oss;
    int i, j, size, top, bottom;
    size = qr.getSize();
    for (j = -border; j < size + border; j += 2)
    {
        for (i = -border; i < size + border; ++i)
        {
            top = qr.getModule(i, j);
            bottom = qr.getModule(i, j + 1);
            if (top && bottom)
            {
                oss << "\033[40;97m \033[0m";
            }
            else if (top && !bottom)
            {
                oss << "\033[40;97m\u2584\033[0m";
            }
            else if (!top && bottom)
            {
                oss << "\033[40;97m\u2580\033[0m";
            }
            else
            {
                oss << "\033[40;97m\u2588\033[0m";
            }
        }
        oss << std::endl;
    }
    return oss.str();
}

std::string DeviceAuthResponse::get_prompt(const int qr_ecc = 0)
{
    bool complete_url = !verification_uri_complete.empty();
    std::ostringstream prompt;
    prompt << "Authenticate at\n-----------------\n"
           << (complete_url ? verification_uri_complete : verification_uri)
           << "\n-----------------\n";
    if (!complete_url)
    {
        prompt << "With code" << user_code << user_code
               << "\n-----------------\n";
    }

    prompt << "Or scan the QR code to authenticate with a mobile device"
           << std::endl
           << std::endl
           << getQr((complete_url ? verification_uri_complete : verification_uri).c_str(), qr_ecc)
           << std::endl
           << "Hit enter when you authenticate\n";
    return prompt.str();
}

static size_t WriteCallback(void *contents, size_t size, size_t nmemb, void *userp)
{
    ((std::string *)userp)->append((char *)contents, size * nmemb);
    return size * nmemb;
}

void make_authorization_request(const char *client_id,
                                const char *client_secret,
                                const char *scope,
                                const char *device_endpoint,
                                DeviceAuthResponse *response)
{
    CURL *curl;
    CURLcode res;
    std::string readBuffer;

    curl = curl_easy_init();
    if (!curl)
        throw NetworkError();
    std::string params = std::string("client_id=") + client_id + "&scope=" + scope;
    curl_easy_setopt(curl, CURLOPT_URL, device_endpoint);
    curl_easy_setopt(curl, CURLOPT_USERNAME, client_id);
    curl_easy_setopt(curl, CURLOPT_PASSWORD, client_secret);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, params.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);
    res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);
    if (res != CURLE_OK)
        throw NetworkError();
    try
    {
        auto data = json::parse(readBuffer);
        response->user_code = data.at("user_code");
        response->device_code = data.at("device_code");
        response->verification_uri = data.at("verification_uri");
        if (data.find("verification_uri_complete") != data.end())
        {
            response->verification_uri_complete = data.at("verification_uri_complete");
        }
    }
    catch (json::exception &e)
    {
        throw ResponseError();
    }
}

void poll_for_token(const char *client_id,
                    const char *client_secret,
                    const char *token_endpoint,
                    const char *device_code,
                    std::string &token)
{
    int timeout = 300,
        interval = 3;
    CURL *curl;
    CURLcode res;
    json data;
    std::ostringstream oss;
    std::string params;

    oss << "grant_type=urn:ietf:params:oauth:grant-type:device_code"
        << "&device_code=" << device_code
        << "&client_id=" << client_id;
    params = oss.str();

    while (true)
    {
        timeout -= interval;
        if (timeout < 0)
        {
            throw TimeoutError();
        }
        std::string readBuffer;
        std::this_thread::sleep_for(std::chrono::seconds(interval));
        curl = curl_easy_init();
        if (!curl)
            throw NetworkError();
        curl_easy_setopt(curl, CURLOPT_URL, token_endpoint);
        curl_easy_setopt(curl, CURLOPT_USERNAME, client_id);
        curl_easy_setopt(curl, CURLOPT_PASSWORD, client_secret);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, params.c_str());
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);

        res = curl_easy_perform(curl);
        curl_easy_cleanup(curl);
        if (res != CURLE_OK)
            throw NetworkError();
        try
        {
            data = json::parse(readBuffer);
            if (data["error"].empty())
            {
                token = data.at("access_token");
                break;
            }
            else if (data["error"] == "authorization_pending")
            {
                // Do nothing
            }
            else if (data["error"] == "slow_down")
            {
                ++interval;
            }
            else
            {
                throw ResponseError();
            }
        }
        catch (json::exception &e)
        {
            throw ResponseError();
        }
    }
}

void get_userinfo(const char *userinfo_endpoint,
                  const char *token,
                  const char *username_attribute,
                  Userinfo *userinfo)
{
    CURL *curl;
    CURLcode res;
    std::string readBuffer;

    curl = curl_easy_init();
    if (!curl)
        throw NetworkError();
    curl_easy_setopt(curl, CURLOPT_URL, userinfo_endpoint);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);

    std::string auth_header = "Authorization: Bearer ";
    auth_header += token;
    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, auth_header.c_str());
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

    res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);
    if (res != CURLE_OK)
        throw NetworkError();
    try
    {
        auto data = json::parse(readBuffer);
        userinfo->sub = data.at("sub");
        userinfo->username = data.at(username_attribute);
        userinfo->name = data.at("name");
    }
    catch (json::exception &e)
    {
        throw ResponseError();
    }
}

void show_prompt(pam_handle_t *pamh,
                 int qr_error_correction_level,
                 DeviceAuthResponse *device_auth_response)
{
    int pam_err;
    char *response;
    struct pam_conv *conv;
    struct pam_message msg;
    const struct pam_message *msgp;
    struct pam_response *resp;
    std::string prompt;

    pam_err = pam_get_item(pamh, PAM_CONV, (const void **)&conv);
    if (pam_err != PAM_SUCCESS)
        throw PamError();
    prompt = device_auth_response->get_prompt(qr_error_correction_level);
    msg.msg_style = PAM_PROMPT_ECHO_OFF;
    msg.msg = prompt.c_str();
    msgp = &msg;
    response = NULL;
    pam_err = (*conv->conv)(1, &msgp, &resp, conv->appdata_ptr);
    if (resp != NULL)
    {
        if (pam_err == PAM_SUCCESS)
        {
            response = resp->resp;
        }
        else
        {
            free(resp->resp);
        }
        free(resp);
    }
    if (response)
        free(response);
}

bool is_authorized(Config *config,
                   const char *username_local,
                   const char *username_remote)
{
    // Try to authorize against local config
    if (config->usermap.count(username_remote) > 0)
    {
        if (config->usermap[username_remote].count(username_local) > 0)
        {
            return true;
        }
    }

    // Try to authorize against LDAP
    if (!config->ldap_host.empty())
    {
        size_t filter_length = config->ldap_filter.length() + strlen(username_remote) + 1;
        char *filter = new char[filter_length];
        snprintf(filter, filter_length, config->ldap_filter.c_str(), username_remote);
        int rc = ldap_check_attr(config->ldap_host.c_str(), config->ldap_basedn.c_str(),
                                 config->ldap_user.c_str(), config->ldap_passwd.c_str(),
                                 filter, config->ldap_attr.c_str(), username_local);
        delete[] filter;
        if (rc == LDAPQUERY_TRUE)
            return true;
    }

    return false;
}

/* expected hook */
PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    return PAM_SUCCESS;
}

/* expected hook */
PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    return PAM_SUCCESS;
}

/* expected hook, custom logic */
PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    const char *username_local;
    std::string token;
    Config config;
    DeviceAuthResponse device_auth_response;
    Userinfo userinfo;

    try
    {
        (argc > 0) ? config.load(argv[0]) : config.load("/etc/pam_oauth2_device/config.json");
    }
    catch (json::exception &e)
    {
        return PAM_AUTH_ERR;
    }

    try
    {
        if (pam_get_user(pamh, &username_local, "Username: ") != PAM_SUCCESS)
            throw PamError();
        make_authorization_request(
            config.client_id.c_str(), config.client_secret.c_str(),
            config.scope.c_str(), config.device_endpoint.c_str(),
            &device_auth_response);
        show_prompt(pamh, config.qr_error_correction_level, &device_auth_response);
        poll_for_token(config.client_id.c_str(), config.client_secret.c_str(),
                       config.token_endpoint.c_str(),
                       device_auth_response.device_code.c_str(), token);
        get_userinfo(config.userinfo_endpoint.c_str(), token.c_str(),
                     config.username_attribute.c_str(), &userinfo);
    }
    catch (PamError &e)
    {
        return PAM_SYSTEM_ERR;
    }
    catch (TimeoutError &e)
    {
        return PAM_AUTH_ERR;
    }
    catch (NetworkError &e)
    {
        return PAM_AUTH_ERR;
    }

    if (is_authorized(&config, username_local, userinfo.username.c_str()))
        return PAM_SUCCESS;
    return PAM_AUTH_ERR;
}
