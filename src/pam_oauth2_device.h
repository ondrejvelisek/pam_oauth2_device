#include <string>

class Userinfo {
    public:
        std::string sub,
                    username,
                    name;
};

class DeviceAuthResponse {
    public:
        std::string user_code,
            verification_uri,
            verification_uri_complete,
            device_code;
        std::string get_prompt();
};

int make_authorization_request(const char *client_id,
                               const char *scope,
                               const char *device_endpoint,
                               DeviceAuthResponse *response);

int poll_for_token(const char *client_id,
                   const char *client_secret,
                   const char *token_endpoint,
                   const char *device_code,
                   std::string &token);
 
int get_userinfo(const char *userinfo_endpoint,
                 const char *token,
                 Userinfo *userinfo);