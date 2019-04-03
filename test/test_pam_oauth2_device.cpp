#include "gtest/gtest.h"
#include "pam_oauth2_device.h"

#define DEVICE_ENDPOINT "http://localhost:8042/devicecode"
#define TOKEN_ENDPOINT "http://localhost:8042/token"
#define USERINFO_ENDPOINT "http://localhost:8042/userinfo"
#define CLIENT_ID "client_id"
#define CLIENT_SECRET "NDVmODY1ZDczMGIyMTM1MWFlYWM2NmYw"
#define SCOPE "openid profile"
#define USER_CODE "QWERTY"
#define DEVICE_CODE "e1e9b7be-e720-467e-bbe1-5c382356e4a9"
#define ACCESS_TOKEN "ZjBhNTQxYzEzMGQwNWU1OWUxMDhkMTM5"
#define VERIFICATION_URL "http://localhost:8042/oidc/device"

namespace {

TEST(PamTest, Device) {
    int rc;
    DeviceAuthResponse response;
    rc = make_authorization_request(
        CLIENT_ID, SCOPE, DEVICE_ENDPOINT, &response);
    EXPECT_EQ(rc, 0);
    EXPECT_EQ(response.user_code, USER_CODE);
    EXPECT_EQ(response.device_code, DEVICE_CODE);
    EXPECT_EQ(response.verification_uri, VERIFICATION_URL);
    EXPECT_EQ(response.verification_uri_complete,
              std::string(VERIFICATION_URL) + "?user_code=" + DEVICE_CODE);
}

TEST(PamTest, Token) {
    int rc;
    std::string token;
    rc = poll_for_token(CLIENT_ID, CLIENT_SECRET,
                        TOKEN_ENDPOINT,
                        DEVICE_CODE, token);
    EXPECT_EQ(rc, 0);
    EXPECT_EQ(token, ACCESS_TOKEN);
}

TEST(PamTest, Userinfo) {
    int rc;
    Userinfo userinfo;
    rc = get_userinfo(USERINFO_ENDPOINT, ACCESS_TOKEN, &userinfo);
    EXPECT_EQ(rc, 0);
    EXPECT_EQ(userinfo.sub, "YzQ4YWIzMzJhZjc5OWFkMzgwNmEwM2M5");
    EXPECT_EQ(userinfo.username, "jdoe");
    EXPECT_EQ(userinfo.name, "Joe Doe");
}

}