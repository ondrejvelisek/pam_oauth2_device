#include "gtest/gtest.h"
#include "include/config.hpp"

#define CLIENT_ID "client_id"

namespace {

TEST(ConfigTest, WrongFormat) {
    struct Config config;
    int rc;
    rc = config.load("data/template_wrong.json");
    EXPECT_EQ(rc, 1);
    EXPECT_TRUE(config.client_id.empty());
}

TEST(ConfigTest, Empty) {
    struct Config config;
    int rc;
    rc = config.load("data/template_empty.json");
    EXPECT_EQ(rc, 1);
    EXPECT_TRUE(config.client_id.empty());
}

TEST(ConfigTest, NoLdap) {
    struct Config config;
    int rc;
    rc = config.load("data/template_noldap.json");
    EXPECT_EQ(rc, 0);
    EXPECT_EQ(config.client_id, CLIENT_ID);
    EXPECT_TRUE(config.ldap_host.empty());
}

TEST(ConfigTest, Full) {
    struct Config config;
    int rc;
    rc = config.load("../config_template.json");
    EXPECT_EQ(rc, 0);
    EXPECT_EQ(config.client_id, CLIENT_ID);
    EXPECT_EQ(config.ldap_host, "ldaps://ldap-server:636");
    EXPECT_EQ(config.usermap["provider_user_id_1"].count("root"), 1);
    EXPECT_EQ(config.usermap.size(), 2);
    EXPECT_EQ(config.qr_error_correction_level, 0);
}

}