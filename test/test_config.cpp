#include "gtest/gtest.h"
#include "include/config.hpp"
#include "include/nlohmann/json.hpp"

#define CLIENT_ID "client_id"

using json = nlohmann::json;

namespace
{

TEST(ConfigTest, MissingFile)
{
    Config config;
    ASSERT_THROW(config.load("data/missing.json"), json::parse_error);
}

TEST(ConfigTest, WrongFormat)
{
    Config config;
    ASSERT_THROW(config.load("data/template_wrong.json"), json::parse_error);
}

TEST(ConfigTest, Empty)
{
    Config config;
    ASSERT_THROW(config.load("data/template_empty.json"), json::out_of_range);
}

TEST(ConfigTest, NoLdap)
{
    Config config;
    config.load("data/template_noldap.json");
    EXPECT_EQ(config.client_id, CLIENT_ID);
    EXPECT_TRUE(config.ldap_hosts.empty());
}

TEST(ConfigTest, Full)
{
    Config config;
    config.load("../config_template.json");
    EXPECT_EQ(config.client_id, CLIENT_ID);
    EXPECT_EQ(config.ldap_hosts.size(), 3);
    EXPECT_EQ(config.usermap["provider_user_id_1"].count("root"), 1);
    EXPECT_EQ(config.usermap.size(), 2);
    EXPECT_EQ(config.qr_error_correction_level, 0);
}

} // namespace
