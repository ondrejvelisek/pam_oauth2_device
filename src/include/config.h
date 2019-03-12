struct Config {
    char *client_id, *client_secret, *scope,
         *device_endpoint, *token_endpoint, *userinfo_endpoint,
         *ldap_host, *ldap_basedn, *ldap_user, *ldap_passwd, *ldap_filter, *ldap_attr;
};

int load_config(struct Config *config, const char *path);
void free_config(struct Config *config);
