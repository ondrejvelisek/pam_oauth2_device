#ifndef PAM_OAUTH2_DEVICE_LDAPQUERY_H
#define PAM_OAUTH2_DEVICE_LDAPQUERY_H

#define LDAPQUERY_ERROR -1
#define LDAPQUERY_TRUE 1
#define LDAPQUERY_FALSE 0

int ldap_check_attr(const char *host, const char *basedn, const char *user,
                    const char *passwd, const char *filter, const char *attr,
                    const char *value);

#endif  // PAM_OAUTH2_DEVICE_LDAPQUERY_H