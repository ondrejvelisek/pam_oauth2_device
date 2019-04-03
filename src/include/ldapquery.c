#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ldap.h>

#include "ldapquery.h"


int ldap_check_attr(const char *host, const char *basedn,
                    const char *user, const char *passwd,
                    const char *filter, const char *attr,
                    const char *value) {
    LDAP *ld;
    LDAPMessage *res, *msg;
    BerElement *ber;
    BerValue *servercredp;
    char *a, *passwd_local;
    int rc, i;
    struct berval cred;
    struct berval **vals;
    char *attr_local = NULL;
    char *attrs[] = {attr_local, NULL};
    const int ldap_version = LDAP_VERSION3;

    if (ldap_initialize(&ld, host) != LDAP_SUCCESS) {
        return LDAPQUERY_ERROR;
    }

    if (ldap_set_option(ld, LDAP_OPT_PROTOCOL_VERSION, &ldap_version) != LDAP_SUCCESS) {
        return LDAPQUERY_ERROR;
    }

    passwd_local = (char *) malloc(strlen(passwd) + 1);
    strcpy(passwd_local, passwd);
    cred.bv_val = passwd_local;
    cred.bv_len = strlen(passwd);
    rc = ldap_sasl_bind_s(ld, user, LDAP_SASL_SIMPLE, &cred, NULL, NULL, &servercredp);
    free(passwd_local);
    if ( rc != LDAP_SUCCESS ) {
        return LDAPQUERY_ERROR;
    }

    attr_local = strdup(attr);
    rc = ldap_search_ext_s(ld, basedn, LDAP_SCOPE_SUBTREE, filter, attrs, 0, NULL, NULL, NULL, 0, &res);
    free(attr_local);
    if (rc != LDAP_SUCCESS) {
        ldap_msgfree(res);
        ldap_unbind_ext_s(ld, NULL, NULL);
        return LDAPQUERY_ERROR;
    }

    rc = LDAPQUERY_FALSE;
    for ( msg = ldap_first_message( ld, res ); msg != NULL; msg = ldap_next_message( ld, msg ) ) {
        switch(ldap_msgtype(msg)) {
        case LDAP_RES_SEARCH_ENTRY:
        for (a = ldap_first_attribute( ld, res, &ber ); a != NULL; a = ldap_next_attribute( ld, res, ber )) {
            if ((vals = ldap_get_values_len( ld, res, a)) != NULL) {
                for (i = 0; vals[i] != NULL; ++i) {
                    if (strcmp(a, attr) == 0) {
                        if (strcmp(vals[i]->bv_val, value) == 0) {
                            rc = LDAPQUERY_TRUE;
                        }
                    }
                }
                ldap_value_free_len(vals);
            }
            ldap_memfree(a);
        }
        if (ber != NULL) {
            ber_free(ber, 0);
        }
        break;
        default:
        break;
        }
    }

    ldap_msgfree(res);
    ldap_unbind_ext_s(ld, NULL, NULL);
    return rc;
}