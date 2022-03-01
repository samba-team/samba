/*
 * Copyright (c) 2021, PADL Software Pty Ltd.
 * All rights reserved.
 *
 * Portions Copyright (c) 2004 Kungliga Tekniska Högskolan
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * 3. Neither the name of PADL Software nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY PADL SOFTWARE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL PADL SOFTWARE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*
 * This plugin authorizes federated GSS-API pre-authentication clients by
 * querying an AD DC in the KDC realm for the altSecurityIdentities
 * attribute.
 *
 * For example, GSS-API initiator foo@AAA.H5L.SE using the eap-aes128
 * mechanism to authenticate in realm H5L.SE would require a user entry
 * where altSecurityIdentities equals either:
 *
 *  EAP:foo@AAA.H5L.SE
 *  EAP-AES128:foo@AAA.H5L.SE
 *
 * (Stripping the mechanism name after the hyphen is a convention
 * intended to allow mechanism variants to be grouped together.)
 *
 * Once the user entry is found, the name is canonicalized by reading the
 * sAMAccountName attribute and concatenating it with the KDC realm,
 * specifically the canonicalized realm of the WELLKNOWN/FEDERATED HDB
 * entry.
 *
 * The KDC will need to have access to a default credentials cache, or
 * OpenLDAP will need to be linked against a version of Cyrus SASL and
 * Heimdal that supports keytab credentials.
 */

#include "kdc_locl.h"

#include <resolve.h>
#include <common_plugin.h>
#include <heimqueue.h>

#include <gssapi/gssapi.h>
#include <gssapi_mech.h>

#include <ldap.h>

#include "gss_preauth_authorizer_plugin.h"

#ifndef PAC_REQUESTOR_SID
#define PAC_REQUESTOR_SID               18
#endif

struct ad_server_tuple {
    HEIM_TAILQ_ENTRY(ad_server_tuple) link;
    char *realm;
    LDAP *ld;
#ifdef LDAP_OPT_X_SASL_GSS_CREDS
    gss_cred_id_t gss_cred;
#endif
};

struct altsecid_gss_preauth_authorizer_context {
    HEIM_TAILQ_HEAD(ad_server_tuple_list, ad_server_tuple) servers;
};

static int
sasl_interact(LDAP *ld, unsigned flags, void *defaults, void *interact)
{
    return LDAP_SUCCESS;
}

#ifdef LDAP_OPT_X_SASL_GSS_CREDS
static krb5_error_code
ad_acquire_cred(krb5_context context,
                krb5_const_realm realm,
                struct ad_server_tuple *server)
{
    const char *keytab_name = NULL;
    char *keytab_name_buf = NULL;
    krb5_error_code ret;

    OM_uint32 major, minor;
    gss_key_value_element_desc client_keytab;
    gss_key_value_set_desc cred_store;
    gss_OID_set_desc desired_mechs;

    desired_mechs.count = 1;
    desired_mechs.elements = GSS_KRB5_MECHANISM;

    keytab_name = krb5_config_get_string(context, NULL, "kdc", realm,
                                         "gss_altsecid_authorizer_keytab_name", NULL);
    if (keytab_name == NULL)
        keytab_name = krb5_config_get_string(context, NULL, "kdc",
                                             "gss_altsecid_authorizer_keytab_name", NULL);
    if (keytab_name == NULL) {
        ret = _krb5_kt_client_default_name(context, &keytab_name_buf);
        if (ret)
            return ret;

        keytab_name = keytab_name_buf;
    }

    client_keytab.key = "client_keytab";
    client_keytab.value = keytab_name;

    cred_store.count = 1;
    cred_store.elements = &client_keytab;

    major = gss_acquire_cred_from(&minor, GSS_C_NO_NAME, GSS_C_INDEFINITE,
                                  &desired_mechs, GSS_C_INITIATE,
                                  &cred_store, &server->gss_cred, NULL, NULL);
    if (GSS_ERROR(major))
        ret = minor ? minor : KRB5_KT_NOTFOUND;
    else
        ret = 0;

    krb5_xfree(keytab_name_buf);

    return ret;
}
#endif

static krb5_boolean
is_recoverable_ldap_err_p(int lret)
{
    return
        (lret == LDAP_SERVER_DOWN ||
         lret == LDAP_TIMEOUT ||
         lret == LDAP_UNAVAILABLE ||
         lret == LDAP_BUSY ||
         lret == LDAP_CONNECT_ERROR);
}

static krb5_error_code
ad_connect(krb5_context context,
           krb5_const_realm realm,
           struct ad_server_tuple *server)
{
    krb5_error_code ret;
    struct {
        char *server;
        int port;
    } *s, *servers = NULL;
    size_t i, num_servers = 0;

    {
        struct rk_dns_reply *r;
        struct rk_resource_record *rr;
        char *domain;

        asprintf(&domain, "_ldap._tcp.%s", realm);
        if (domain == NULL) {
            ret = krb5_enomem(context);
            goto out;
        }

        r = rk_dns_lookup(domain, "SRV");
        free(domain);
        if (r == NULL) {
            krb5_set_error_message(context, KRB5KDC_ERR_SVC_UNAVAILABLE,
                                   "Couldn't find AD DC in DNS");
            ret = KRB5KDC_ERR_SVC_UNAVAILABLE;
            goto out;
        }

        for (rr = r->head ; rr != NULL; rr = rr->next) {
            if (rr->type != rk_ns_t_srv)
                continue;
            s = realloc(servers, sizeof(*servers) * (num_servers + 1));
            if (s == NULL) {
                ret = krb5_enomem(context);
                rk_dns_free_data(r);
                goto out;
            }
            servers = s;
            num_servers++;
            servers[num_servers - 1].port =  rr->u.srv->port;
            servers[num_servers - 1].server =  strdup(rr->u.srv->target);
        }
        rk_dns_free_data(r);
    }

#ifdef LDAP_OPT_X_SASL_GSS_CREDS
    if (server->gss_cred == GSS_C_NO_CREDENTIAL) {
        ret = ad_acquire_cred(context, realm, server);
        if (ret)
            goto out;
    }
#endif

    for (i = 0; i < num_servers; i++) {
        int lret, version = LDAP_VERSION3;
        LDAP *ld;
        char *url = NULL;

        asprintf(&url, "ldap://%s:%d", servers[i].server, servers[i].port);
        if (url == NULL) {
            ret = krb5_enomem(context);
            goto out;
        }

        lret = ldap_initialize(&ld, url);
        free(url);
        if (lret != LDAP_SUCCESS)
            continue;

        ldap_set_option(ld, LDAP_OPT_PROTOCOL_VERSION, &version);
        ldap_set_option(ld, LDAP_OPT_REFERRALS, LDAP_OPT_OFF);
#ifdef LDAP_OPT_X_SASL_GSS_CREDS
        ldap_set_option(ld, LDAP_OPT_X_SASL_GSS_CREDS, server->gss_cred);
#endif

        lret = ldap_sasl_interactive_bind_s(ld, NULL, "GSS-SPNEGO",
                                            NULL, NULL, LDAP_SASL_QUIET,
                                            sasl_interact, NULL);
        if (lret != LDAP_SUCCESS) {
            krb5_set_error_message(context, 0,
                                   "Couldn't bind to AD DC %s:%d: %s",
                                   servers[i].server, servers[i].port,
                                   ldap_err2string(lret));
            ldap_unbind_ext_s(ld, NULL, NULL);
            continue;
        }

        server->ld = ld;
        break;
    }

    ret = (server->ld != NULL) ? 0 : KRB5_KDC_UNREACH;

out:
    for (i = 0; i < num_servers; i++)
        free(servers[i].server);
    free(servers);

    if (ret && server->ld) {
        ldap_unbind_ext_s(server->ld, NULL, NULL);
        server->ld = NULL;
    }

    return ret;
}

static krb5_error_code
ad_lookup(krb5_context context,
          krb5_const_realm realm,
          struct ad_server_tuple *server,
          gss_const_name_t initiator_name,
          gss_const_OID mech_type,
          krb5_principal *canon_principal,
          kdc_data_t *requestor_sid)
{
    krb5_error_code ret;
    OM_uint32 minor;
    const char *mech_type_str, *p;
    char *filter = NULL;
    gss_buffer_desc initiator_name_buf = GSS_C_EMPTY_BUFFER;
    LDAPMessage *m = NULL, *m0;
    char *basedn = NULL;
    int lret;
    char *attrs[] = { "sAMAccountName", "objectSid", NULL };
    struct berval **values = NULL;

    *canon_principal = NULL;
    if (requestor_sid)
	*requestor_sid = NULL;

    mech_type_str = gss_oid_to_name(mech_type);
    if (mech_type_str == NULL) {
        ret = KRB5_PREAUTH_BAD_TYPE; /* should never happen */
        goto out;
    }

    ret = KRB5_KDC_ERR_CLIENT_NOT_TRUSTED;

    if (GSS_ERROR(gss_display_name(&minor, initiator_name,
                                   &initiator_name_buf, NULL)))
        goto out;

    if ((p = strrchr(mech_type_str, '-')) != NULL) {
        asprintf(&filter, "(&(objectClass=user)"
                 "(|(altSecurityIdentities=%.*s:%.*s)(altSecurityIdentities=%s:%.*s)))",
                 (int)(p - mech_type_str), mech_type_str,
                 (int)initiator_name_buf.length, (char *)initiator_name_buf.value,
                 mech_type_str,
                 (int)initiator_name_buf.length,
                 (char *)initiator_name_buf.value);
    } else {
        asprintf(&filter, "(&(objectClass=user)(altSecurityIdentities=%s:%.*s))",
                 mech_type_str,
                 (int)initiator_name_buf.length,
                 (char *)initiator_name_buf.value);
    }
    if (filter == NULL)
        goto enomem;

    lret = ldap_domain2dn(realm, &basedn);
    if (lret != LDAP_SUCCESS)
        goto out;

    lret = ldap_search_ext_s(server->ld, basedn, LDAP_SCOPE_SUBTREE,
                             filter, attrs, 0,
                             NULL, NULL, NULL, 1, &m);
    if (lret == LDAP_SIZELIMIT_EXCEEDED)
        ret = KRB5KDC_ERR_PRINCIPAL_NOT_UNIQUE;
    else if (is_recoverable_ldap_err_p(lret))
        ret = KRB5KDC_ERR_SVC_UNAVAILABLE;
    if (lret != LDAP_SUCCESS)
        goto out;

    m0 = ldap_first_entry(server->ld, m);
    if (m0 == NULL)
        goto out;

    values = ldap_get_values_len(server->ld, m0, "sAMAccountName");
    if (values == NULL ||
        ldap_count_values_len(values) == 0)
        goto out;

    ret = krb5_make_principal(context, canon_principal, realm,
                              values[0]->bv_val, NULL);
    if (ret)
	goto out;

    if (requestor_sid) {
	ldap_value_free_len(values);

	values = ldap_get_values_len(server->ld, m0, "objectSid");
	if (values == NULL ||
	    ldap_count_values_len(values) == 0)
	    goto out;

	*requestor_sid = kdc_data_create(values[0]->bv_val, values[0]->bv_len);
	if (*requestor_sid == NULL)
	    goto enomem;
    }

    goto out;

enomem:
    ret = krb5_enomem(context);
    goto out;

out:
    if (ret) {
	krb5_free_principal(context, *canon_principal);
	*canon_principal = NULL;

	if (requestor_sid) {
	    kdc_object_release(*requestor_sid);
	    *requestor_sid = NULL;
	}
    }

    ldap_value_free_len(values);
    ldap_msgfree(m);
    ldap_memfree(basedn);
    free(filter);
    gss_release_buffer(&minor, &initiator_name_buf);

    return ret;
}

static KRB5_LIB_CALL krb5_error_code
authorize(void *ctx,
          astgs_request_t r,
          gss_const_name_t initiator_name,
          gss_const_OID mech_type,
          OM_uint32 ret_flags,
          krb5_boolean *authorized,
          krb5_principal *mapped_name)
{
    struct altsecid_gss_preauth_authorizer_context *c = ctx;
    struct ad_server_tuple *server = NULL;
    krb5_error_code ret;
    krb5_context context = kdc_request_get_context((kdc_request_t)r);
    const hdb_entry *client = kdc_request_get_client(r);
    krb5_const_principal server_princ = kdc_request_get_server_princ(r);
    krb5_const_realm realm = krb5_principal_get_realm(context, client->principal);
    krb5_boolean reconnect_p = FALSE;
    krb5_boolean is_tgs;
    kdc_data_t requestor_sid = NULL;

    *authorized = FALSE;
    *mapped_name = NULL;

    if (!krb5_principal_is_federated(context, client->principal) ||
        (ret_flags & GSS_C_ANON_FLAG))
        return KRB5_PLUGIN_NO_HANDLE;

    is_tgs = krb5_principal_is_krbtgt(context, server_princ);

    HEIM_TAILQ_FOREACH(server, &c->servers, link) {
        if (strcmp(realm, server->realm) == 0)
            break;
    }

    if (server == NULL) {
        server = calloc(1, sizeof(*server));
        if (server == NULL)
            return krb5_enomem(context);

        server->realm = strdup(realm);
        if (server->realm == NULL) {
            free(server);
            return krb5_enomem(context);
        }

        HEIM_TAILQ_INSERT_HEAD(&c->servers, server, link);
    }

    do {
        if (server->ld == NULL) {
            ret = ad_connect(context, realm, server);
            if (ret)
                return ret;
        }

        ret = ad_lookup(context, realm, server,
                        initiator_name, mech_type,
                        mapped_name, is_tgs ? &requestor_sid : NULL);
        if (ret == KRB5KDC_ERR_SVC_UNAVAILABLE) {
            ldap_unbind_ext_s(server->ld, NULL, NULL);
            server->ld = NULL;

            /* try to reconnect iff we haven't already tried */
            reconnect_p = !reconnect_p;
        }

        *authorized = (ret == 0);
    } while (reconnect_p);

    if (requestor_sid) {
	kdc_request_set_attribute((kdc_request_t)r,
				  HSTR("org.h5l.gss-pa-requestor-sid"), requestor_sid);
	kdc_object_release(requestor_sid);
    }

    return ret;
}

static KRB5_LIB_CALL krb5_error_code
finalize_pac(void *ctx, astgs_request_t r)
{
    kdc_data_t requestor_sid;

    requestor_sid = kdc_request_get_attribute((kdc_request_t)r,
					      HSTR("org.h5l.gss-pa-requestor-sid"));
    if (requestor_sid == NULL)
	return 0;

    kdc_audit_setkv_object((kdc_request_t)r, "gss_requestor_sid", requestor_sid);

    return kdc_request_add_pac_buffer(r, PAC_REQUESTOR_SID,
				      kdc_data_get_data(requestor_sid));
}

static KRB5_LIB_CALL krb5_error_code
init(krb5_context context, void **contextp)
{
    struct altsecid_gss_preauth_authorizer_context *c;

    c = calloc(1, sizeof(*c));
    if (c == NULL)
        return krb5_enomem(context);

    HEIM_TAILQ_INIT(&c->servers);

    *contextp = c;
    return 0;
}

static KRB5_LIB_CALL void
fini(void *context)
{
    struct altsecid_gss_preauth_authorizer_context *c = context;
    struct ad_server_tuple *server, *next;
    OM_uint32 minor;

    HEIM_TAILQ_FOREACH_SAFE(server, &c->servers, link, next) {
        free(server->realm);
        ldap_unbind_ext_s(server->ld, NULL, NULL);
#ifdef LDAP_OPT_X_SASL_GSS_CREDS
        gss_release_cred(&minor, &server->gss_cred);
#endif
        free(server);
    }
}

static krb5plugin_gss_preauth_authorizer_ftable plug_desc =
    { 1, init, fini, authorize, finalize_pac };

static krb5plugin_gss_preauth_authorizer_ftable *plugs[] = { &plug_desc };

static uintptr_t
altsecid_gss_preauth_authorizer_get_instance(const char *libname)
{
    if (strcmp(libname, "krb5") == 0)
        return krb5_get_instance(libname);
    if (strcmp(libname, "kdc") == 0)
        return kdc_get_instance(libname);
    return 0;
}

krb5_plugin_load_ft kdc_gss_preauth_authorizer_plugin_load;

krb5_error_code KRB5_CALLCONV
kdc_gss_preauth_authorizer_plugin_load(heim_pcontext context,
                                       krb5_get_instance_func_t *get_instance,
                                       size_t *num_plugins,
                                       krb5_plugin_common_ftable_cp **plugins)
{
    *get_instance = altsecid_gss_preauth_authorizer_get_instance;
    *num_plugins = sizeof(plugs) / sizeof(plugs[0]);
    *plugins = (krb5_plugin_common_ftable_cp *)plugs;
    return 0;
}
