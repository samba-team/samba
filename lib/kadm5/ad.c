/*
 * Copyright (c) 2004 Kungliga Tekniska Högskolan
 * (Royal Institute of Technology, Stockholm, Sweden). 
 * All rights reserved. 
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
 * 3. Neither the name of the Institute nor the names of its contributors 
 *    may be used to endorse or promote products derived from this software 
 *    without specific prior written permission. 
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND 
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE 
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE 
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE 
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL 
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS 
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) 
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT 
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY 
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF 
 * SUCH DAMAGE. 
 */

#include "kadm5_locl.h"
#ifdef OPENLDAP
#include <ldap.h>
#if 0
#include <sasl.h>
#endif
#include <resolve.h>
#endif

RCSID("$Id$");

#ifdef OPENLDAP

#define CTX2LP(context) ((LDAP *)((context)->ldap_conn))
#define CTX2BASE(context) ((context)->base_dn)

static int
sasl_interact(LDAP *ld, unsigned flags, void *defaults, void *interact)
{
#if 0
    char *dflt;
    sasl_interact_t *in = interact;

    while (interact->id != SASL_CB_LIST_END) {
        dflt = in->defresult;
	if (dflt == NULL && dflt[0] == '\0')
	    dflt = "";
	in->result = strdup(dflt);
        in->len = strlen(in->result);
        in++;
    }
#endif
    return LDAP_SUCCESS;
}

void static
laddattr(char ***al, int *attrlen, char *attr)
{
    char **a;
    a = realloc(*al, (*attrlen + 2) * sizeof(**al));
    if (a == NULL)
	return;
    a[*attrlen] = attr;
    a[*attrlen + 1] = NULL;
    *al = a;
}


static kadm5_ret_t
_kadm5_ad_connect(void *server_handle)
{
    kadm5_ad_context *context = server_handle;
    struct {
	char *server;
	int port;
    } *s, *servers = NULL;
    int i, num_servers = 0;

    {
	struct dns_reply *r;
	struct resource_record *rr;
	char *domain;

	asprintf(&domain, "_ldap._tcp.%s", context->realm);
	if (domain == NULL)
	    return KADM5_NO_SRV;

	r = dns_lookup(domain, "SRV");
	free(domain);
	if (r == NULL)
	    return KADM5_NO_SRV;
	
	for (rr = r->head ; rr != NULL; rr = rr->next) {
	    if (rr->type != T_SRV)
		continue;
	    s = realloc(servers, sizeof(*servers) * (num_servers + 1));
	    if (s == NULL) {
		dns_free_data(r);
		goto fail;
	    }
	    servers = s;
	    num_servers++;
	    servers[num_servers - 1].port =  rr->u.srv->port;
	    servers[num_servers - 1].server =  strdup(rr->u.srv->target);
	}
	dns_free_data(r);
    }

    if (num_servers == 0)
	return KADM5_NO_SRV;

    if (context->ldap_conn == NULL) {
	int lret, version = LDAP_VERSION3;
	LDAP *lp;

	lp = ldap_init(servers[0].server, servers[0].port);
	if (lp == NULL)
	    return KADM5_RPC_ERROR; 
	
	if (ldap_set_option(lp, LDAP_OPT_PROTOCOL_VERSION, &version)) {
	    ldap_unbind(lp);
	    return KADM5_RPC_ERROR; 
	}
	
	if (ldap_set_option(lp, LDAP_OPT_REFERRALS, LDAP_OPT_OFF)) {
	    ldap_unbind(lp);
	    return KADM5_RPC_ERROR; 
	}
	
	lret = ldap_sasl_interactive_bind_s(lp, NULL, NULL, NULL, NULL, 
					    LDAP_SASL_QUIET,
					    sasl_interact, NULL);
	if (lret != LDAP_SUCCESS) {
	    ldap_unbind(lp);
	    return KADM5_RPC_ERROR; 
	}

	context->ldap_conn = lp;
    }

    {
	LDAPMessage *m, *m0;
	char **attr = NULL;
	int attrlen = 0;
	char **vals;
	int ret;
	
	laddattr(&attr, &attrlen, "defaultNamingContext");

	ret = ldap_search_s(CTX2LP(context), "", LDAP_SCOPE_BASE, 
			    "objectclass=*", attr, 0, &m);
	free(attr);
	if (ret != 0)
	    goto fail;

	if (ldap_count_entries(CTX2LP(context), m) == 1) {
	    m0 = ldap_first_entry(CTX2LP(context), m);
	    if (m0 == NULL) {
		ldap_msgfree(m);
		goto fail;
	    }
	    vals = ldap_get_values(CTX2LP(context), 
				   m0, "defaultNamingContext");
	    if (vals == NULL)
		goto fail;
	    context->base_dn = strdup(vals[0]);
	}
	ldap_msgfree(m);
    }

    for (i = 0; i < num_servers; i++)
	free(servers[i].server);
    free(servers);

    return 0;

 fail:
    for (i = 0; i < num_servers; i++)
	free(servers[i].server);
    free(servers);

    if (context->ldap_conn) {
	ldap_unbind(CTX2LP(context));
	context->ldap_conn = NULL;
    }
    return KADM5_RPC_ERROR;
}
#endif

static kadm5_ret_t
ad_get_cred(kadm5_ad_context *context, const char *password)
{
    kadm5_ret_t ret;
    krb5_ccache cc;
    char *service;

    if (context->ccache)
	return 0;

    asprintf(&service, "%s/%s@%s", KRB5_TGS_NAME,
	     context->realm, context->realm);
    if (service == NULL)
	return ENOMEM;

    ret = _kadm5_c_get_cred_cache(context->context,
				  context->client_name,
				  service,
				  password, krb5_prompter_posix, 
				  NULL, NULL, &cc);
    free(service);
    if(ret)
	return ret; /* XXX */
    context->ccache = cc;
    return 0;
}


static kadm5_ret_t
kadm5_ad_chpass_principal(void *server_handle,
			  krb5_principal principal,
			  char *password)
{
    kadm5_ad_context *context = server_handle;
    krb5_data result_code_string, result_string;
    int result_code;
    kadm5_ret_t ret;

    ret = ad_get_cred(context, NULL);
    if (ret)
	return ret;

    krb5_data_zero (&result_code_string);
    krb5_data_zero (&result_string);

    ret = krb5_set_password (context->context, 
			     context->ccache,
			     password,
			     principal,
			     &result_code,
			     &result_code_string,
			     &result_string);

    krb5_data_free (&result_code_string);
    krb5_data_free (&result_string);

    /* XXX do mapping here on error codes */

    return ret;
}

static kadm5_ret_t
kadm5_ad_create_principal(void *server_handle,
			  kadm5_principal_ent_t entry,
			  u_int32_t mask,
			  char *password)
{
    kadm5_ad_context *context = server_handle;

    /*
     * principal
     * KADM5_PRINCIPAL|KADM5_ATTRIBUTES|KADM5_PRINC_EXPIRE_TIME
     */

    /*
     * return 0 || KADM5_DUP;
     */

#ifdef OPENLDAP
    context = NULL; /* XXX */
    return KADM5_DUP; /* XXX */
#else
    krb5_set_error_string(context->context, "Function not implemented");
    return KADM5_RPC_ERROR;
#endif
}

static kadm5_ret_t
kadm5_ad_delete_principal(void *server_handle, krb5_principal principal)
{
    kadm5_ad_context *context = server_handle;
    krb5_set_error_string(context->context, "Function not implemented");
    return KADM5_RPC_ERROR;
}

static kadm5_ret_t
kadm5_ad_destroy(void *server_handle)
{
    kadm5_ad_context *context = server_handle;

    if (context->ccache)
	krb5_cc_destroy(context->context, context->ccache);

#ifdef OPENLDAP
    {
	LDAP *lp = CTX2LP(context);
	if (lp)
	    ldap_unbind(lp);
    }
    return 0;
#else
    krb5_set_error_string(context->context, "Function not implemented");
    return KADM5_RPC_ERROR;
#endif
}

static kadm5_ret_t
kadm5_ad_flush(void *server_handle)
{
    kadm5_ad_context *context = server_handle;
#ifdef OPENLDAP
    krb5_set_error_string(context->context, "Function not implemented");
    return KADM5_RPC_ERROR;
#else
    krb5_set_error_string(context->context, "Function not implemented");
    return KADM5_RPC_ERROR;
#endif
}

static kadm5_ret_t
kadm5_ad_get_principal(void *server_handle,
		       krb5_principal principal, 
		       kadm5_principal_ent_t entry, 
		       u_int32_t mask)
{
    kadm5_ad_context *context = server_handle;
    LDAPMessage *m;
    char **attr = NULL;
    int attrlen = 0;
    char *filter, *p;
    int ret;

    /*
     * principal
     * KADM5_PRINCIPAL | KADM5_KVNO | KADM5_ATTRIBUTES
     */

    /*
     * return 0 || KADM5_DUP;
     */
#ifdef OPENLDAP

    if (mask & KADM5_KVNO)
	laddattr(&attr, &attrlen, "msDS-KeyVersionNumber");

    if (mask & KADM5_PRINCIPAL) {
	laddattr(&attr, &attrlen, "userPrincipalName");
	laddattr(&attr, &attrlen, "servicePrincipalName");
    }

    krb5_unparse_name(context->context, principal, &p);

    asprintf(&filter, "(|(userPrincipalName=%s)(servicePrincipalName=%s))",
	     p, p);
    free(p);

    ret = ldap_search_s(CTX2LP(context), CTX2BASE(context),
			LDAP_SCOPE_SUBTREE, 
			filter, attr, 0, &m);
    free(attr);

    if (mask & KADM5_KVNO)
	entry->kvno = 0; /* XXX */
    if (mask & KADM5_ATTRIBUTES)
	entry->attributes = 0;
    if (mask & KADM5_PRINCIPAL)
	krb5_copy_principal(context->context, principal, &entry->principal);

    return 0;
#else
    krb5_set_error_string(context->context, "Function not implemented");
    return KADM5_RPC_ERROR;
#endif
}

static kadm5_ret_t
kadm5_ad_get_principals(void *server_handle,
			const char *exp,
			char ***principals,
			int *count)
{
    kadm5_ad_context *context = server_handle;

    /*
     * KADM5_PRINCIPAL | KADM5_KVNO | KADM5_ATTRIBUTES
     */

#ifdef OPENLDAP
    kadm5_ret_t ret;

    ret = _kadm5_ad_connect(server_handle);
    if (ret)
	return ret;

    krb5_set_error_string(context->context, "Function not implemented");
    return KADM5_RPC_ERROR;
#else
    krb5_set_error_string(context->context, "Function not implemented");
    return KADM5_RPC_ERROR;
#endif
}

static kadm5_ret_t
kadm5_ad_get_privs(void *server_handle, u_int32_t*privs)
{
    kadm5_ad_context *context = server_handle;
    krb5_set_error_string(context->context, "Function not implemented");
    return KADM5_RPC_ERROR;
}

static kadm5_ret_t
kadm5_ad_modify_principal(void *server_handle,
			  kadm5_principal_ent_t entry,
			  u_int32_t mask)
{
    kadm5_ad_context *context = server_handle;

    /* 
     * KADM5_ATTRIBUTES
     * KRB5_KDB_DISALLOW_ALL_TIX (| KADM5_KVNO)
     */

    if (mask & KADM5_KVNO)
	entry->kvno = 1;

#ifdef OPENLDAP
    context = NULL; /* XXX */
    return 0;
#else
    krb5_set_error_string(context->context, "Function not implemented");
    return KADM5_RPC_ERROR;
#endif
}

static kadm5_ret_t
kadm5_ad_randkey_principal(void *server_handle,
			   krb5_principal principal,
			   krb5_keyblock **keys,
			   int *n_keys)
{
    kadm5_ad_context *context = server_handle;

    *keys = NULL;
    *n_keys = 0;

    /*
     * random key
     */

#ifdef OPENLDAP
#if 0
    LDAP *lp = CTX2LP(context);
#endif
    krb5_data result_code_string, result_string;
    int result_code;
    kadm5_ret_t ret;
    char password[128];

#if 1
    if (1)
	return KADM5_RPC_ERROR;
#else
    random_password (password, sizeof(password));
#endif

    ret = ad_get_cred(context, NULL);
    if (ret)
	return ret;

    krb5_data_zero (&result_code_string);
    krb5_data_zero (&result_string);

    ret = krb5_set_password (context->context, 
			     context->ccache,
			     password,
			     principal,
			     &result_code,
			     &result_code_string,
			     &result_string);

    krb5_data_free (&result_code_string);
    krb5_data_free (&result_string);

    if (ret == 0) {

	*keys = malloc(sizeof(**keys) * 1);
	if (*keys == NULL)
	    return ENOMEM;
	*n_keys = 1;

	ret = krb5_string_to_key(context->context,
				 ENCTYPE_ARCFOUR_HMAC_MD5,
				 password,
				 principal,
				 &(*keys)[0]);
	memset(password, 0, sizeof(password));
	if (ret) {
	    free(*keys);
	    *keys = NULL;
	    *n_keys = 0;
	    return ret;
	}
    }

    return ret;
#else
    krb5_set_error_string(context->context, "Function not implemented");
    return KADM5_RPC_ERROR;
#endif
}

static kadm5_ret_t
kadm5_ad_rename_principal(void *server_handle,
			  krb5_principal from,
			  krb5_principal to)
{
    kadm5_ad_context *context = server_handle;
    krb5_set_error_string(context->context, "Function not implemented");
    return KADM5_RPC_ERROR;
}

static kadm5_ret_t
kadm5_ad_chpass_principal_with_key(void *server_handle, 
				   krb5_principal princ,
				   int n_key_data,
				   krb5_key_data *key_data)
{
    kadm5_ad_context *context = server_handle;
    krb5_set_error_string(context->context, "Function not implemented");
    return KADM5_RPC_ERROR;
}

static void
set_funcs(kadm5_ad_context *c)
{
#define SET(C, F) (C)->funcs.F = kadm5_ad_ ## F
    SET(c, chpass_principal);
    SET(c, chpass_principal_with_key);
    SET(c, create_principal);
    SET(c, delete_principal);
    SET(c, destroy);
    SET(c, flush);
    SET(c, get_principal);
    SET(c, get_principals);
    SET(c, get_privs);
    SET(c, modify_principal);
    SET(c, randkey_principal);
    SET(c, rename_principal);
}

kadm5_ret_t 
kadm5_ad_init_with_password(const char *client_name,
			    const char *password,
			    const char *service_name,
			    kadm5_config_params *realm_params,
			    unsigned long struct_version,
			    unsigned long api_version,
			    void **server_handle)
{
    krb5_context context;
    kadm5_ret_t ret;
    kadm5_ad_context *ctx;

    ret = krb5_init_context(&context);
    if (ret)
	return ret;

    ctx = malloc(sizeof(*ctx));
    if(ctx == NULL) {
	krb5_free_context(context);
	return ENOMEM;
    }
    memset(ctx, 0, sizeof(*ctx));
    set_funcs(ctx);

    ctx->context = context;
    krb5_add_et_list (context, initialize_kadm5_error_table_r);

    ret = krb5_parse_name(ctx->context, client_name, &ctx->caller);
    if(ret) {
	krb5_free_context(context);
	free(ctx);
	return ret;
    }

    if(realm_params->mask & KADM5_CONFIG_REALM) {
	ret = 0;
	ctx->realm = strdup(realm_params->realm);
	if (ctx->realm == NULL)
	    ret = ENOMEM;
    } else
	ret = krb5_get_default_realm(ctx->context, &ctx->realm);
    if (ret) {
	krb5_free_context(context);
	free(ctx);
	return ret;
    }

    ctx->client_name = strdup(client_name);

    if(password != NULL && *password != '\0')
	ret = ad_get_cred(ctx, password);
    else
	ret = ad_get_cred(ctx, NULL);
    if(ret) {
	kadm5_ad_destroy(ctx);
	return ret;
    }

    ret = _kadm5_ad_connect(ctx);
    if (ret) {
	kadm5_ad_destroy(ctx);
	return ret;
    }

    *server_handle = ctx;
    return 0;
}
