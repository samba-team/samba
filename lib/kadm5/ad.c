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

#define HAVE_TSASL 1

#include "kadm5_locl.h"
#if 1
#undef OPENLDAP
#undef HAVE_TSASL
#endif
#ifdef OPENLDAP
#include <ldap.h>
#ifdef HAVE_TSASL
#include <tsasl.h>
#endif
#include <resolve.h>
#include <base64.h>
#endif

RCSID("$Id$");

#ifdef OPENLDAP

#define CTX2LP(context) ((LDAP *)((context)->ldap_conn))
#define CTX2BASE(context) ((context)->base_dn)

/*
 * userAccountControl
 */

#define UF_SCRIPT	 			0x00000001
#define UF_ACCOUNTDISABLE			0x00000002
#define UF_UNUSED_0	 			0x00000004
#define UF_HOMEDIR_REQUIRED			0x00000008
#define UF_LOCKOUT	 			0x00000010
#define UF_PASSWD_NOTREQD 			0x00000020
#define UF_PASSWD_CANT_CHANGE 			0x00000040
#define UF_ENCRYPTED_TEXT_PASSWORD_ALLOWED	0x00000080
#define UF_TEMP_DUPLICATE_ACCOUNT       	0x00000100
#define UF_NORMAL_ACCOUNT               	0x00000200
#define UF_UNUSED_1	 			0x00000400
#define UF_INTERDOMAIN_TRUST_ACCOUNT    	0x00000800
#define UF_WORKSTATION_TRUST_ACCOUNT    	0x00001000
#define UF_SERVER_TRUST_ACCOUNT         	0x00002000
#define UF_UNUSED_2	 			0x00004000
#define UF_UNUSED_3	 			0x00008000
#define UF_PASSWD_NOT_EXPIRE			0x00010000
#define UF_MNS_LOGON_ACCOUNT			0x00020000
#define UF_SMARTCARD_REQUIRED			0x00040000
#define UF_TRUSTED_FOR_DELEGATION		0x00080000
#define UF_NOT_DELEGATED			0x00100000
#define UF_USE_DES_KEY_ONLY			0x00200000
#define UF_DONT_REQUIRE_PREAUTH			0x00400000
#define UF_UNUSED_4				0x00800000
#define UF_UNUSED_5				0x01000000
#define UF_UNUSED_6				0x02000000
#define UF_UNUSED_7				0x04000000
#define UF_UNUSED_8				0x08000000
#define UF_UNUSED_9				0x10000000
#define UF_UNUSED_10				0x20000000
#define UF_UNUSED_11				0x40000000
#define UF_UNUSED_12				0x80000000

/*
 *
 */

#ifndef HAVE_TSASL
static int
sasl_interact(LDAP *ld, unsigned flags, void *defaults, void *interact)
{
#if 0
    sasl_interact_t *in = interact;
    char *defresult;

    while (interact->id != SASL_CB_LIST_END) {
        defresult = in->defresult;
	if (defresult == NULL)
	    defresult = "";
	in->result = strdup(defresult);
        in->len = strlen(in->result);
        in++;
    }
#endif
    return LDAP_SUCCESS;
}
#endif

#if 0
static Sockbuf_IO ldap_tsasl_io = {
    NULL,			/* sbi_setup */
    NULL,			/* sbi_remove */
    NULL,			/* sbi_ctrl */
    NULL,			/* sbi_read */
    NULL,			/* sbi_write */
    NULL			/* sbi_close */
};
#endif

#ifdef HAVE_TSASL
static int
ldap_tsasl_bind_s(LDAP *ld,
		  LDAP_CONST char *dn,
		  LDAPControl **serverControls,
		  LDAPControl **clientControls,
		  const char *host)
{
    struct tsasl_peer *peer = NULL;
    struct tsasl_buffer in, out;
    struct berval ccred, *scred;
    char *mech = "GSSAPI"; /* XXX ? */
    int ret, rc;

    ret = tsasl_peer_init(TSASL_FLAGS_INITIATOR |
			  TSASL_FLAGS_CONFIDENTIALITY | 
			  TSASL_FLAGS_INTEGRITY,
			  "ldap",
			  host,
			  &peer);
    if (ret != TSASL_DONE) {
	rc = LDAP_LOCAL_ERROR;
	goto out;
    }

    ret = tsasl_select_mech(peer, mech);
    if (ret != TSASL_DONE) {
	rc = LDAP_LOCAL_ERROR;
	goto out;
    }

    in.tb_data = NULL;
    in.tb_size = 0;

    do {
	ret = tsasl_request(peer, &in, &out);
	if (in.tb_size != 0) {
	    free(in.tb_data);
	    in.tb_data = NULL; 
	    in.tb_size = 0;
	}
	if (ret != TSASL_DONE && ret != TSASL_CONTINUE) {
	    rc = LDAP_AUTH_UNKNOWN;
	    goto out;
	}

	ccred.bv_val = out.tb_data;
	ccred.bv_len = out.tb_size;

	rc = ldap_sasl_bind_s(ld, dn, mech, &ccred,
			      serverControls, clientControls, &scred);
	tsasl_buffer_free(&out);

	if (rc != LDAP_SUCCESS && rc != LDAP_SASL_BIND_IN_PROGRESS) {
	    if(scred && scred->bv_len)
		ber_bvfree(scred);
	    goto out;
	}

	in.tb_data = malloc(scred->bv_len);
	if (in.tb_data == NULL) {
	    rc = LDAP_LOCAL_ERROR;
	    goto out;
	}
	memcpy(in.tb_data, scred->bv_val, scred->bv_len);
	in.tb_size = scred->bv_len;
	ber_bvfree(scred);

    } while (rc == LDAP_SASL_BIND_IN_PROGRESS);

 out:
    if (rc == LDAP_SUCCESS) {
#if 0
	ber_sockbuf_add_io(ld->ld_conns->lconn_sb, &ldap_tsasl_io,
			   LBER_SBIOD_LEVEL_APPLICATION, peer);

#endif
    } else if (peer != NULL)
	tsasl_peer_free(peer);

    return rc;
}
#endif /* HAVE_TSASL */

/*
 *
 */

void static
laddattr(char ***al, int *attrlen, char *attr)
{
    char **a;
    a = realloc(*al, (*attrlen + 2) * sizeof(**al));
    if (a == NULL)
	return;
    a[*attrlen] = attr;
    a[*attrlen + 1] = NULL;
    (*attrlen)++;
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

    if (context->ldap_conn)
	return 0;

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

    for (i = 0; i < num_servers; i++) {
	int lret, version = LDAP_VERSION3;
	LDAP *lp;

	lp = ldap_init(servers[i].server, servers[i].port);
	if (lp == NULL)
	    continue;
	
	if (ldap_set_option(lp, LDAP_OPT_PROTOCOL_VERSION, &version)) {
	    ldap_unbind(lp);
	    continue;
	}
	
	if (ldap_set_option(lp, LDAP_OPT_REFERRALS, LDAP_OPT_OFF)) {
	    ldap_unbind(lp);
	    continue;
	}
	
#ifdef HAVE_TSASL
	lret = ldap_tsasl_bind_s(lp, NULL, NULL, NULL,
				 servers[i].server);
				 
#else
	lret = ldap_sasl_interactive_bind_s(lp, NULL, NULL, NULL, NULL, 
					    LDAP_SASL_QUIET,
					    sasl_interact, NULL);
#endif
	if (lret != LDAP_SUCCESS) {
	    ldap_unbind(lp);
	    continue;
	}

	context->ldap_conn = lp;
	break;
    }
    if (i >= num_servers)
	goto fail;

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

	if (ldap_count_entries(CTX2LP(context), m) > 0) {
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
	} else
	    goto fail;
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

#define NTTIME_EPOCH 0x019DB1DED53E8000LL

static time_t
nt2unixtime(const char *str)
{
    unsigned long long t;
    t = strtoll(str, NULL, 10);
    t = ((t - NTTIME_EPOCH) / (long long)10000000);
    if (t > (((time_t)(~(long long)0)) >> 1))
	return 0;
    return (time_t)t;
}

/* XXX create filter in a better way */

static int
ad_find_entry(kadm5_ad_context *context, const char *fqdn, char **name)
{
    LDAPMessage *m, *m0;
    char **attr = NULL;
    int attrlen = 0;
    char *filter;
    int ret;

    if (name)
	*name = NULL;

    laddattr(&attr, &attrlen, "distinguishedName");

    if (fqdn)
	asprintf(&filter, "(&(objectClass=computer)(dNSHostName=%s))", fqdn);
    else
	return KADM5_RPC_ERROR;

    ret = ldap_search_s(CTX2LP(context), CTX2BASE(context),
			LDAP_SCOPE_SUBTREE, 
			filter, attr, 0, &m);
    free(attr);
    free(filter);
    if (ret)
	return KADM5_RPC_ERROR;

    if (ldap_count_entries(CTX2LP(context), m) < 0) {
	char **vals;
	m0 = ldap_first_entry(CTX2LP(context), m);
	vals = ldap_get_values(CTX2LP(context), m0, "distinguishedName");
	if (vals == NULL || vals[0] == NULL) {
	    ldap_msgfree(m);
	    return KADM5_RPC_ERROR;
	}
	if (name)
	    *name = strdup(vals[0]);
	ldap_msgfree(m);
    } else
	return KADM5_UNK_PRINC;

    return 0;
}

#endif /* OPENLDAP */

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
     *
     * return 0 || KADM5_DUP;
     */

#ifdef OPENLDAP
    int ret;

    ret = ad_get_cred(context, NULL);
    if (ret)
	return ret;

    /*
     */

    if (ad_find_entry(context, "tiffo.l.nxs.se", NULL) == 0)
	return KADM5_DUP;

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
#ifdef OPENLDAP
    LDAPMessage *m, *m0;
    char **attr = NULL;
    int attrlen = 0;
    char *filter, *p, *q, *u;
    int ret;

    /*
     * principal
     * KADM5_PRINCIPAL | KADM5_KVNO | KADM5_ATTRIBUTES
     */

    /*
     * return 0 || KADM5_DUP;
     */

    if (mask & KADM5_KVNO)
	laddattr(&attr, &attrlen, "msDS-KeyVersionNumber");

    if (mask & KADM5_PRINCIPAL) {
	laddattr(&attr, &attrlen, "userPrincipalName");
	laddattr(&attr, &attrlen, "servicePrincipalName");
    }
    laddattr(&attr, &attrlen, "objectClass");
    laddattr(&attr, &attrlen, "lastLogon");
    laddattr(&attr, &attrlen, "badPwdCount");
    laddattr(&attr, &attrlen, "badPasswordTime");
    laddattr(&attr, &attrlen, "pwdLastSet");
    laddattr(&attr, &attrlen, "accountExpires");
    laddattr(&attr, &attrlen, "userAccountControl");

    krb5_unparse_name_short(context->context, principal, &p);
    krb5_unparse_name(context->context, principal, &u);

    /* replace @ in domain part with a / */
    q = strrchr(p, '@');
    if (q && (p != q && *(q - 1) != '\\'))
	*q = '/';

    asprintf(&filter, 
	     "(|(userPrincipalName=%s)(servicePrincipalName=%s))",
	     u, p);
    free(p);
    free(u);

    ret = ldap_search_s(CTX2LP(context), CTX2BASE(context),
			LDAP_SCOPE_SUBTREE, 
			filter, attr, 0, &m);
    free(attr);
    if (ret)
	return KADM5_RPC_ERROR;

    if (ldap_count_entries(CTX2LP(context), m) > 0) {
	char **vals;
	m0 = ldap_first_entry(CTX2LP(context), m);
	if (m0 == NULL) {
	    ldap_msgfree(m);
	    goto fail;
	}
#if 0
	vals = ldap_get_values(CTX2LP(context), m0, "servicePrincipalName");
	if (vals)
	    printf("servicePrincipalName %s\n", vals[0]);
	vals = ldap_get_values(CTX2LP(context), m0, "userPrincipalName");
	if (vals)
	    printf("userPrincipalName %s\n", vals[0]);
	vals = ldap_get_values(CTX2LP(context), m0, "userAccountControl");
	if (vals)
	    printf("userAccountControl %s\n", vals[0]);
#endif
	vals = ldap_get_values(CTX2LP(context), m0, "accountExpires");
	if (vals)
	    entry->princ_expire_time = nt2unixtime(vals[0]);

	vals = ldap_get_values(CTX2LP(context), m0, "lastLogon");
	if (vals)
	    entry->last_success = nt2unixtime(vals[0]);

	vals = ldap_get_values(CTX2LP(context), m0, "badPasswordTime");
	if (vals)
	    entry->last_failed = nt2unixtime(vals[0]);

	vals = ldap_get_values(CTX2LP(context), m0, "pwdLastSet");
	if (vals)
	    entry->last_pwd_change = nt2unixtime(vals[0]);

	vals = ldap_get_values(CTX2LP(context), m0, "badPwdCount");
	if (vals)
	    entry->fail_auth_count = atoi(vals[0]);

	if (mask & KADM5_KVNO) {
	    vals = ldap_get_values(CTX2LP(context), m0, 
				   "msDS-KeyVersionNumber");
	    if (vals)
		entry->kvno = atoi(vals[0]);
	    else
		entry->kvno = 0;
	}
	ldap_msgfree(m);
    } else {
	printf("no entry\n");
	return KADM5_UNK_PRINC;
    }

    if (mask & KADM5_ATTRIBUTES)
	entry->attributes = 0;
    if (mask & KADM5_PRINCIPAL)
	krb5_copy_principal(context->context, principal, &entry->principal);

    return 0;
 fail:
    return KADM5_RPC_ERROR;
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
	entry->kvno = 0;

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

    /*
     * random key
     */

#ifdef OPENLDAP
    krb5_data result_code_string, result_string;
    int result_code, plen;
    kadm5_ret_t ret;
    char *password;

    *keys = NULL;
    *n_keys = 0;

    {
	char p[64];
	krb5_generate_random_block(p, sizeof(p));
	plen = base64_encode(p, sizeof(p), &password);
	if (plen < 0)
	    return ENOMEM;
    }

    ret = ad_get_cred(context, NULL);
    if (ret) {
	free(password);
	return ret;
    }

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
	if (*keys == NULL) {
	    ret = ENOMEM;
	    goto out;
	}
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
	    goto out;
	}
    }
    memset(password, 0, plen);
    free(password);
 out:
    return ret;
#else
    *keys = NULL;
    *n_keys = 0;

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

#ifdef OPENLDAP
    ret = _kadm5_ad_connect(ctx);
    if (ret) {
	kadm5_ad_destroy(ctx);
	return ret;
    }
#endif

    *server_handle = ctx;
    return 0;
}
