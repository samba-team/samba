/*
 * Copyright (c) 1997-2007 Kungliga Tekniska Högskolan
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

#include "kdc_locl.h"
#include "krb5_err.h"
#include "krb5_locl.h"

#ifdef TIME_T_SIGNED
#if SIZEOF_TIME_T == 4
#define MAX_TIME ((time_t)INT32_MAX)
#elif SIZEOF_TIME_T == 8
#define MAX_TIME ((time_t)INT64_MAX)
#else
#error "Unexpected sizeof(time_t)"
#endif
#else

#if SIZEOF_TIME_T == 4
#define MAX_TIME ((time_t)UINT32_MAX)
#else
#define MAX_TIME ((time_t)UINT64_MAX)
#endif
#endif

#undef __attribute__
#define __attribute__(X)

void
_kdc_fix_time(time_t **t)
{
    if(*t == NULL){
	ALLOC(*t);
	**t = MAX_TIME;
    }
    if(**t == 0) **t = MAX_TIME; /* fix for old clients */
}

static int
realloc_method_data(METHOD_DATA *md)
{
    PA_DATA *pa;
    pa = realloc(md->val, (md->len + 1) * sizeof(*md->val));
    if(pa == NULL)
	return ENOMEM;
    md->val = pa;
    md->len++;
    return 0;
}

static krb5_error_code
get_pa_etype_info2(krb5_context context,
		   krb5_kdc_configuration *config,
		   METHOD_DATA *md, Key *ckey,
		   krb5_boolean include_salt);

static krb5_error_code
set_salt_padata(krb5_context context,
                krb5_kdc_configuration *config,
                METHOD_DATA *md, Key *key)
{
    if (!key->salt)
        return 0;

    return get_pa_etype_info2(context, config, md, key, TRUE);
}

const PA_DATA*
_kdc_find_padata(const KDC_REQ *req, int *start, int type)
{
    if (req->padata == NULL)
	return NULL;

    while((size_t)*start < req->padata->len){
	(*start)++;
	if(req->padata->val[*start - 1].padata_type == (unsigned)type)
	    return &req->padata->val[*start - 1];
    }
    return NULL;
}

/*
 * This is a hack to allow predefined weak services, like afs to
 * still use weak types
 */

krb5_boolean
_kdc_is_weak_exception(krb5_principal principal, krb5_enctype etype)
{
    if (principal->name.name_string.len > 0 &&
	strcmp(principal->name.name_string.val[0], "afs") == 0 &&
	(etype == ETYPE_DES_CBC_CRC
	 || etype == ETYPE_DES_CBC_MD4
	 || etype == ETYPE_DES_CBC_MD5))
	return TRUE;
    return FALSE;
}


/*
 * Detect if `key' is the using the the precomputed `default_salt'.
 */

static krb5_boolean
is_default_salt_p(const krb5_salt *default_salt, const Key *key)
{
    if (key->salt == NULL)
	return TRUE;
    if (default_salt->salttype != key->salt->type)
	return FALSE;
    if (krb5_data_cmp(&default_salt->saltvalue, &key->salt->salt) != 0)
	return FALSE;
    return TRUE;
}

/*
 * Detect if `key' is the using the the precomputed `default_salt'
 * (for des-cbc-crc) or any salt otherwise.
 *
 * This is for avoiding Kerberos v4 (yes really) keys in AS-REQ as
 * that salt is strange, and a buggy client will try to use the
 * principal as the salt and not the returned value.
 */

static krb5_boolean
is_good_salt_p(const krb5_salt *default_salt, const Key *key)
{
    if (key->key.keytype == KRB5_ENCTYPE_DES_CBC_CRC)
	return is_default_salt_p(default_salt, key);

    return TRUE;
}

krb5_boolean
_kdc_is_anon_request(const KDC_REQ *req)
{
    const KDC_REQ_BODY *b = &req->req_body;

    /*
     * Versions of Heimdal from 0.9rc1 through 1.50 use bit 14 instead
     * of 16 for request_anonymous, as indicated in the anonymous draft
     * prior to version 11. Bit 14 is assigned to S4U2Proxy, but S4U2Proxy
     * requests are only sent to the TGS and, in any case, would have an
     * additional ticket present.
     */
    return b->kdc_options.request_anonymous ||
	   (b->kdc_options.cname_in_addl_tkt && !b->additional_tickets);
}

/*
 * return the first appropriate key of `princ' in `ret_key'.  Look for
 * all the etypes in (`etypes', `len'), stopping as soon as we find
 * one, but preferring one that has default salt.
 *
 * XXX This function does way way too much.  Split it up!
 *
 * XXX `etypes' and `len' are always `b->etype.val' and `b->etype.len' -- the
 *     etype list from the KDC-REQ-BODY, which is available here as
 *     `r->req->req_body', so we could just stop having it passed in.
 *
 * XXX Picking an enctype(s) for PA-ETYPE-INFO* is rather different than
 *     picking an enctype for a ticket's session key.  The former is what we do
 *     here when `(flags & KFE_IS_PREAUTH)', the latter otherwise.
 */

krb5_error_code
_kdc_find_etype(astgs_request_t r, uint32_t flags,
		krb5_enctype *etypes, unsigned len,
		krb5_enctype *ret_enctype, Key **ret_key,
		krb5_boolean *ret_default_salt)
{
    krb5_boolean use_strongest_session_key;
    krb5_boolean is_preauth = flags & KFE_IS_PREAUTH;
    krb5_boolean is_tgs = flags & KFE_IS_TGS;
    hdb_entry *princ;
    krb5_principal request_princ;
    krb5_error_code ret;
    krb5_salt def_salt;
    krb5_enctype enctype = ETYPE_NULL;
    const krb5_enctype *p;
    Key *key = NULL;
    size_t i, k, m;

    if (is_preauth && (flags & KFE_USE_CLIENT) &&
        r->client->flags.synthetic)
        return KRB5KDC_ERR_ETYPE_NOSUPP;

    if ((flags & KFE_USE_CLIENT) && !r->client->flags.synthetic) {
	princ = r->client;
	request_princ = r->client_princ;
    } else {
	princ = r->server;
	request_princ = r->server->principal;
    }

    use_strongest_session_key =
	is_preauth ? r->config->preauth_use_strongest_session_key
            : (is_tgs ? r->config->tgt_use_strongest_session_key :
		        r->config->svc_use_strongest_session_key);

    /* We'll want to avoid keys with v4 salted keys in the pre-auth case... */
    ret = krb5_get_pw_salt(r->context, request_princ, &def_salt);
    if (ret)
	return ret;

    ret = KRB5KDC_ERR_ETYPE_NOSUPP;

    /*
     * Pick an enctype that is in the intersection of:
     *
     *  - permitted_enctypes (local policy)
     *  - requested enctypes (KDC-REQ-BODY's etype list)
     *  - the client's long-term keys' enctypes
     *    OR
     *    the server's configured etype list
     *
     * There are two sub-cases:
     *
     *  - use local enctype preference (local policy)
     *  - use the client's preference list
     */

    if (use_strongest_session_key) {
	/*
	 * Pick the strongest key that the KDC, target service, and
	 * client all support, using the local cryptosystem enctype
	 * list in strongest-to-weakest order to drive the search.
	 *
	 * This is not what RFC4120 says to do, but it encourages
	 * adoption of stronger enctypes.  This doesn't play well with
	 * clients that have multiple Kerberos client implementations
	 * with different supported enctype lists sharing the same ccache.
	 */

	/* drive the search with local supported enctypes list */
	p = krb5_kerberos_enctypes(r->context);
	for (i = 0;
	    p[i] != ETYPE_NULL && enctype == ETYPE_NULL;
	    i++) {
	    if (krb5_enctype_valid(r->context, p[i]) != 0 &&
                !_kdc_is_weak_exception(princ->principal, p[i]))
		continue;

	    /* check that the client supports it too */
	    for (k = 0; k < len && enctype == ETYPE_NULL; k++) {

		if (p[i] != etypes[k])
		    continue;

                if (!is_preauth && (flags & KFE_USE_CLIENT)) {
                    /*
                     * It suffices that the client says it supports this
                     * enctype in its KDC-REQ-BODY's etype list, which is what
                     * `etypes' is here.
                     */
                    enctype = p[i];
                    ret = 0;
                    break;
                }

                /* check target princ support */
		key = NULL;
                if (!is_preauth && !(flags & KFE_USE_CLIENT) && princ->etypes) {
                    /*
                     * Use the etypes list from the server's HDB entry instead
                     * of deriving it from its long-term keys.  This allows an
                     * entry to have just one long-term key but record support
                     * for multiple enctypes.
                     */
                    for (m = 0; m < princ->etypes->len; m++) {
                        if (p[i] == princ->etypes->val[m]) {
                            enctype = p[i];
                            ret = 0;
                            break;
                        }
                    }
                } else {
                    /*
                     * Use the entry's long-term keys as the source of its
                     * supported enctypes, either because we're making
                     * PA-ETYPE-INFO* or because we're selecting a session key
                     * enctype.
                     */
                    while (hdb_next_enctype2key(r->context, princ, NULL,
                                                 p[i], &key) == 0) {
                        if (key->key.keyvalue.length == 0) {
                            ret = KRB5KDC_ERR_NULL_KEY;
                            continue;
                        }
                        enctype = p[i];
                        ret = 0;
                        if (is_preauth && ret_key != NULL &&
                            !is_good_salt_p(&def_salt, key))
                            continue;
                    }
                }
	    }
	}
    } else {
	/*
	 * Pick the first key from the client's enctype list that is
	 * supported by the cryptosystem and by the given principal.
	 *
	 * RFC4120 says we SHOULD pick the first _strong_ key from the
	 * client's list... not the first key...  If the admin disallows
	 * weak enctypes in krb5.conf and selects this key selection
	 * algorithm, then we get exactly what RFC4120 says.
	 */
	for(i = 0; ret != 0 && i < len; i++) {

	    if (krb5_enctype_valid(r->context, etypes[i]) != 0 &&
		!_kdc_is_weak_exception(princ->principal, etypes[i]))
		continue;

	    key = NULL;
	    while (ret != 0 &&
                   hdb_next_enctype2key(r->context, princ, NULL,
					etypes[i], &key) == 0) {
		if (key->key.keyvalue.length == 0) {
		    ret = KRB5KDC_ERR_NULL_KEY;
		    continue;
		}
                enctype = etypes[i];
		ret = 0;
		if (is_preauth && ret_key != NULL &&
		    !is_good_salt_p(&def_salt, key))
		    continue;
	    }
	}
    }

    if (ret == 0 && enctype == ETYPE_NULL) {
        /*
         * if the service principal is one for which there is a known 1DES
         * exception and no other enctype matches both the client request and
         * the service key list, provide a DES-CBC-CRC key.
         */
	if (ret_key == NULL &&
	    _kdc_is_weak_exception(princ->principal, ETYPE_DES_CBC_CRC)) {
            ret = 0;
            enctype = ETYPE_DES_CBC_CRC;
        } else {
            ret = KRB5KDC_ERR_ETYPE_NOSUPP;
        }
    }

    if (ret == 0) {
	if (ret_enctype != NULL)
	    *ret_enctype = enctype;
	if (ret_key != NULL)
	    *ret_key = key;
	if (ret_default_salt != NULL)
	    *ret_default_salt = is_default_salt_p(&def_salt, key);
    }

    krb5_free_salt (r->context, def_salt);
    return ret;
}

/*
 * The principal's session_etypes must be sorted in order of strength, with
 * preferred etype first.
*/
krb5_error_code
_kdc_find_session_etype(astgs_request_t r,
			krb5_enctype *etypes, size_t len,
			const hdb_entry *princ,
			krb5_enctype *ret_enctype)
{
    size_t i;

    if (princ->session_etypes == NULL) {
	/* The principal must have session etypes available. */
	return KRB5KDC_ERR_ETYPE_NOSUPP;
    }

    /* Loop over the client's specified etypes. */
    for (i = 0; i < len; ++i) {
	size_t j;

	/* Check that the server also supports the etype. */
	for (j = 0; j < princ->session_etypes->len; ++j) {
	    if (princ->session_etypes->val[j] == etypes[i]) {
		*ret_enctype = etypes[i];
		return 0;
	    }
	}
    }

    return KRB5KDC_ERR_ETYPE_NOSUPP;
}

krb5_error_code
_kdc_make_anonymous_principalname (PrincipalName *pn)
{
    pn->name_type = KRB5_NT_WELLKNOWN;
    pn->name_string.len = 2;
    pn->name_string.val = calloc(2, sizeof(*pn->name_string.val));
    if (pn->name_string.val == NULL)
	goto failed;

    pn->name_string.val[0] = strdup(KRB5_WELLKNOWN_NAME);
    if (pn->name_string.val[0] == NULL)
	goto failed;

    pn->name_string.val[1] = strdup(KRB5_ANON_NAME);
    if (pn->name_string.val[1] == NULL)
	goto failed;

    return 0;

failed:
    free_PrincipalName(pn);

    pn->name_type = KRB5_NT_UNKNOWN;
    pn->name_string.len = 0;
    pn->name_string.val = NULL;

    return ENOMEM;
}

static void
_kdc_r_log(astgs_request_t r, int level, const char *fmt, ...)
	__attribute__ ((__format__ (__printf__, 3, 4)))
{
    va_list ap;
    char *s;
    va_start(ap, fmt);
    s = kdc_log_msg_va(r->context, r->config, level, fmt, ap);
    if(s) free(s);
    va_end(ap);
}

void
_kdc_set_const_e_text(astgs_request_t r, const char *e_text)
{
    /* We should never see this */
    if (r->e_text) {
	kdc_log(r->context, r->config, 1,
                "trying to replace e-text \"%s\" with \"%s\"\n",
		r->e_text, e_text);
	return;
    }

    r->e_text = e_text;
    kdc_log(r->context, r->config, 4, "%s", e_text);
}

void
_kdc_set_e_text(astgs_request_t r, const char *fmt, ...)
	__attribute__ ((__format__ (__printf__, 2, 3)))
{
    va_list ap;
    char *e_text = NULL;
    int vasprintf_ret;

    va_start(ap, fmt);
    vasprintf_ret = vasprintf(&e_text, fmt, ap);
    va_end(ap);

    if (vasprintf_ret < 0 || !e_text) {
	/* not much else to do... */
        kdc_log(r->context, r->config, 1,
                "Could not set e_text: %s (out of memory)", fmt);
	return;
    }

    /* We should never see this */
    if (r->e_text) {
	kdc_log(r->context, r->config, 1, "trying to replace e-text: %s\n",
		e_text);
	free(e_text);
	return;
    }

    r->e_text = e_text;
    r->e_text_buf = e_text;
    kdc_log(r->context, r->config, 4, "%s", e_text);
}

void
_kdc_log_timestamp(astgs_request_t r, const char *type,
		   KerberosTime authtime, KerberosTime *starttime,
		   KerberosTime endtime, KerberosTime *renew_till)
{
    krb5_kdc_configuration *config = r->config;
    char authtime_str[100], starttime_str[100],
	endtime_str[100], renewtime_str[100];

    if (authtime)
	kdc_audit_setkv_number((kdc_request_t)r, "auth", authtime);
    if (starttime && *starttime)
	kdc_audit_setkv_number((kdc_request_t)r, "start", *starttime);
    if (endtime)
	kdc_audit_setkv_number((kdc_request_t)r, "end", endtime);
    if (renew_till && *renew_till)
	kdc_audit_setkv_number((kdc_request_t)r, "renew", *renew_till);

    krb5_format_time(r->context, authtime,
		     authtime_str, sizeof(authtime_str), TRUE);
    if (starttime)
	krb5_format_time(r->context, *starttime,
			 starttime_str, sizeof(starttime_str), TRUE);
    else
	strlcpy(starttime_str, "unset", sizeof(starttime_str));
    krb5_format_time(r->context, endtime,
		     endtime_str, sizeof(endtime_str), TRUE);
    if (renew_till)
	krb5_format_time(r->context, *renew_till,
			 renewtime_str, sizeof(renewtime_str), TRUE);
    else
	strlcpy(renewtime_str, "unset", sizeof(renewtime_str));

    kdc_log(r->context, config, 4,
	    "%s authtime: %s starttime: %s endtime: %s renew till: %s",
	    type, authtime_str, starttime_str, endtime_str, renewtime_str);
}

/*
 *
 */

#ifdef PKINIT

static krb5_error_code
pa_pkinit_validate(astgs_request_t r, const PA_DATA *pa)
{
    pk_client_params *pkp = NULL;
    char *client_cert = NULL;
    krb5_error_code ret;

    ret = _kdc_pk_rd_padata(r, pa, &pkp);
    if (ret || pkp == NULL) {
	if (ret == HX509_CERT_REVOKED ||
	    ret == KRB5_KDC_ERR_CLIENT_NOT_TRUSTED) {

	    ret = KRB5_KDC_ERR_CLIENT_NOT_TRUSTED;
	} else if (ret == KRB5_KDC_ERR_CERTIFICATE_MISMATCH) {
	    ret = KRB5_KDC_ERR_CERTIFICATE_MISMATCH;
	} else {
	    ret = KRB5KRB_AP_ERR_BAD_INTEGRITY;
	}
	_kdc_r_log(r, 4, "Failed to decode PKINIT PA-DATA -- %s",
		   r->cname);
	goto out;
    }

    /* Validate the freshness token. */
    ret = _kdc_pk_validate_freshness_token(r, pkp);
    if (ret) {
	_kdc_r_log(r, 4, "Failed to validate freshness token");
	goto out;
    }

    ret = _kdc_pk_check_client(r, pkp, &client_cert);
    if (client_cert)
	kdc_audit_addkv((kdc_request_t)r, 0, KDC_REQUEST_KV_PKINIT_CLIENT_CERT,
			"%s", client_cert);
    if (ret) {
	_kdc_set_e_text(r, "PKINIT certificate not allowed to "
			"impersonate principal");
	kdc_audit_setkv_number((kdc_request_t)r, KDC_REQUEST_KV_AUTH_EVENT,
			       KDC_AUTH_EVENT_CLIENT_NAME_UNAUTHORIZED);
	goto out;
    }

    r->pa_endtime = _kdc_pk_endtime(pkp);
    if (!r->client->flags.synthetic)
        r->pa_max_life = _kdc_pk_max_life(pkp);

    _kdc_r_log(r, 4, "PKINIT pre-authentication succeeded -- %s using %s",
	       r->cname, client_cert);

    ret = _kdc_pk_mk_pa_reply(r, pkp);
    if (ret) {
	_kdc_set_e_text(r, "Failed to build PK-INIT reply");
	goto out;
    }
    ret = _kdc_add_initial_verified_cas(r->context, r->config,
					pkp, &r->et);

    kdc_audit_setkv_number((kdc_request_t)r, KDC_REQUEST_KV_AUTH_EVENT,
			   KDC_AUTH_EVENT_PREAUTH_SUCCEEDED);

    /*
     * Match Windows by preferring the authenticator nonce over the one in the
     * request body.
     */
    r->ek.nonce = _kdc_pk_nonce(pkp);

 out:
    if (pkp)
	_kdc_pk_free_client_param(r->context, pkp);
    free(client_cert);

    return ret;
}

#endif /* PKINIT */

static krb5_error_code
pa_gss_validate(astgs_request_t r, const PA_DATA *pa)
{
    gss_client_params *gcp = NULL;
    char *client_name = NULL;
    krb5_error_code ret;
    int open = 0;

    ret = _kdc_gss_rd_padata(r, pa, &gcp, &open);
    if (ret && gcp == NULL)
	return ret;

    if (open) {
	ret = _kdc_gss_check_client(r, gcp, &client_name);
	if (client_name)
	    kdc_audit_addkv((kdc_request_t)r, 0, KDC_REQUEST_KV_GSS_INITIATOR,
			    "%s", client_name);
	if (ret) {
	    _kdc_set_e_text(r, "GSS-API client not allowed to "
			    "impersonate principal");
	    kdc_audit_setkv_number((kdc_request_t)r, KDC_REQUEST_KV_AUTH_EVENT,
				   KDC_AUTH_EVENT_CLIENT_NAME_UNAUTHORIZED);
	    goto out;
	}

	r->pa_endtime = _kdc_gss_endtime(r, gcp);

	_kdc_r_log(r, 4, "GSS pre-authentication succeeded -- %s using %s",
		   r->cname, client_name);
	kdc_audit_setkv_number((kdc_request_t)r, KDC_REQUEST_KV_AUTH_EVENT,
			       KDC_AUTH_EVENT_PREAUTH_SUCCEEDED);

	ret = _kdc_gss_mk_composite_name_ad(r, gcp);
	if (ret) {
	    _kdc_set_e_text(r, "Failed to build GSS authorization data");
	    goto out;
	}
    }

    ret = _kdc_gss_mk_pa_reply(r, gcp);
    if (ret) {
	if (ret != KRB5_KDC_ERR_MORE_PREAUTH_DATA_REQUIRED)
	    _kdc_set_e_text(r, "Failed to build GSS pre-authentication reply");
	goto out;
    }

    ret = kdc_request_set_attribute((kdc_request_t)r,
				    HSTR("org.h5l.pa-gss-client-params"), gcp);
    if (ret)
	goto out;

out:
    kdc_object_release(gcp);
    free(client_name);

    return ret;
}

static krb5_error_code
pa_gss_finalize_pac(astgs_request_t r)
{
    gss_client_params *gcp;

    gcp = kdc_request_get_attribute((kdc_request_t)r, HSTR("org.h5l.pa-gss-client-params"));

    heim_assert(gcp != NULL, "invalid GSS-API client params");

    return _kdc_gss_finalize_pac(r, gcp);
}

static krb5_error_code
pa_enc_chal_decrypt_kvno(astgs_request_t r,
			 krb5_enctype aenctype,
			 krb5_data *pepper1client,
			 krb5_data *pepper1kdc,
			 krb5_data *pepper2,
			 krb5_kvno kvno,
			 EncryptedData *enc_data,
			 krb5_keyblock *KDCchallengekey,
			 struct Key **used_key)
{
    unsigned int invalidKeys = 0;
    krb5_error_code ret;
    const Keys *keys = NULL;
    unsigned int i;

    if (KDCchallengekey)
	krb5_keyblock_zero(KDCchallengekey);
    if (used_key)
	*used_key = NULL;

    keys = hdb_kvno2keys(r->context, r->client, kvno);
    if (keys == NULL) {
	return KRB5KDC_ERR_ETYPE_NOSUPP;
    }

    for (i = 0; i < keys->len; i++) {
	struct Key *k = &keys->val[i];
	krb5_crypto challengecrypto, longtermcrypto;
	krb5_keyblock client_challengekey;

	ret = krb5_crypto_init(r->context, &k->key, 0, &longtermcrypto);
	if (ret)
	    continue;

	ret = krb5_crypto_fx_cf2(r->context, r->armor_crypto, longtermcrypto,
				 pepper1client, pepper2, aenctype,
				 &client_challengekey);
	if (ret) {
	    krb5_crypto_destroy(r->context, longtermcrypto);
	    continue;
	}

	ret = krb5_crypto_init(r->context, &client_challengekey, 0,
			       &challengecrypto);
	krb5_free_keyblock_contents(r->context, &client_challengekey);
	if (ret) {
	    krb5_crypto_destroy(r->context, longtermcrypto);
	    continue;
	}

	ret = _krb5_validate_pa_enc_challenge(r->context,
					      challengecrypto,
					      KRB5_KU_ENC_CHALLENGE_CLIENT,
					      enc_data,
					      r->cname);
	krb5_crypto_destroy(r->context, challengecrypto);
	if (ret) {
	    const char *msg;
	    krb5_error_code ret2;
	    char *str = NULL;

	    krb5_crypto_destroy(r->context, longtermcrypto);

	    if (ret != KRB5KRB_AP_ERR_BAD_INTEGRITY)
		return ret;

	    invalidKeys += 1;

	    if (pepper1kdc == NULL)
		/* The caller is not interessted in details */
		continue;

	    ret2 = krb5_enctype_to_string(r->context, k->key.keytype, &str);
	    if (ret2)
		str = NULL;
	    msg = krb5_get_error_message(r->context, ret);
	    _kdc_r_log(r, 2, "Failed to decrypt ENC-CHAL -- %s "
		       "(enctype %s) error %s",
		       r->cname, str ? str : "unknown enctype", msg);
	    krb5_free_error_message(r->context, msg);
	    free(str);

	    continue;
	}

	if (pepper1kdc == NULL) {
	    /* The caller is not interessted in details */
	    return 0;
	}

	heim_assert(KDCchallengekey != NULL,
		    "KDCchallengekey pointer required with pepper1kdc");
	heim_assert(used_key != NULL,
		    "used_key pointer required with pepper1kdc");

	/*
	 * Provide KDC authentication to the client, uses a different
	 * challenge key (different pepper).
	 */

	ret = krb5_crypto_fx_cf2(r->context, r->armor_crypto, longtermcrypto,
				 pepper1kdc, pepper2, aenctype,
				 KDCchallengekey);
	krb5_crypto_destroy(r->context, longtermcrypto);
	if (ret)
	    return ret;

	*used_key = k;
	return 0;
    }

    if (invalidKeys == 0)
	return KRB5KDC_ERR_ETYPE_NOSUPP;

    return KRB5KDC_ERR_PREAUTH_FAILED;
}

static krb5_error_code
pa_enc_chal_validate(astgs_request_t r, const PA_DATA *pa)
{
    krb5_kvno kvno = r->client->kvno;
    krb5_data pepper1client, pepper1kdc, pepper2;
    EncryptedData enc_data;
    krb5_enctype aenctype;
    krb5_error_code ret;
    krb5_keyblock KDCchallengekey;
    struct Key *k = NULL;
    size_t size;

    heim_assert(r->armor_crypto != NULL, "ENC-CHAL called for non FAST");

    if (_kdc_is_anon_request(&r->req)) {
	ret = KRB5KRB_AP_ERR_BAD_INTEGRITY;
	kdc_log(r->context, r->config, 4, "ENC-CHAL doesn't support anon");
	return ret;
    }

    if (r->client->flags.locked_out) {
       ret = KRB5KDC_ERR_CLIENT_REVOKED;
       kdc_log(r->context, r->config, 0,
               "Client (%s) is locked out", r->cname);
       kdc_audit_setkv_number((kdc_request_t)r, KDC_REQUEST_KV_AUTH_EVENT,
			      KDC_AUTH_EVENT_CLIENT_LOCKED_OUT);
       return ret;
    }

    ret = decode_EncryptedData(pa->padata_value.data,
			       pa->padata_value.length,
			       &enc_data,
			       &size);
    if (ret) {
	ret = KRB5KRB_AP_ERR_BAD_INTEGRITY;
	_kdc_r_log(r, 4, "Failed to decode PA-DATA -- %s",
		   r->cname);
	return ret;
    }

    pepper1client.data = "clientchallengearmor";
    pepper1client.length = strlen(pepper1client.data);
    pepper1kdc.data = "kdcchallengearmor";
    pepper1kdc.length = strlen(pepper1kdc.data);
    pepper2.data = "challengelongterm";
    pepper2.length = strlen(pepper2.data);

    krb5_crypto_getenctype(r->context, r->armor_crypto, &aenctype);

    kdc_log(r->context, r->config, 5, "FAST armor enctype is: %d", (int)aenctype);

    ret = pa_enc_chal_decrypt_kvno(r, aenctype,
				   &pepper1client,
				   &pepper1kdc,
				   &pepper2,
				   kvno,
				   &enc_data,
				   &KDCchallengekey,
				   &k);
    if (ret == KRB5KDC_ERR_ETYPE_NOSUPP) {
	char *estr;
	_kdc_set_e_text(r, "No key matching entype");
	if(krb5_enctype_to_string(r->context, enc_data.etype, &estr))
	    estr = NULL;
	if(estr == NULL)
	    _kdc_r_log(r, 4,
		       "No client key matching ENC-CHAL (%d) -- %s",
		       enc_data.etype, r->cname);
	else
	    _kdc_r_log(r, 4,
		       "No client key matching ENC-CHAL (%s) -- %s",
		       estr, r->cname);
	free(estr);
	free_EncryptedData(&enc_data);
	kdc_audit_setkv_number((kdc_request_t)r,
			       KDC_REQUEST_KV_PA_FAILED_KVNO,
			       kvno);
	return ret;
    }
    if (ret == KRB5KRB_AP_ERR_SKEW) {
	/*
	 * Logging happens inside of
	 * _krb5_validate_pa_enc_challenge()
	 * via pa_enc_chal_decrypt_kvno()
	 */

	free_EncryptedData(&enc_data);
	kdc_audit_setkv_number((kdc_request_t)r, KDC_REQUEST_KV_AUTH_EVENT,
			       KDC_AUTH_EVENT_CLIENT_TIME_SKEW);

	/*
	 * The following is needed to make windows clients to
	 * retry using the timestamp in the error message, if
	 * there is a e_text, they become unhappy.
	 */
	r->e_text = NULL;
	return ret;
    }
    if (ret == KRB5KDC_ERR_PREAUTH_FAILED) {
	krb5_error_code hret = ret;
	int hi;

	/*
	 * Logging happens inside of
	 * via pa_enc_chal_decrypt_kvno()
	 */

	kdc_audit_setkv_number((kdc_request_t)r,
			       KDC_REQUEST_KV_PA_FAILED_KVNO,
			       kvno);

	/*
	 * Check if old and older keys are
	 * able to decrypt.
	 */
	for (hi = 1; hi < 3; hi++) {
	    krb5_kvno hkvno;

	    if (hi >= kvno) {
		break;
	    }

	    hkvno = kvno - hi;
	    hret = pa_enc_chal_decrypt_kvno(r, aenctype,
					    &pepper1client,
					    NULL, /* pepper1kdc */
					    &pepper2,
					    hkvno,
					    &enc_data,
					    NULL, /* KDCchallengekey */
					    NULL); /* used_key */
	    if (hret == 0) {
		kdc_audit_setkv_number((kdc_request_t)r,
				       KDC_REQUEST_KV_PA_HISTORIC_KVNO,
				       hkvno);
		break;
	    }
	    if (hret == KRB5KDC_ERR_ETYPE_NOSUPP) {
		break;
	    }
	}

	free_EncryptedData(&enc_data);

	if (hret == 0)
	    kdc_audit_setkv_number((kdc_request_t)r, KDC_REQUEST_KV_AUTH_EVENT,
				   KDC_AUTH_EVENT_HISTORIC_LONG_TERM_KEY);
	else
	    kdc_audit_setkv_number((kdc_request_t)r, KDC_REQUEST_KV_AUTH_EVENT,
				   KDC_AUTH_EVENT_WRONG_LONG_TERM_KEY);

	return ret;
    }
    free_EncryptedData(&enc_data);
    if (ret == 0) {
	krb5_crypto challengecrypto;
	char *estr = NULL;
	char *astr = NULL;
	char *kstr = NULL;

	ret = krb5_crypto_init(r->context, &KDCchallengekey, 0, &challengecrypto);
	krb5_free_keyblock_contents(r->context, &KDCchallengekey);
	if (ret)
	    return ret;

	ret = _krb5_make_pa_enc_challenge(r->context, challengecrypto,
					  KRB5_KU_ENC_CHALLENGE_KDC,
					  r->rep.padata);
	krb5_crypto_destroy(r->context, challengecrypto);
	if (ret)
	    return ret;

	ret = set_salt_padata(r->context, r->config, r->rep.padata, k);
	if (ret)
	    return ret;

	/*
	 * Found a key that the client used, lets pick that as the reply key
	 */

	krb5_free_keyblock_contents(r->context, &r->reply_key);
	ret = krb5_copy_keyblock_contents(r->context, &k->key, &r->reply_key);
	if (ret)
	    return ret;

	if (krb5_enctype_to_string(r->context, (int)aenctype, &astr))
	    astr = NULL;
	if (krb5_enctype_to_string(r->context, enc_data.etype, &estr))
	    estr = NULL;
	if (krb5_enctype_to_string(r->context, k->key.keytype, &kstr))
	    kstr = NULL;
	_kdc_r_log(r, 4, "ENC-CHAL Pre-authentication succeeded -- %s "
		   "using armor=%s enc=%s key=%s",
		   r->cname,
		   astr ? astr : "unknown enctype",
		   estr ? estr : "unknown enctype",
		   kstr ? kstr : "unknown enctype");
	kdc_audit_setkv_number((kdc_request_t)r, KDC_REQUEST_KV_AUTH_EVENT,
			       KDC_AUTH_EVENT_VALIDATED_LONG_TERM_KEY);
	kdc_audit_setkv_number((kdc_request_t)r,
			       KDC_REQUEST_KV_PA_SUCCEEDED_KVNO,
			       kvno);
	return 0;
    }

    return ret;
}

static krb5_error_code
pa_enc_ts_decrypt_kvno(astgs_request_t r,
		       krb5_kvno kvno,
		       const EncryptedData *enc_data,
		       krb5_data *ts_data,
		       Key **_pa_key)
{
    krb5_error_code ret;
    krb5_crypto crypto;
    Key *pa_key = NULL;
    const Keys *keys = NULL;

    if (_pa_key)
	*_pa_key = NULL;

    krb5_data_zero(ts_data);

    keys = hdb_kvno2keys(r->context, r->client, kvno);
    if (keys == NULL) {
	return KRB5KDC_ERR_ETYPE_NOSUPP;
    }
    ret = hdb_enctype2key(r->context, r->client, keys,
			  enc_data->etype, &pa_key);
    if(ret){
	return KRB5KDC_ERR_ETYPE_NOSUPP;
    }

 try_next_key:
    ret = krb5_crypto_init(r->context, &pa_key->key, 0, &crypto);
    if (ret) {
	const char *msg = krb5_get_error_message(r->context, ret);
	_kdc_r_log(r, 4, "krb5_crypto_init failed: %s", msg);
	krb5_free_error_message(r->context, msg);
	return ret;
    }

    ret = krb5_decrypt_EncryptedData(r->context,
				     crypto,
				     KRB5_KU_PA_ENC_TIMESTAMP,
				     enc_data,
				     ts_data);
    krb5_crypto_destroy(r->context, crypto);
    /*
     * Since the user might have several keys with the same
     * enctype but with different salting, we need to try all
     * the keys with the same enctype.
     */
    if (ret) {
	ret = hdb_next_enctype2key(r->context, r->client, keys,
				   enc_data->etype, &pa_key);
	if (ret == 0)
	    goto try_next_key;

	return KRB5KDC_ERR_PREAUTH_FAILED;
    }

    if (_pa_key)
	*_pa_key = pa_key;
    return 0;
}

static krb5_error_code
pa_enc_ts_validate(astgs_request_t r, const PA_DATA *pa)
{
    krb5_kvno kvno = r->client->kvno;
    EncryptedData enc_data;
    krb5_error_code ret;
    krb5_data ts_data;
    PA_ENC_TS_ENC p;
    size_t len;
    Key *pa_key;
    char *str;

    if (r->armor_crypto && !r->config->enable_armored_pa_enc_timestamp) {
       ret = KRB5KDC_ERR_POLICY;
       kdc_log(r->context, r->config, 0,
               "Armored encrypted timestamp pre-authentication is disabled");
       return ret;
    } else if (!r->armor_crypto && !r->config->enable_unarmored_pa_enc_timestamp) {
       ret = KRB5KDC_ERR_POLICY;
       kdc_log(r->context, r->config, 0,
               "Unarmored encrypted timestamp pre-authentication is disabled");
       return ret;
    }

    if (r->client->flags.locked_out) {
       ret = KRB5KDC_ERR_CLIENT_REVOKED;
       kdc_log(r->context, r->config, 0,
               "Client (%s) is locked out", r->cname);
       kdc_audit_setkv_number((kdc_request_t)r, KDC_REQUEST_KV_AUTH_EVENT,
			      KDC_AUTH_EVENT_CLIENT_LOCKED_OUT);
       return ret;
    }

    ret = decode_EncryptedData(pa->padata_value.data,
			       pa->padata_value.length,
			       &enc_data,
			       &len);
    if (ret) {
	ret = KRB5KRB_AP_ERR_BAD_INTEGRITY;
	_kdc_r_log(r, 4, "Failed to decode PA-DATA -- %s",
		   r->cname);
	goto out;
    }
	
    ret = pa_enc_ts_decrypt_kvno(r, kvno, &enc_data, &ts_data, &pa_key);
    if (ret == KRB5KDC_ERR_ETYPE_NOSUPP) {
	char *estr;
	_kdc_set_e_text(r, "No key matching enctype");
	if(krb5_enctype_to_string(r->context, enc_data.etype, &estr))
	    estr = NULL;
	if(estr == NULL)
	    _kdc_r_log(r, 4,
		       "No client key matching pa-data (%d) -- %s",
		       enc_data.etype, r->cname);
	else
	    _kdc_r_log(r, 4,
		       "No client key matching pa-data (%s) -- %s",
		       estr, r->cname);
	free(estr);
	free_EncryptedData(&enc_data);
	kdc_audit_setkv_number((kdc_request_t)r,
			       KDC_REQUEST_KV_PA_FAILED_KVNO,
			       kvno);
	goto out;
    }
    if (ret == KRB5KDC_ERR_PREAUTH_FAILED) {
	krb5_error_code ret2;
	const char *msg = krb5_get_error_message(r->context, ret);
	krb5_error_code hret = ret;
	int hi;

	kdc_audit_setkv_number((kdc_request_t)r,
			       KDC_REQUEST_KV_PA_FAILED_KVNO,
			       kvno);

	/*
	 * Check if old and older keys are
	 * able to decrypt.
	 */
	for (hi = 1; hi < 3; hi++) {
	    krb5_kvno hkvno;

	    if (hi >= kvno) {
		break;
	    }

	    hkvno = kvno - hi;
	    hret = pa_enc_ts_decrypt_kvno(r, hkvno,
					  &enc_data,
					  &ts_data,
					  NULL); /* pa_key */
	    if (hret == 0) {
		krb5_data_free(&ts_data);
		kdc_audit_setkv_number((kdc_request_t)r,
				       KDC_REQUEST_KV_PA_HISTORIC_KVNO,
				       hkvno);
		break;
	    }
	    if (hret == KRB5KDC_ERR_ETYPE_NOSUPP) {
		break;
	    }
	}

	ret2 = krb5_enctype_to_string(r->context, enc_data.etype, &str);
	if (ret2)
	    str = NULL;
	_kdc_r_log(r, 2, "Failed to decrypt PA-DATA -- %s "
		   "(enctype %s) error %s",
		   r->cname, str ? str : "unknown enctype", msg);
	krb5_xfree(str);
	krb5_free_error_message(r->context, msg);
	kdc_audit_setkv_number((kdc_request_t)r, KDC_REQUEST_KV_PA_ETYPE,
			       enc_data.etype);
	if (hret == 0)
	    kdc_audit_setkv_number((kdc_request_t)r, KDC_REQUEST_KV_AUTH_EVENT,
				   KDC_AUTH_EVENT_HISTORIC_LONG_TERM_KEY);
	else
	    kdc_audit_setkv_number((kdc_request_t)r, KDC_REQUEST_KV_AUTH_EVENT,
				   KDC_AUTH_EVENT_WRONG_LONG_TERM_KEY);

	free_EncryptedData(&enc_data);

	ret = KRB5KDC_ERR_PREAUTH_FAILED;
	goto out;
    }
    free_EncryptedData(&enc_data);
    if (ret) {
	goto out;
    }
    ret = decode_PA_ENC_TS_ENC(ts_data.data,
			       ts_data.length,
			       &p,
			       &len);
    krb5_data_free(&ts_data);
    if(ret){
	ret = KRB5KDC_ERR_PREAUTH_FAILED;
	_kdc_r_log(r, 4, "Failed to decode PA-ENC-TS-ENC -- %s",
		   r->cname);
	goto out;
    }
    if (labs(kdc_time - p.patimestamp) > r->context->max_skew) {
	char client_time[100];
		
	krb5_format_time(r->context, p.patimestamp,
			 client_time, sizeof(client_time), TRUE);

	ret = KRB5KRB_AP_ERR_SKEW;
	_kdc_r_log(r, 4, "Too large time skew, "
		   "client time %s is out by %u > %u seconds -- %s",
		   client_time,
		   (unsigned)labs(kdc_time - p.patimestamp),
		   r->context->max_skew,
		   r->cname);
	kdc_audit_setkv_number((kdc_request_t)r, KDC_REQUEST_KV_AUTH_EVENT,
			       KDC_AUTH_EVENT_CLIENT_TIME_SKEW);

	/*
	 * The following is needed to make windows clients to
	 * retry using the timestamp in the error message, if
	 * there is a e_text, they become unhappy.
	 */
	r->e_text = NULL;
	free_PA_ENC_TS_ENC(&p);
	goto out;
    }
    free_PA_ENC_TS_ENC(&p);

    ret = set_salt_padata(r->context, r->config, r->rep.padata, pa_key);
    if (ret == 0)
        ret = krb5_copy_keyblock_contents(r->context, &pa_key->key, &r->reply_key);
    if (ret)
	return ret;

    ret = krb5_enctype_to_string(r->context, pa_key->key.keytype, &str);
    if (ret)
	str = NULL;
    _kdc_r_log(r, 4, "ENC-TS Pre-authentication succeeded -- %s using %s",
	       r->cname, str ? str : "unknown enctype");
    krb5_xfree(str);
    kdc_audit_setkv_number((kdc_request_t)r, KDC_REQUEST_KV_PA_ETYPE,
			   pa_key->key.keytype);
    kdc_audit_setkv_number((kdc_request_t)r, KDC_REQUEST_KV_AUTH_EVENT,
			   KDC_AUTH_EVENT_VALIDATED_LONG_TERM_KEY);
    kdc_audit_setkv_number((kdc_request_t)r,
			   KDC_REQUEST_KV_PA_SUCCEEDED_KVNO,
			   kvno);

    ret = 0;

 out:

    return ret;
}

#ifdef PKINIT

static krb5_error_code
make_freshness_token(astgs_request_t r, const Key *krbtgt_key, unsigned krbtgt_kvno)
{
    krb5_error_code ret = 0;
    const struct timeval current_kdc_time = krb5_kdc_get_time();
    int usec = current_kdc_time.tv_usec;
    const PA_ENC_TS_ENC ts_enc = {
	.patimestamp = current_kdc_time.tv_sec,
	.pausec = &usec,
    };
    unsigned char *encoded_ts_enc = NULL;
    size_t ts_enc_size;
    size_t ts_enc_len = 0;
    EncryptedData encdata;
    krb5_crypto crypto;
    unsigned char *token = NULL;
    size_t token_size;
    size_t token_len = 0;
    size_t token_alloc_size;

    ASN1_MALLOC_ENCODE(PA_ENC_TS_ENC,
		       encoded_ts_enc,
		       ts_enc_size,
		       &ts_enc,
		       &ts_enc_len,
		       ret);
    if (ret)
	return ret;
    if (ts_enc_size != ts_enc_len)
	krb5_abortx(r->context, "internal error in ASN.1 encoder");

    ret = krb5_crypto_init(r->context, &krbtgt_key->key, 0, &crypto);
    if (ret) {
	free(encoded_ts_enc);
	return ret;
    }

    ret = krb5_encrypt_EncryptedData(r->context,
				     crypto,
				     KRB5_KU_AS_FRESHNESS,
				     encoded_ts_enc,
				     ts_enc_len,
				     krbtgt_kvno,
				     &encdata);
    free(encoded_ts_enc);
    krb5_crypto_destroy(r->context, crypto);
    if (ret)
	return ret;

    token_size = length_EncryptedData(&encdata);
    token_alloc_size = token_size + 2; /* Account for the two leading zero bytes. */
    token = calloc(1, token_alloc_size);
    if (token == NULL) {
	free_EncryptedData(&encdata);
	return ENOMEM;
    }

    ret = encode_EncryptedData(token + token_alloc_size - 1,
			       token_size,
			       &encdata,
			       &token_len);
    free_EncryptedData(&encdata);
    if (ret) {
	free(token);
	return ret;
    }
    if (token_size != token_len)
	krb5_abortx(r->context, "internal error in ASN.1 encoder");

    ret = krb5_padata_add(r->context,
			  r->rep.padata,
			  KRB5_PADATA_AS_FRESHNESS,
			  token,
			  token_alloc_size);
    if (ret)
	free(token);
    return ret;
}

#endif /* PKINIT */

static krb5_error_code
send_freshness_token(astgs_request_t r, const Key *krbtgt_key, unsigned krbtgt_kvno)
{
    krb5_error_code ret = 0;
#ifdef PKINIT
    int idx = 0;
    const PA_DATA *freshness_padata = NULL;

    freshness_padata = _kdc_find_padata(&r->req,
					&idx,
					KRB5_PADATA_AS_FRESHNESS);
    if (freshness_padata == NULL) {
	return 0;
    }

    ret = make_freshness_token(r, krbtgt_key, krbtgt_kvno);
#endif /* PKINIT */
    return ret;
}

struct kdc_patypes {
    int type;
    const char *name;
    unsigned int flags;
#define PA_ANNOUNCE	1
#define PA_REQ_FAST	2 /* only use inside fast */
#define PA_SYNTHETIC_OK	4
#define PA_REPLACE_REPLY_KEY	8   /* PA mech replaces reply key */
#define PA_USES_LONG_TERM_KEY	16  /* PA mech uses client's long-term key */
#define PA_HARDWARE_AUTH	32  /* PA mech uses hardware authentication */
#define PA_USES_FAST_COOKIE	64  /* Multi-step PA mech maintains state in PA-FX-COOKIE */
    krb5_error_code (*validate)(astgs_request_t, const PA_DATA *pa);
    krb5_error_code (*finalize_pac)(astgs_request_t r);
    void (*cleanup)(astgs_request_t r);
};

static const struct kdc_patypes pat[] = {
#ifdef PKINIT
    {
	KRB5_PADATA_PK_AS_REQ, "PK-INIT(ietf)",
        PA_ANNOUNCE | PA_SYNTHETIC_OK | PA_REPLACE_REPLY_KEY | PA_HARDWARE_AUTH,
	pa_pkinit_validate, NULL, NULL
    },
    {
	KRB5_PADATA_PK_AS_REQ_WIN, "PK-INIT(win2k)", PA_ANNOUNCE | PA_REPLACE_REPLY_KEY | PA_HARDWARE_AUTH,
	pa_pkinit_validate, NULL, NULL
    },
    {
	KRB5_PADATA_PKINIT_KX, "Anonymous PK-INIT", PA_ANNOUNCE,
	NULL, NULL, NULL
    },
#else
    { KRB5_PADATA_PK_AS_REQ, "PK-INIT(ietf)", 0, NULL , NULL, NULL },
    { KRB5_PADATA_PK_AS_REQ_WIN, "PK-INIT(win2k)", 0, NULL, NULL, NULL },
    { KRB5_PADATA_PKINIT_KX, "Anonymous PK-INIT", 0, NULL, NULL, NULL },
#endif
    { KRB5_PADATA_PA_PK_OCSP_RESPONSE , "OCSP", 0, NULL, NULL, NULL },
    { 
	KRB5_PADATA_ENC_TIMESTAMP , "ENC-TS",
	PA_ANNOUNCE | PA_USES_LONG_TERM_KEY,
	pa_enc_ts_validate, NULL, NULL
    },
    {
	KRB5_PADATA_ENCRYPTED_CHALLENGE , "ENC-CHAL",
	PA_ANNOUNCE | PA_USES_LONG_TERM_KEY | PA_REQ_FAST,
	pa_enc_chal_validate, NULL, NULL
    },
    { KRB5_PADATA_REQ_ENC_PA_REP , "REQ-ENC-PA-REP", 0, NULL, NULL, NULL },
    { KRB5_PADATA_FX_FAST, "FX-FAST", PA_ANNOUNCE, NULL, NULL, NULL },
    { KRB5_PADATA_FX_ERROR, "FX-ERROR", 0, NULL, NULL, NULL },
    { KRB5_PADATA_FX_COOKIE, "FX-COOKIE", 0, NULL, NULL, NULL },
    {
	KRB5_PADATA_GSS , "GSS",
	PA_ANNOUNCE | PA_SYNTHETIC_OK | PA_REPLACE_REPLY_KEY | PA_USES_FAST_COOKIE,
	pa_gss_validate, pa_gss_finalize_pac, NULL
    },
};

static void
log_patypes(astgs_request_t r, METHOD_DATA *padata)
{
    krb5_kdc_configuration *config = r->config;
    struct rk_strpool *p = NULL;
    char *str;
    size_t n, m;
	
    for (n = 0; n < padata->len; n++) {
	for (m = 0; m < sizeof(pat) / sizeof(pat[0]); m++) {
	    if (padata->val[n].padata_type == pat[m].type) {
		p = rk_strpoolprintf(p, "%s", pat[m].name);
		break;
	    }
	}
	if (m == sizeof(pat) / sizeof(pat[0]))
	    p = rk_strpoolprintf(p, "%d", padata->val[n].padata_type);
	if (p && n + 1 < padata->len)
	    p = rk_strpoolprintf(p, ", ");
	if (p == NULL) {
	    kdc_log(r->context, config, 1, "out of memory");
	    return;
	}
    }
    if (p == NULL)
	p = rk_strpoolprintf(p, "none");

    str = rk_strpoolcollect(p);
    kdc_log(r->context, config, 4, "Client sent patypes: %s", str);
    kdc_audit_addkv((kdc_request_t)r, KDC_AUDIT_EATWHITE,
		    "client-pa", "%s", str);
    free(str);
}

static krb5_boolean
pa_used_flag_isset(astgs_request_t r, unsigned int flag)
{
    if (r->pa_used == NULL)
	return FALSE;

    return (r->pa_used->flags & flag) == flag;
}

/*
 *
 */

krb5_error_code
_kdc_encode_reply(krb5_context context,
		  krb5_kdc_configuration *config,
		  astgs_request_t r, uint32_t nonce,
		  krb5_enctype etype,
		  int skvno, const EncryptionKey *skey,
		  int ckvno,
		  int rk_is_subkey,
		  krb5_data *reply)
{
    unsigned char *buf;
    size_t buf_size;
    size_t len = 0;
    krb5_error_code ret;
    krb5_crypto crypto;
    KDC_REP *rep = &r->rep;
    EncTicketPart *et = &r->et;
    EncKDCRepPart *ek = &r->ek;

    heim_assert(rep->padata != NULL, "reply padata uninitialized");

    ASN1_MALLOC_ENCODE(EncTicketPart, buf, buf_size, et, &len, ret);
    if(ret) {
	const char *msg = krb5_get_error_message(context, ret);
	kdc_log(context, config, 4, "Failed to encode ticket: %s", msg);
	krb5_free_error_message(context, msg);
	return ret;
    }
    if(buf_size != len)
	krb5_abortx(context, "Internal error in ASN.1 encoder");

    ret = krb5_crypto_init(context, skey, etype, &crypto);
    if (ret) {
        const char *msg = krb5_get_error_message(context, ret);
	kdc_log(context, config, 4, "krb5_crypto_init failed: %s", msg);
	krb5_free_error_message(context, msg);
	free(buf);
	return ret;
    }

    ret = krb5_encrypt_EncryptedData(context,
				     crypto,
				     KRB5_KU_TICKET,
				     buf,
				     len,
				     skvno,
				     &rep->ticket.enc_part);
    free(buf);
    krb5_crypto_destroy(context, crypto);
    if(ret) {
	const char *msg = krb5_get_error_message(context, ret);
	kdc_log(context, config, 4, "Failed to encrypt data: %s", msg);
	krb5_free_error_message(context, msg);
	return ret;
    }

    if (r && r->armor_crypto) {
	KrbFastFinished finished;
	krb5_data data;

	kdc_log(context, config, 4, "FAST armor protection");

	memset(&finished, 0, sizeof(finished));
	krb5_data_zero(&data);

	finished.timestamp = kdc_time;
	finished.usec = 0;
	finished.crealm = et->crealm;
	finished.cname = et->cname;

	ASN1_MALLOC_ENCODE(Ticket, data.data, data.length,
			   &rep->ticket, &len, ret);
	if (ret)
	    return ret;
	if (data.length != len)
	    krb5_abortx(context, "internal asn.1 error");

	ret = krb5_create_checksum(context, r->armor_crypto,
				   KRB5_KU_FAST_FINISHED, 0,
				   data.data, data.length,
				   &finished.ticket_checksum);
	krb5_data_free(&data);
	if (ret)
	    return ret;

	ret = _kdc_fast_mk_response(context, r->armor_crypto,
				    rep->padata, &r->strengthen_key, &finished,
				    nonce, &data);
	free_Checksum(&finished.ticket_checksum);
	if (ret)
	    return ret;

	free_METHOD_DATA(r->rep.padata);

	ret = krb5_padata_add(context, rep->padata,
			      KRB5_PADATA_FX_FAST,
			      data.data, data.length);
	if (ret)
	    return ret;

	/*
	 * Hide client name for privacy reasons
	 */
	if (r->fast.flags.requested_hidden_names) {
	    const Realm anon_realm = KRB5_ANON_REALM;

	    free_Realm(&rep->crealm);
	    ret = copy_Realm(&anon_realm, &rep->crealm);
	    if (ret == 0) {
		free_PrincipalName(&rep->cname);
		ret = _kdc_make_anonymous_principalname(&rep->cname);
	    }
	    if (ret)
		return ret;
	}
    }

    if (rep->padata->len == 0) {
	free_METHOD_DATA(rep->padata);
	free(rep->padata);
	rep->padata = NULL;
    }

    if(rep->msg_type == krb_as_rep && !config->encode_as_rep_as_tgs_rep)
	ASN1_MALLOC_ENCODE(EncASRepPart, buf, buf_size, ek, &len, ret);
    else
	ASN1_MALLOC_ENCODE(EncTGSRepPart, buf, buf_size, ek, &len, ret);
    if(ret) {
	const char *msg = krb5_get_error_message(context, ret);
	kdc_log(context, config, 4, "Failed to encode KDC-REP: %s", msg);
	krb5_free_error_message(context, msg);
	return ret;
    }
    if(buf_size != len) {
	free(buf);
	kdc_log(context, config, 4, "Internal error in ASN.1 encoder");
	_kdc_set_e_text(r, "KDC internal error");
	return KRB5KRB_ERR_GENERIC;
    }
    ret = krb5_crypto_init(context, &r->reply_key, 0, &crypto);
    if (ret) {
	const char *msg = krb5_get_error_message(context, ret);
	free(buf);
	kdc_log(context, config, 4, "krb5_crypto_init failed: %s", msg);
	krb5_free_error_message(context, msg);
	return ret;
    }
    if(rep->msg_type == krb_as_rep) {
        ret = krb5_encrypt_EncryptedData(context,
                                         crypto,
                                         KRB5_KU_AS_REP_ENC_PART,
                                         buf,
                                         len,
                                         ckvno,
                                         &rep->enc_part);
        free(buf);
        if (ret == 0)
            ASN1_MALLOC_ENCODE(AS_REP, buf, buf_size, rep, &len, ret);
    } else {
        ret = krb5_encrypt_EncryptedData(context,
                                         crypto,
                                         rk_is_subkey ?
                                             KRB5_KU_TGS_REP_ENC_PART_SUB_KEY :
                                             KRB5_KU_TGS_REP_ENC_PART_SESSION,
                                         buf,
                                         len,
                                         ckvno,
                                         &rep->enc_part);
        free(buf);
        if (ret == 0)
            ASN1_MALLOC_ENCODE(TGS_REP, buf, buf_size, rep, &len, ret);
    }
    krb5_crypto_destroy(context, crypto);
    if(ret) {
	const char *msg = krb5_get_error_message(context, ret);
	kdc_log(context, config, 4, "Failed to encode KDC-REP: %s", msg);
	krb5_free_error_message(context, msg);
	return ret;
    }
    if(buf_size != len) {
	free(buf);
	kdc_log(context, config, 4, "Internal error in ASN.1 encoder");
	_kdc_set_e_text(r, "KDC internal error");
	return KRB5KRB_ERR_GENERIC;
    }
    reply->data = buf;
    reply->length = buf_size;
    return 0;
}

/*
 *
 */

static krb5_error_code
get_pa_etype_info(krb5_context context,
		  krb5_kdc_configuration *config,
		  METHOD_DATA *md, Key *ckey,
		  krb5_boolean include_salt)
{
    krb5_error_code ret = 0;
    ETYPE_INFO_ENTRY eie; /* do not free this one */
    ETYPE_INFO ei;
    PA_DATA pa;
    size_t len;

    /*
     * Code moved here from what used to be make_etype_info_entry() because
     * using the ASN.1 compiler-generated SEQUENCE OF add functions makes that
     * old function's body and this one's small and clean.
     *
     * The following comment blocks were there:
     *
     *  According to `the specs', we can't send a salt if we have AFS3 salted
     *  key, but that requires that you *know* what cell you are using (e.g by
     *  assuming that the cell is the same as the realm in lower case)
     *
     *  We shouldn't sent salttype since it is incompatible with the
     *  specification and it breaks windows clients.  The afs salting problem
     *  is solved by using KRB5-PADATA-AFS3-SALT implemented in Heimdal 0.7 and
     *  later.
     *
     *  We return no salt type at all, as that should indicate the default salt
     *  type and make everybody happy.  some systems (like w2k) dislike being
     *  told the salt type here.
     */

    pa.padata_type = KRB5_PADATA_ETYPE_INFO;
    pa.padata_value.data = NULL;
    pa.padata_value.length = 0;
    ei.len = 0;
    ei.val = NULL;
    eie.etype = ckey->key.keytype;
    eie.salttype = NULL;
    eie.salt = NULL;
    if (include_salt && ckey->salt)
        eie.salt = &ckey->salt->salt;
    ret = add_ETYPE_INFO(&ei, &eie);
    if (ret == 0)
        ASN1_MALLOC_ENCODE(ETYPE_INFO, pa.padata_value.data, pa.padata_value.length,
                           &ei, &len, ret);
    if (ret == 0)
        add_METHOD_DATA(md, &pa);
    free_ETYPE_INFO(&ei);
    free_PA_DATA(&pa);
    return ret;
}

/*
 *
 */

extern const int _krb5_AES_SHA1_string_to_default_iterator;
extern const int _krb5_AES_SHA2_string_to_default_iterator;

static krb5_error_code
make_s2kparams(int value, size_t len, krb5_data **ps2kparams)
{
    krb5_data *s2kparams;
    krb5_error_code ret;

    ALLOC(s2kparams);
    if (s2kparams == NULL)
	return ENOMEM;
    ret = krb5_data_alloc(s2kparams, len);
    if (ret) {
	free(s2kparams);
	return ret;
    }
    _krb5_put_int(s2kparams->data, value, len);
    *ps2kparams = s2kparams;
    return 0;
}

static krb5_error_code
make_etype_info2_entry(ETYPE_INFO2_ENTRY *ent,
		       Key *key,
		       krb5_boolean include_salt)
{
    krb5_error_code ret;

    ent->etype = key->key.keytype;
    if (key->salt && include_salt) {
	ALLOC(ent->salt);
	if (ent->salt == NULL)
	    return ENOMEM;
	*ent->salt = malloc(key->salt->salt.length + 1);
	if (*ent->salt == NULL) {
	    free(ent->salt);
	    ent->salt = NULL;
	    return ENOMEM;
	}
	memcpy(*ent->salt, key->salt->salt.data, key->salt->salt.length);
	(*ent->salt)[key->salt->salt.length] = '\0';
    } else
	ent->salt = NULL;

    ent->s2kparams = NULL;

    switch (key->key.keytype) {
    case ETYPE_AES128_CTS_HMAC_SHA1_96:
    case ETYPE_AES256_CTS_HMAC_SHA1_96:
	ret = make_s2kparams(_krb5_AES_SHA1_string_to_default_iterator,
			     4, &ent->s2kparams);
	break;
    case KRB5_ENCTYPE_AES128_CTS_HMAC_SHA256_128:
    case KRB5_ENCTYPE_AES256_CTS_HMAC_SHA384_192:
	ret = make_s2kparams(_krb5_AES_SHA2_string_to_default_iterator,
			     4, &ent->s2kparams);
	break;
    case ETYPE_DES_CBC_CRC:
    case ETYPE_DES_CBC_MD4:
    case ETYPE_DES_CBC_MD5:
	/* Check if this was a AFS3 salted key */
	if(key->salt && key->salt->type == hdb_afs3_salt)
	    ret = make_s2kparams(1, 1, &ent->s2kparams);
	else
	    ret = 0;
	break;
    default:
	ret = 0;
	break;
    }
    return ret;
}

/*
 * Return an ETYPE-INFO2. Enctypes are storted the same way as in the
 * database (client supported enctypes first, then the unsupported
 * enctypes).
 */

static krb5_error_code
get_pa_etype_info2(krb5_context context,
		   krb5_kdc_configuration *config,
		   METHOD_DATA *md, Key *ckey,
		   krb5_boolean include_salt)
{
    krb5_error_code ret = 0;
    ETYPE_INFO2 pa;
    unsigned char *buf;
    size_t len;

    pa.len = 1;
    pa.val = calloc(1, sizeof(pa.val[0]));
    if(pa.val == NULL)
	return ENOMEM;

    ret = make_etype_info2_entry(&pa.val[0], ckey, include_salt);
    if (ret) {
	free_ETYPE_INFO2(&pa);
	return ret;
    }

    ASN1_MALLOC_ENCODE(ETYPE_INFO2, buf, len, &pa, &len, ret);
    free_ETYPE_INFO2(&pa);
    if(ret)
	return ret;
    ret = realloc_method_data(md);
    if(ret) {
	free(buf);
	return ret;
    }
    md->val[md->len - 1].padata_type = KRB5_PADATA_ETYPE_INFO2;
    md->val[md->len - 1].padata_value.length = len;
    md->val[md->len - 1].padata_value.data = buf;
    return 0;
}

/*
 * Return 0 if the client has only older enctypes, this is for
 * determining if the server should send ETYPE_INFO2 or not.
 */

static int
newer_enctype_present(krb5_context context,
		      struct KDC_REQ_BODY_etype *etype_list)
{
    size_t i;

    for (i = 0; i < etype_list->len; i++) {
	if (!krb5_is_enctype_old(context, etype_list->val[i]))
	    return 1;
    }
    return 0;
}

static krb5_error_code
get_pa_etype_info_both(krb5_context context,
		       krb5_kdc_configuration *config,
		       struct KDC_REQ_BODY_etype *etype_list,
		       METHOD_DATA *md, Key *ckey,
		       krb5_boolean include_salt)
{
    krb5_error_code ret;

    /*
     * Windows 2019 (and earlier versions) always sends the salt
     * and Samba has testsuites that check this behaviour, so a
     * Samba AD DC will set this flag to match the AS-REP packet
     * more closely.
     */
    if (config->force_include_pa_etype_salt)
	include_salt = TRUE;

    /*
     * RFC4120 requires:
     *   When the AS server is to include pre-authentication data in a
     *   KRB-ERROR or in an AS-REP, it MUST use PA-ETYPE-INFO2, not
     *   PA-ETYPE-INFO, if the etype field of the client's AS-REQ lists
     *   at least one "newer" encryption type.  Otherwise (when the etype
     *   field of the client's AS-REQ does not list any "newer" encryption
     *   types), it MUST send both PA-ETYPE-INFO2 and PA-ETYPE-INFO (both
     *   with an entry for each enctype).  A "newer" enctype is any enctype
     *   first officially specified concurrently with or subsequent to the
     *   issue of this RFC.  The enctypes DES, 3DES, or RC4 and any defined
     *   in [RFC1510] are not "newer" enctypes.
     *
     * It goes on to state:
     *   The preferred ordering of the "hint" pre-authentication data that
     *   affect client key selection is: ETYPE-INFO2, followed by ETYPE-INFO,
     *   followed by PW-SALT.  As noted in Section 3.1.3, a KDC MUST NOT send
     *   ETYPE-INFO or PW-SALT when the client's AS-REQ includes at least one
     *   "newer" etype.
     */

    ret = get_pa_etype_info2(context, config, md, ckey, include_salt);
    if (ret)
	return ret;

    if (!newer_enctype_present(context, etype_list))
	ret = get_pa_etype_info(context, config, md, ckey, include_salt);

    return ret;
}

/*
 *
 */

void
_log_astgs_req(astgs_request_t r, krb5_enctype setype)
{
    const KDC_REQ_BODY *b = &r->req.req_body;
    krb5_enctype cetype = r->reply_key.keytype;
    krb5_error_code ret;
    struct rk_strpool *p;
    struct rk_strpool *s = NULL;
    char *str;
    char *cet;
    char *set;
    size_t i;

    /*
     * we are collecting ``p'' and ``s''.  The former is a textual
     * representation of the enctypes as strings which will be used
     * for debugging.  The latter is a terse comma separated list of
     * the %d's of the enctypes to emit into our audit trail to
     * conserve space in the logs.
     */

    p = rk_strpoolprintf(NULL, "%s", "Client supported enctypes: ");

    for (i = 0; i < b->etype.len; i++) {
	ret = krb5_enctype_to_string(r->context, b->etype.val[i], &str);
	if (ret == 0) {
	    p = rk_strpoolprintf(p, "%s", str);
	    free(str);
	} else
	    p = rk_strpoolprintf(p, "%d", b->etype.val[i]);
	if (p == NULL) {
	    rk_strpoolfree(s);
	    _kdc_r_log(r, 4, "out of memory");
	    return;
	}
	s = rk_strpoolprintf(s, "%d", b->etype.val[i]);
	if (i + 1 < b->etype.len) {
	    p = rk_strpoolprintf(p, ", ");
	    s = rk_strpoolprintf(s, ",");
	}
    }
    if (p == NULL)
	p = rk_strpoolprintf(p, "no encryption types");

    str = rk_strpoolcollect(s);
    if (str)
        kdc_audit_addkv((kdc_request_t)r, KDC_AUDIT_EATWHITE, "etypes", "%s",
                        str);
    free(str);

    ret = krb5_enctype_to_string(r->context, cetype, &cet);
    if(ret == 0) {
	ret = krb5_enctype_to_string(r->context, setype, &set);
	if (ret == 0) {
	    p = rk_strpoolprintf(p, ", using %s/%s", cet, set);
	    free(set);
	}
	free(cet);
    }
    if (ret != 0)
	p = rk_strpoolprintf(p, ", using enctypes %d/%d",
			     cetype, setype);

    str = rk_strpoolcollect(p);
    if (str)
	_kdc_r_log(r, 4, "%s", str);
    free(str);

    kdc_audit_addkv((kdc_request_t)r, 0, "etype", "%d/%d", cetype, setype);

    {
	char fixedstr[128];
	int result;

	result = unparse_flags(KDCOptions2int(b->kdc_options), asn1_KDCOptions_units(),
			       fixedstr, sizeof(fixedstr));
	if (result > 0) {
	    _kdc_r_log(r, 4, "Requested flags: %s", fixedstr);
	    kdc_audit_addkv((kdc_request_t)r, KDC_AUDIT_EATWHITE,
			    "flags", "%s", fixedstr);
	}
    }
}

/*
 * verify the flags on `client' and `server', returning 0
 * if they are OK and generating an error messages and returning
 * and error code otherwise.
 */

KDC_LIB_FUNCTION krb5_error_code KDC_LIB_CALL
kdc_check_flags(astgs_request_t r,
                krb5_boolean is_as_req,
                hdb_entry *client,
                hdb_entry *server)
{
    if (client != NULL) {
	/* check client */
	if (client->flags.locked_out) {
	    kdc_audit_addreason((kdc_request_t)r, "Client is locked out");
	    return KRB5KDC_ERR_CLIENT_REVOKED;
	}

	if (client->flags.invalid) {
	    kdc_audit_addreason((kdc_request_t)r,
                                "Client has invalid bit set");
	    return KRB5KDC_ERR_POLICY;
	}

	if (!client->flags.client) {
	    kdc_audit_addreason((kdc_request_t)r,
                                "Principal may not act as client");
	    return KRB5KDC_ERR_POLICY;
	}

	if (client->valid_start && *client->valid_start > kdc_time) {
	    char starttime_str[100];
	    krb5_format_time(r->context, *client->valid_start,
			     starttime_str, sizeof(starttime_str), TRUE);
	    kdc_audit_addreason((kdc_request_t)r, "Client not yet valid "
                                "until %s", starttime_str);
	    return KRB5KDC_ERR_CLIENT_NOTYET;
	}

	if (client->valid_end && *client->valid_end < kdc_time) {
	    char endtime_str[100];
	    krb5_format_time(r->context, *client->valid_end,
			     endtime_str, sizeof(endtime_str), TRUE);
	    kdc_audit_addreason((kdc_request_t)r, "Client expired at %s",
                                endtime_str);
	    return  KRB5KDC_ERR_NAME_EXP;
	}

	if (client->flags.require_pwchange &&
	    (server == NULL || !server->flags.change_pw))
	    return KRB5KDC_ERR_KEY_EXPIRED;

	if (client->pw_end && *client->pw_end < kdc_time
	    && (server == NULL || !server->flags.change_pw)) {
	    char pwend_str[100];
	    krb5_format_time(r->context, *client->pw_end,
			     pwend_str, sizeof(pwend_str), TRUE);
	    kdc_audit_addreason((kdc_request_t)r, "Client's key has expired "
                                "at %s", pwend_str);
	    return KRB5KDC_ERR_KEY_EXPIRED;
	}
    }

    /* check server */

    if (server != NULL) {
	if (server->flags.locked_out) {
	    kdc_audit_addreason((kdc_request_t)r, "Server locked out");
	    return KRB5KDC_ERR_SERVICE_REVOKED;
	}
	if (server->flags.invalid) {
	    kdc_audit_addreason((kdc_request_t)r,
				"Server has invalid flag set");
	    return KRB5KDC_ERR_POLICY;
	}
	if (!server->flags.server) {
	    kdc_audit_addreason((kdc_request_t)r,
                                "Principal may not act as server");
	    return KRB5KDC_ERR_POLICY;
	}

	if (!is_as_req && server->flags.initial) {
	    kdc_audit_addreason((kdc_request_t)r,
                                "AS-REQ is required for server");
	    return KRB5KDC_ERR_POLICY;
	}

	if (server->valid_start && *server->valid_start > kdc_time) {
	    char starttime_str[100];
	    krb5_format_time(r->context, *server->valid_start,
			     starttime_str, sizeof(starttime_str), TRUE);
	    kdc_audit_addreason((kdc_request_t)r, "Server not yet valid "
                                "until %s", starttime_str);
	    return KRB5KDC_ERR_SERVICE_NOTYET;
	}

	if (server->valid_end && *server->valid_end < kdc_time) {
	    char endtime_str[100];
	    krb5_format_time(r->context, *server->valid_end,
			     endtime_str, sizeof(endtime_str), TRUE);
	    kdc_audit_addreason((kdc_request_t)r, "Server expired at %s",
                                endtime_str);
	    return KRB5KDC_ERR_SERVICE_EXP;
	}

	if (server->pw_end && *server->pw_end < kdc_time) {
	    char pwend_str[100];
	    krb5_format_time(r->context, *server->pw_end,
			     pwend_str, sizeof(pwend_str), TRUE);
	    kdc_audit_addreason((kdc_request_t)r, "Server's key has expired "
                                "at %s", pwend_str);
	    return KRB5KDC_ERR_KEY_EXPIRED;
	}
    }
    return 0;
}

/*
 * Return TRUE if `from' is part of `addresses' taking into consideration
 * the configuration variables that tells us how strict we should be about
 * these checks
 */

krb5_boolean
_kdc_check_addresses(astgs_request_t r, HostAddresses *addresses,
		     const struct sockaddr *from)
{
    krb5_kdc_configuration *config = r->config;
    krb5_error_code ret;
    krb5_address addr;
    krb5_boolean result;
    krb5_boolean only_netbios = TRUE;
    size_t i;

    if (!config->check_ticket_addresses && !config->warn_ticket_addresses)
	return TRUE;

    /*
     * Fields of HostAddresses type are always OPTIONAL and should be non-
     * empty, but we check for empty just in case as our compiler doesn't
     * support size constraints on SEQUENCE OF.
     */
    if (addresses == NULL || addresses->len == 0)
	return config->allow_null_ticket_addresses;

    for (i = 0; i < addresses->len; ++i) {
	if (addresses->val[i].addr_type != KRB5_ADDRESS_NETBIOS) {
	    only_netbios = FALSE;
	}
    }

    /* Windows sends it's netbios name, which I can only assume is
     * used for the 'allowed workstations' check.  This is painful,
     * but we still want to check IP addresses if they happen to be
     * present.
     */

    if(only_netbios)
	return config->allow_null_ticket_addresses;

    ret = krb5_sockaddr2address (r->context, from, &addr);
    if(ret)
	return FALSE;

    result = krb5_address_search(r->context, &addr, addresses);
    krb5_free_address (r->context, &addr);
    return result;
}

/*
 *
 */
krb5_error_code
_kdc_check_anon_policy(astgs_request_t r)
{
    if (!r->config->allow_anonymous) {
	kdc_audit_addreason((kdc_request_t)r,
                            "Anonymous tickets denied by local policy");
	return KRB5KDC_ERR_POLICY;
    }

    return 0;
}

/*
 * Determine whether the client requested a PAC be included
 * or excluded explictly, or whether it doesn't care.
 */

static uint64_t
get_pac_attributes(krb5_context context, KDC_REQ *req)
{
    krb5_error_code ret;
    PA_PAC_REQUEST pacreq;
    const PA_DATA *pa;
    int i = 0;
    uint32_t pac_attributes;

    pa = _kdc_find_padata(req, &i, KRB5_PADATA_PA_PAC_REQUEST);
    if (pa == NULL)
	return KRB5_PAC_WAS_GIVEN_IMPLICITLY;

    ret = decode_PA_PAC_REQUEST(pa->padata_value.data,
				pa->padata_value.length,
				&pacreq,
				NULL);
    if (ret)
	return KRB5_PAC_WAS_GIVEN_IMPLICITLY;

    pac_attributes = pacreq.include_pac ? KRB5_PAC_WAS_REQUESTED : 0;
    free_PA_PAC_REQUEST(&pacreq);
    if (pac_attributes == 0 && context->flags & KRB5_CTX_F_ALWAYS_INCLUDE_PAC) {
	pac_attributes = KRB5_PAC_WAS_GIVEN_IMPLICITLY;
    }
    return pac_attributes;
}

/*
 *
 */

static krb5_error_code
generate_pac(astgs_request_t r, const Key *skey, const Key *tkey,
	     krb5_boolean is_tgs)
{
    krb5_error_code ret;
    uint16_t rodc_id;
    krb5_principal client;
    krb5_const_principal canon_princ = NULL;

    r->pac_attributes = get_pac_attributes(r->context, &r->req);
    kdc_audit_setkv_number((kdc_request_t)r, "pac_attributes",
			   r->pac_attributes);

    if (!is_tgs && !(r->pac_attributes & (KRB5_PAC_WAS_REQUESTED | KRB5_PAC_WAS_GIVEN_IMPLICITLY)))
	return 0;

    /*
     * When a PA mech does not use the client's long-term key, the PAC
     * may include the client's long-term key (encrypted in the reply key)
     * for use by other shared secret authentication protocols, e.g. NTLM.
     * Validate a PA mech was actually used before doing this.
     */

    ret = _kdc_pac_generate(r,
			    r->client,
			    r->server,
			    r->pa_used && !pa_used_flag_isset(r, PA_USES_LONG_TERM_KEY)
				? &r->reply_key : NULL,
			    r->pac_attributes,
			    &r->pac);
    if (ret) {
	_kdc_r_log(r, 4, "PAC generation failed for -- %s",
		   r->cname);
	return ret;
    }
    if (r->pac == NULL)
	return 0;

    rodc_id = r->server->kvno >> 16;

    /* libkrb5 expects ticket and PAC client names to match */
    ret = _krb5_principalname2krb5_principal(r->context, &client,
					     r->et.cname, r->et.crealm);
    if (ret)
	return ret;

    /*
     * Include the canonical name of the principal in the authorization
     * data, if the realms match (if they don't, then the KDC could
     * impersonate any realm. Windows always canonicalizes the realm,
     * but Heimdal permits aliases between realms.)
     */
    if (krb5_realm_compare(r->context, client, r->canon_client_princ)) {
	char *cpn = NULL;

	canon_princ = r->canon_client_princ;

	(void) krb5_unparse_name(r->context, canon_princ, &cpn);
	kdc_audit_addkv((kdc_request_t)r, 0, "canon_client_name", "%s",
			cpn ? cpn : "<unknown>");
	krb5_xfree(cpn);
    }

    if (r->pa_used && r->pa_used->finalize_pac) {
	ret = r->pa_used->finalize_pac(r);
	if (ret)
	    return ret;
    }

    ret = _krb5_kdc_pac_sign_ticket(r->context,
				    r->pac,
				    client,
				    &skey->key, /* Server key */
				    &tkey->key, /* TGS key */
				    rodc_id,
				    NULL, /* UPN */
				    canon_princ,
				    !is_tgs, /* add_ticket_sig */
				    !is_tgs, /* add_full_sig */
				    &r->et,
				    is_tgs ? &r->pac_attributes : NULL);
    krb5_free_principal(r->context, client);
    krb5_pac_free(r->context, r->pac);
    r->pac = NULL;
    if (ret) {
	_kdc_r_log(r, 4, "PAC signing failed for -- %s",
		   r->cname);
	return ret;
    }

    return ret;
}

/*
 *
 */

krb5_boolean
_kdc_is_anonymous(krb5_context context, krb5_const_principal principal)
{
    return krb5_principal_is_anonymous(context, principal, KRB5_ANON_MATCH_ANY);
}

/*
 * Returns TRUE if principal is the unauthenticated anonymous identity,
 * i.e. WELLKNOWN/ANONYMOUS@WELLKNOWN:ANONYMOUS. Unfortunately due to
 * backwards compatibility logic in krb5_principal_is_anonymous() we
 * have to use our own implementation.
 */

krb5_boolean
_kdc_is_anonymous_pkinit(krb5_context context, krb5_const_principal principal)
{
    return _kdc_is_anonymous(context, principal) &&
	strcmp(principal->realm, KRB5_ANON_REALM) == 0;
}

static int
require_preauth_p(astgs_request_t r)
{
    return r->config->require_preauth
	|| r->client->flags.require_preauth
	|| r->server->flags.require_preauth;
}


/*
 *
 */

static krb5_error_code
add_enc_pa_rep(astgs_request_t r)
{
    krb5_error_code ret;
    krb5_crypto crypto;
    Checksum checksum;
    krb5_data cdata;
    size_t len;

    ret = krb5_crypto_init(r->context, &r->reply_key, 0, &crypto);
    if (ret)
	return ret;

    ret = krb5_create_checksum(r->context, crypto,
			       KRB5_KU_AS_REQ, 0,
			       r->request.data, r->request.length,
			       &checksum);
    krb5_crypto_destroy(r->context, crypto);
    if (ret)
	return ret;

    ASN1_MALLOC_ENCODE(Checksum, cdata.data, cdata.length,
		       &checksum, &len, ret);
    free_Checksum(&checksum);
    if (ret)
	return ret;
    heim_assert(cdata.length == len, "ASN.1 internal error");

    if (r->ek.encrypted_pa_data == NULL) {
	ALLOC(r->ek.encrypted_pa_data);
	if (r->ek.encrypted_pa_data == NULL)
	    return ENOMEM;
    }
    ret = krb5_padata_add(r->context, r->ek.encrypted_pa_data,
			  KRB5_PADATA_REQ_ENC_PA_REP, cdata.data, cdata.length);
    if (ret)
	return ret;

    if (!r->config->enable_fast)
	return 0;

    return krb5_padata_add(r->context, r->ek.encrypted_pa_data,
			   KRB5_PADATA_FX_FAST, NULL, 0);
}

/*
 * Add an authorization data element indicating that a synthetic
 * principal was used, so that the TGS does not accidentally
 * synthesize a non-synthetic principal that has since been deleted.
 */
static krb5_error_code
add_synthetic_princ_ad(astgs_request_t r)
{
    krb5_data data;

    krb5_data_zero(&data);

    return _kdc_tkt_add_if_relevant_ad(r->context, &r->et,
				       KRB5_AUTHDATA_SYNTHETIC_PRINC_USED,
				       &data);
}

static krb5_error_code
get_local_tgs(krb5_context context,
	      krb5_kdc_configuration *config,
	      krb5_const_realm realm,
	      HDB **krbtgtdb,
	      hdb_entry **krbtgt)
{
    krb5_error_code ret;
    krb5_principal tgs_name;

    *krbtgtdb = NULL;
    *krbtgt = NULL;

    ret = krb5_make_principal(context,
			      &tgs_name,
			      realm,
			      KRB5_TGS_NAME,
			      realm,
			      NULL);
    if (ret == 0)
	ret = _kdc_db_fetch(context, config, tgs_name,
		     HDB_F_GET_KRBTGT, NULL, krbtgtdb, krbtgt);

    krb5_free_principal(context, tgs_name);
    return ret;
}

/*
 *
 */

krb5_error_code
_kdc_as_rep(astgs_request_t r)
{
    krb5_kdc_configuration *config = r->config;
    KDC_REQ *req = &r->req;
    const char *from = r->from;
    KDC_REQ_BODY *b = NULL;
    KDC_REP *rep = &r->rep;
    KDCOptions f;
    krb5_enctype setype;
    krb5_error_code ret = 0;
    Key *skey;
    int found_pa = 0;
    int i, flags = HDB_F_FOR_AS_REQ;
    const PA_DATA *pa;
    krb5_boolean is_tgs;
    const char *msg;
    Key *krbtgt_key;
    unsigned krbtgt_kvno;

    memset(rep, 0, sizeof(*rep));

    ALLOC(rep->padata);
    if (rep->padata == NULL) {
	ret = ENOMEM;
	krb5_set_error_message(r->context, ret, N_("malloc: out of memory", ""));
	goto out;
    }

    /*
     * Look for FAST armor and unwrap
     */
    ret = _kdc_fast_unwrap_request(r, NULL, NULL);
    if (ret) {
	_kdc_r_log(r, 1, "FAST unwrap request from %s failed: %d", from, ret);
	goto out;
    }

    /* Validate armor TGT, and initialize the armor client and PAC */
    if (r->armor_ticket) {
	ret = _kdc_fast_check_armor_pac(r, HDB_F_FOR_AS_REQ);
	if (ret)
	    goto out;
    }

    b = &req->req_body;
    f = b->kdc_options;

    if (f.canonicalize)
	flags |= HDB_F_CANON;

    if (b->sname == NULL) {
	ret = KRB5KDC_ERR_S_PRINCIPAL_UNKNOWN;
	_kdc_set_e_text(r, "No server in request");
	goto out;
    }

    ret = _krb5_principalname2krb5_principal(r->context, &r->server_princ,
					     *(b->sname), b->realm);
    if (!ret)
	ret = krb5_unparse_name(r->context, r->server_princ, &r->sname);
    if (ret) {
	kdc_log(r->context, config, 2,
		"AS_REQ malformed server name from %s", from);
	goto out;
    }

    if (b->cname == NULL) {
	ret = KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN;
	_kdc_set_e_text(r, "No client in request");
	goto out;
    }

    ret = _krb5_principalname2krb5_principal(r->context, &r->client_princ,
					     *(b->cname), b->realm);
    if (!ret)
	ret = krb5_unparse_name(r->context, r->client_princ, &r->cname);
    if (ret) {
	kdc_log(r->context, config, 2,
		"AS-REQ malformed client name from %s", from);
	goto out;
    }

    kdc_log(r->context, config, 4, "AS-REQ %s from %s for %s",
	    r->cname, r->from, r->sname);

    is_tgs = krb5_principal_is_krbtgt(r->context, r->server_princ);

    if (_kdc_is_anonymous(r->context, r->client_princ) &&
	!_kdc_is_anon_request(req)) {
	kdc_log(r->context, config, 2, "Anonymous client w/o anonymous flag");
	ret = KRB5KDC_ERR_BADOPTION;
	goto out;
    }

    ret = _kdc_db_fetch(r->context, config, r->client_princ,
                        HDB_F_GET_CLIENT | HDB_F_SYNTHETIC_OK | flags, NULL,
                        &r->clientdb, &r->client);
    switch (ret) {
    case 0:	/* Success */
	break;
    case HDB_ERR_NOT_FOUND_HERE:
	kdc_log(r->context, config, 5, "client %s does not have secrets at this KDC, need to proxy",
		r->cname);
	goto out;
    case HDB_ERR_WRONG_REALM: {
	char *fixed_client_name = NULL;

	ret = krb5_unparse_name(r->context, r->client->principal,
				&fixed_client_name);
	if (ret) {
	    goto out;
	}

	kdc_log(r->context, config, 4, "WRONG_REALM - %s -> %s",
		r->cname, fixed_client_name);
	free(fixed_client_name);

        r->e_text = NULL;
	ret = _kdc_fast_mk_error(r, r->rep.padata, r->armor_crypto,
				 &req->req_body,
                                 r->error_code = KRB5_KDC_ERR_WRONG_REALM,
				 r->client->principal, r->server_princ,
				 NULL, NULL, r->reply);
	goto out;
    }
    default:
    {
	msg = krb5_get_error_message(r->context, ret);
	kdc_log(r->context, config, 4, "UNKNOWN -- %s: %s", r->cname, msg);
	krb5_free_error_message(r->context, msg);
	ret = KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN;
	kdc_audit_setkv_number((kdc_request_t)r, KDC_REQUEST_KV_AUTH_EVENT,
			       KDC_AUTH_EVENT_CLIENT_UNKNOWN);
	goto out;
    }
    }

    kdc_audit_setkv_number((kdc_request_t)r, KDC_REQUEST_KV_AUTH_EVENT,
			   KDC_AUTH_EVENT_CLIENT_FOUND);

    ret = _kdc_db_fetch(r->context, config, r->server_princ,
			HDB_F_GET_SERVER | HDB_F_DELAY_NEW_KEYS |
			flags | (is_tgs ? HDB_F_GET_KRBTGT : 0),
			NULL, &r->serverdb, &r->server);
    switch (ret) {
    case 0:	/* Success */
	break;
    case HDB_ERR_NOT_FOUND_HERE:
	kdc_log(r->context, config, 5, "target %s does not have secrets at this KDC, need to proxy",
		r->sname);
	goto out;
    default:
	msg = krb5_get_error_message(r->context, ret);
	kdc_log(r->context, config, 4, "UNKNOWN -- %s: %s", r->sname, msg);
	krb5_free_error_message(r->context, msg);
	ret = KRB5KDC_ERR_S_PRINCIPAL_UNKNOWN;
	goto out;
    }

    ret = _kdc_check_access(r);
    if(ret)
	goto out;

    /*
     * This has to be here (not later), because we need to have r->sessionetype
     * set prior to calling pa_pkinit_validate(), which in turn calls
     * _kdc_pk_mk_pa_reply(), during padata validation.
     */

    /*
     * Select an enctype for the to-be-issued ticket's session key using the
     * intersection of the client's requested enctypes and the server's (like a
     * root krbtgt, but not necessarily) etypes from its HDB entry.
     */
    ret = _kdc_find_session_etype(r, b->etype.val, b->etype.len,
				  r->server, &r->sessionetype);
    if (ret) {
	kdc_log(r->context, config, 4,
		"Client (%s) from %s has no common enctypes with KDC "
		"to use for the session key",
		r->cname, from);
	goto out;
    }

    /*
     * Select the best encryption type for the KDC without regard to
     * the client since the client never needs to read that data.
     */

    ret = _kdc_get_preferred_key(r->context, config,
				 r->server, r->sname,
				 &setype, &skey);
    if(ret)
	goto out;

    /* If server is not krbtgt, fetch local krbtgt key for signing authdata */
    if (is_tgs) {
	krbtgt_key = skey;
	krbtgt_kvno = r->server->kvno;
    } else {
	ret = get_local_tgs(r->context, config, r->server_princ->realm,
			    &r->krbtgtdb, &r->krbtgt);
	if (ret)
	    goto out;

	ret = _kdc_get_preferred_key(r->context, config, r->krbtgt,
				      r->server_princ->realm,
				      NULL, &krbtgt_key);
	if (ret)
	    goto out;

	krbtgt_kvno = r->server->kvno;
    }

    /*
     * Pre-auth processing
     */

    if(req->padata){
	unsigned int n;

	log_patypes(r, req->padata);

	/* Check if preauth matching */

	for (n = 0; !found_pa && n < sizeof(pat) / sizeof(pat[0]); n++) {
	    if (pat[n].validate == NULL)
		continue;
	    if (r->armor_crypto == NULL && (pat[n].flags & PA_REQ_FAST))
		continue;
	    if (!r->config->enable_fast_cookie && (pat[n].flags & PA_USES_FAST_COOKIE))
		continue;

	    kdc_log(r->context, config, 5,
		    "Looking for %s pa-data -- %s", pat[n].name, r->cname);
	    i = 0;
	    pa = _kdc_find_padata(req, &i, pat[n].type);
	    if (pa) {
                if (r->client->flags.synthetic &&
                    !(pat[n].flags & PA_SYNTHETIC_OK)) {
                    kdc_log(r->context, config, 4, "UNKNOWN -- %s", r->cname);
                    ret = KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN;
                    goto out;
                }
                if (!(pat[n].flags & PA_HARDWARE_AUTH)) {
                    ret = _kdc_hwauth_policy(r);
                    if (ret) {
                        kdc_log(r->context, config, 4, "Hardware authentication required for %s", r->cname);
                        goto out;
                    }
                }
		kdc_audit_addkv((kdc_request_t)r, KDC_AUDIT_VIS, "pa", "%s",
				pat[n].name);
		ret = pat[n].validate(r, pa);
		if (ret != 0) {
		    krb5_error_code  ret2;
		    Key *ckey = NULL;
		    krb5_boolean default_salt;

		    if (ret != KRB5_KDC_ERR_MORE_PREAUTH_DATA_REQUIRED &&
			!kdc_audit_getkv((kdc_request_t)r, KDC_REQUEST_KV_AUTH_EVENT))
			kdc_audit_setkv_number((kdc_request_t)r, KDC_REQUEST_KV_AUTH_EVENT,
					       KDC_AUTH_EVENT_PREAUTH_FAILED);

		    /*
		     * If there is a client key, send ETYPE_INFO{,2}
		     */
		    if (!r->client->flags.locked_out) {
			    ret2 = _kdc_find_etype(r, KFE_IS_PREAUTH|KFE_USE_CLIENT,
						   b->etype.val, b->etype.len,
						   NULL, &ckey, &default_salt);
			    if (ret2 == 0) {
				ret2 = get_pa_etype_info_both(r->context, config, &b->etype,
				                              r->rep.padata, ckey, !default_salt);
				if (ret2 != 0)
				    ret = ret2;
			    }
		    }
		    goto out;
		}
		if (!kdc_audit_getkv((kdc_request_t)r, KDC_REQUEST_KV_AUTH_EVENT))
		    kdc_audit_setkv_number((kdc_request_t)r, KDC_REQUEST_KV_AUTH_EVENT,
					   KDC_AUTH_EVENT_PREAUTH_SUCCEEDED);
		kdc_log(r->context, config, 4,
			"%s pre-authentication succeeded -- %s",
			pat[n].name, r->cname);
		found_pa = 1;
		r->pa_used = &pat[n];
		r->et.flags.pre_authent = 1;
	    }
	}
    }

    if (found_pa == 0) {
	Key *ckey = NULL;
	size_t n;
	krb5_boolean default_salt;

        if (r->client->flags.synthetic) {
            kdc_log(r->context, config, 4, "UNKNOWN -- %s", r->cname);
            ret = KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN;
            goto out;
        }

	for (n = 0; n < sizeof(pat) / sizeof(pat[0]); n++) {
	    if ((pat[n].flags & PA_ANNOUNCE) == 0)
		continue;

	    if (!r->armor_crypto && (pat[n].flags & PA_REQ_FAST))
		continue;
	    if (pat[n].type == KRB5_PADATA_PKINIT_KX && !r->config->allow_anonymous)
		continue;
	    if (pat[n].type == KRB5_PADATA_ENC_TIMESTAMP) {
		if (r->armor_crypto && !r->config->enable_armored_pa_enc_timestamp)
		    continue;
		if (!r->armor_crypto && !r->config->enable_unarmored_pa_enc_timestamp)
		    continue;
	    }
	    if (pat[n].type == KRB5_PADATA_FX_FAST && !r->config->enable_fast)
		continue;
	    if (pat[n].type == KRB5_PADATA_GSS && !r->config->enable_gss_preauth)
		continue;
	    if (!r->config->enable_fast_cookie && (pat[n].flags & PA_USES_FAST_COOKIE))
		continue;

	    ret = krb5_padata_add(r->context, r->rep.padata,
				  pat[n].type, NULL, 0);
	    if (ret)
		goto out;
	}

	/*
	 * If there is a client key, send ETYPE_INFO{,2}
	 */
	ret = _kdc_find_etype(r, KFE_IS_PREAUTH|KFE_USE_CLIENT,
			      b->etype.val, b->etype.len,
			      NULL, &ckey, &default_salt);
	if (ret == 0) {
	    ret = get_pa_etype_info_both(r->context, config, &b->etype,
					 r->rep.padata, ckey, !default_salt);
	    if (ret)
		goto out;
	}

	/*
	 * If the client indicated support for PKINIT Freshness, send back a
	 * freshness token.
	 */
	ret = send_freshness_token(r, krbtgt_key, krbtgt_kvno);
	if (ret)
	    goto out;

	/* 
	 * send requre preauth is its required or anon is requested,
	 * anon is today only allowed via preauth mechanisms.
	 */
	if (require_preauth_p(r) || _kdc_is_anon_request(&r->req)) {
	    ret = KRB5KDC_ERR_PREAUTH_REQUIRED;
	    _kdc_set_e_text(r, "Need to use PA-ENC-TIMESTAMP/PA-PK-AS-REQ");
	    goto out;
	}

	if (ckey == NULL) {
	    ret = KRB5KDC_ERR_CLIENT_NOTYET;
	    _kdc_set_e_text(r, "Doesn't have a client key available");
	    goto out;
	}
	krb5_free_keyblock_contents(r->context,  &r->reply_key);
	ret = krb5_copy_keyblock_contents(r->context, &ckey->key, &r->reply_key);
	if (ret)
	    goto out;
    }

    r->canon_client_princ = r->client->principal;

    if (_kdc_is_anon_request(&r->req)) {
	ret = _kdc_check_anon_policy(r);
	if (ret) {
	    _kdc_set_e_text(r, "Anonymous ticket requests are disabled");
	    goto out;
	}

	r->et.flags.anonymous = 1;
    }

    kdc_audit_setkv_number((kdc_request_t)r, KDC_REQUEST_KV_AUTH_EVENT,
			   KDC_AUTH_EVENT_CLIENT_AUTHORIZED);

    if(f.renew || f.validate || f.proxy || f.forwarded || f.enc_tkt_in_skey) {
	ret = KRB5KDC_ERR_BADOPTION;
	_kdc_set_e_text(r, "Bad KDC options");
	goto out;
    }

    /*
     * Build reply
     */
    rep->pvno = 5;
    rep->msg_type = krb_as_rep;

    if (!config->historical_anon_realm &&
        _kdc_is_anonymous(r->context, r->client_princ)) {
	const Realm anon_realm = KRB5_ANON_REALM;
	ret = copy_Realm(&anon_realm, &rep->crealm);
    } else if (f.canonicalize || r->client->flags.force_canonicalize)
	ret = copy_Realm(&r->canon_client_princ->realm, &rep->crealm);
    else
	ret = copy_Realm(&r->client_princ->realm, &rep->crealm);
    if (ret)
	goto out;
    if (r->et.flags.anonymous)
	ret = _kdc_make_anonymous_principalname(&rep->cname);
    else if (f.canonicalize || r->client->flags.force_canonicalize)
	ret = _krb5_principal2principalname(&rep->cname, r->canon_client_princ);
    else
	ret = _krb5_principal2principalname(&rep->cname, r->client_princ);
    if (ret)
	goto out;

    rep->ticket.tkt_vno = 5;
    if (f.canonicalize || r->server->flags.force_canonicalize)
	ret = copy_Realm(&r->server->principal->realm, &rep->ticket.realm);
    else
	ret = copy_Realm(&r->server_princ->realm, &rep->ticket.realm);
    if (ret)
	goto out;
    if (f.canonicalize || r->server->flags.force_canonicalize)
	_krb5_principal2principalname(&rep->ticket.sname,
				      r->server->principal);
    else
	_krb5_principal2principalname(&rep->ticket.sname,
				      r->server_princ);
    /* java 1.6 expects the name to be the same type, lets allow that
     * uncomplicated name-types, when f.canonicalize is not set (to
     * match Windows Server 1709). */
#define CNT(sp,t) (((sp)->sname->name_type) == KRB5_NT_##t)
    if (!f.canonicalize
	&& (CNT(b, UNKNOWN) || CNT(b, PRINCIPAL) || CNT(b, SRV_INST) || CNT(b, SRV_HST) || CNT(b, SRV_XHST))) {
	rep->ticket.sname.name_type = b->sname->name_type;
    }
#undef CNT

    r->et.flags.initial = 1;
    if(r->client->flags.forwardable && r->server->flags.forwardable)
	r->et.flags.forwardable = f.forwardable;
    if(r->client->flags.proxiable && r->server->flags.proxiable)
	r->et.flags.proxiable = f.proxiable;
    else if (f.proxiable) {
	_kdc_set_e_text(r, "Ticket may not be proxiable");
	ret = KRB5KDC_ERR_POLICY;
	goto out;
    }
    if(r->client->flags.postdate && r->server->flags.postdate)
	r->et.flags.may_postdate = f.allow_postdate;
    else if (f.allow_postdate){
	_kdc_set_e_text(r, "Ticket may not be postdateable");
	ret = KRB5KDC_ERR_POLICY;
	goto out;
    }

    if (b->addresses)
        kdc_audit_addaddrs((kdc_request_t)r, b->addresses, "reqaddrs");

    /* check for valid set of addresses */
    if (!_kdc_check_addresses(r, b->addresses, r->addr)) {
        if (r->config->warn_ticket_addresses) {
            kdc_audit_setkv_bool((kdc_request_t)r, "wrongaddr", TRUE);
        } else {
            _kdc_set_e_text(r, "Request from wrong address");
            ret = KRB5KRB_AP_ERR_BADADDR;
            goto out;
        }
    }

    ret = copy_PrincipalName(&rep->cname, &r->et.cname);
    if (ret)
	goto out;
    ret = copy_Realm(&rep->crealm, &r->et.crealm);
    if (ret)
	goto out;

    {
	time_t start;
	time_t t;
	
	start = r->et.authtime = kdc_time;

	if(f.postdated && req->req_body.from){
	    ALLOC(r->et.starttime);
	    start = *r->et.starttime = *req->req_body.from;
	    r->et.flags.invalid = 1;
	    r->et.flags.postdated = 1; /* XXX ??? */
	}
	_kdc_fix_time(&b->till);
	t = *b->till;

	/* be careful not to overflow */

        /*
         * Pre-auth can override r->client->max_life if configured.
         *
         * See pre-auth methods, specifically PKINIT, which can get or derive
         * this from the client's certificate.
         */
        if (r->pa_max_life > 0)
            t = rk_time_add(start, min(rk_time_sub(t, start), r->pa_max_life));
        else if (r->client->max_life)
	    t = rk_time_add(start, min(rk_time_sub(t, start),
                                       *r->client->max_life));

	if (r->server->max_life)
	    t = rk_time_add(start, min(rk_time_sub(t, start),
                                       *r->server->max_life));

        /* Pre-auth can bound endtime as well */
        if (r->pa_endtime > 0)
            t = rk_time_add(start, min(rk_time_sub(t, start), r->pa_endtime));
#if 0
	t = min(t, rk_time_add(start, realm->max_life));
#endif
	r->et.endtime = t;

	if (start > r->et.endtime) {
	    _kdc_set_e_text(r, "Requested effective lifetime is negative or too short");
	    ret = KRB5KDC_ERR_NEVER_VALID;
	    goto out;
	}

	if(f.renewable_ok && r->et.endtime < *b->till){
	    f.renewable = 1;
	    if(b->rtime == NULL){
		ALLOC(b->rtime);
		*b->rtime = 0;
	    }
	    if(*b->rtime < *b->till)
		*b->rtime = *b->till;
	}
	if(f.renewable && b->rtime){
	    t = *b->rtime;
	    if(t == 0)
		t = MAX_TIME;
	    if(r->client->max_renew)
		t = rk_time_add(start, min(rk_time_sub(t, start),
                                           *r->client->max_renew));
	    if(r->server->max_renew)
		t = rk_time_add(start, min(rk_time_sub(t, start),
                                           *r->server->max_renew));
#if 0
	    t = min(t, rk_time_add(start, realm->max_renew));
#endif
	    ALLOC(r->et.renew_till);
	    *r->et.renew_till = t;
	    r->et.flags.renewable = 1;
	}
    }

    if(b->addresses){
	ALLOC(r->et.caddr);
	copy_HostAddresses(b->addresses, r->et.caddr);
    }

    r->et.transited.tr_type = domain_X500_Compress;
    krb5_data_zero(&r->et.transited.contents);

    /* The MIT ASN.1 library (obviously) doesn't tell lengths encoded
     * as 0 and as 0x80 (meaning indefinite length) apart, and is thus
     * incapable of correctly decoding SEQUENCE OF's of zero length.
     *
     * To fix this, always send at least one no-op last_req
     *
     * If there's a pw_end or valid_end we will use that,
     * otherwise just a dummy lr.
     */
    r->ek.last_req.val = malloc(2 * sizeof(*r->ek.last_req.val));
    if (r->ek.last_req.val == NULL) {
	ret = ENOMEM;
	goto out;
    }
    r->ek.last_req.len = 0;
    if (r->client->pw_end
	&& (config->kdc_warn_pwexpire == 0
	    || kdc_time + config->kdc_warn_pwexpire >= *r->client->pw_end)) {
	r->ek.last_req.val[r->ek.last_req.len].lr_type  = LR_PW_EXPTIME;
	r->ek.last_req.val[r->ek.last_req.len].lr_value = *r->client->pw_end;
	++r->ek.last_req.len;
    }
    if (r->client->valid_end) {
	r->ek.last_req.val[r->ek.last_req.len].lr_type  = LR_ACCT_EXPTIME;
	r->ek.last_req.val[r->ek.last_req.len].lr_value = *r->client->valid_end;
	++r->ek.last_req.len;
    }
    if (r->ek.last_req.len == 0) {
	r->ek.last_req.val[r->ek.last_req.len].lr_type  = LR_NONE;
	r->ek.last_req.val[r->ek.last_req.len].lr_value = 0;
	++r->ek.last_req.len;
    }
    /* Set the nonce if it’s not already set. */
    if (!r->ek.nonce) {
	r->ek.nonce = b->nonce;
    }
    if (r->client->valid_end || r->client->pw_end) {
	ALLOC(r->ek.key_expiration);
	if (r->client->valid_end) {
	    if (r->client->pw_end)
		*r->ek.key_expiration = min(*r->client->valid_end,
					 *r->client->pw_end);
	    else
		*r->ek.key_expiration = *r->client->valid_end;
	} else
	    *r->ek.key_expiration = *r->client->pw_end;
    } else
	r->ek.key_expiration = NULL;
    r->ek.flags = r->et.flags;
    r->ek.authtime = r->et.authtime;
    if (r->et.starttime) {
	ALLOC(r->ek.starttime);
	*r->ek.starttime = *r->et.starttime;
    }
    r->ek.endtime = r->et.endtime;
    if (r->et.renew_till) {
	ALLOC(r->ek.renew_till);
	*r->ek.renew_till = *r->et.renew_till;
    }
    ret = copy_Realm(&rep->ticket.realm, &r->ek.srealm);
    if (ret)
	goto out;
    ret = copy_PrincipalName(&rep->ticket.sname, &r->ek.sname);
    if (ret)
	goto out;
    if(r->et.caddr){
	ALLOC(r->ek.caddr);
	copy_HostAddresses(r->et.caddr, r->ek.caddr);
    }

    /*
     * Check session and reply keys
     */

    if (r->session_key.keytype == ETYPE_NULL) {
	ret = krb5_generate_random_keyblock(r->context, r->sessionetype, &r->session_key);
	if (ret)
	    goto out;
    }

    if (r->reply_key.keytype == ETYPE_NULL) {
	_kdc_set_e_text(r, "Client has no reply key");
	ret = KRB5KDC_ERR_CLIENT_NOTYET;
	goto out;
    }

    ret = copy_EncryptionKey(&r->session_key, &r->et.key);
    if (ret)
	goto out;

    ret = copy_EncryptionKey(&r->session_key, &r->ek.key);
    if (ret)
	goto out;

    if (r->client->flags.synthetic) {
	ret = add_synthetic_princ_ad(r);
	if (ret)
	    goto out;
    }

    _kdc_log_timestamp(r, "AS-REQ", r->et.authtime,
		       r->et.starttime, r->et.endtime,
		       r->et.renew_till);

    _log_astgs_req(r, setype);

    /*
     * We always say we support FAST/enc-pa-rep
     */

    r->et.flags.enc_pa_rep = r->ek.flags.enc_pa_rep = 1;

    /*
     * update reply-key with strengthen-key
     */

    ret = _kdc_fast_strengthen_reply_key(r);
    if (ret)
	goto out;

    /*
     * Add REQ_ENC_PA_REP if client supports it
     */

    i = 0;
    pa = _kdc_find_padata(req, &i, KRB5_PADATA_REQ_ENC_PA_REP);
    if (pa) {

	ret = add_enc_pa_rep(r);
	if (ret) {
	    msg = krb5_get_error_message(r->context, ret);
	    _kdc_r_log(r, 4, "add_enc_pa_rep failed: %s: %d", msg, ret);
	    krb5_free_error_message(r->context, msg);
	    goto out;
	}
    }

    /* Add the PAC */
    if (!r->et.flags.anonymous) {
	ret = generate_pac(r, skey, krbtgt_key, is_tgs);
	if (ret)
	    goto out;
    }

    /*
     * No more changes to the ticket (r->et) from this point on, lest
     * the checksums in the PAC be invalidated.
     */

    /*
     * Last chance for plugins to update reply
     */
    ret = _kdc_finalize_reply(r);
    if (ret)
	goto out;

    /*
     * Don't send kvno from client entry if the pre-authentication
     * mechanism replaced the reply key.
     */

    ret = _kdc_encode_reply(r->context, config,
			    r, req->req_body.nonce, setype,
			    r->server->kvno, &skey->key,
			    pa_used_flag_isset(r, PA_REPLACE_REPLY_KEY) ? 0 : r->client->kvno,
			    0, r->reply);
    if (ret)
	goto out;

    /*
     * Check if message is too large
     */
    if (r->datagram_reply && r->reply->length > config->max_datagram_reply_length) {
	krb5_data_free(r->reply);
	ret = KRB5KRB_ERR_RESPONSE_TOO_BIG;
	_kdc_set_e_text(r, "Reply packet too large");
    }

out:
    if (ret) {
	/* Overwrite ‘error_code’ only if we have an actual error. */
	r->error_code = ret;
    }
    {
	krb5_error_code ret2 = _kdc_audit_request(r);
	if (ret2) {
	    krb5_data_free(r->reply);
	    ret = ret2;
	}
    }

    /*
     * In case of a non proxy error, build an error message.
     */
    if (ret != 0 && ret != HDB_ERR_NOT_FOUND_HERE && r->reply->length == 0) {
	kdc_log(r->context, config, 5, "as-req: sending error: %d to client", ret);
	ret = _kdc_fast_mk_error(r,
				 r->rep.padata,
			         r->armor_crypto,
			         &req->req_body,
			         r->error_code ? r->error_code : ret,
			         r->client_princ,
			         r->server_princ,
			         NULL, NULL,
			         r->reply);
    }

    if (r->pa_used && r->pa_used->cleanup)
	r->pa_used->cleanup(r);

    free_AS_REP(&r->rep);
    free_EncTicketPart(&r->et);
    free_EncKDCRepPart(&r->ek);
    _kdc_free_fast_state(&r->fast);

    if (r->client_princ) {
	krb5_free_principal(r->context, r->client_princ);
	r->client_princ = NULL;
    }
    if (r->server_princ){
	krb5_free_principal(r->context, r->server_princ);
	r->server_princ = NULL;
    }
    if (r->client)
	_kdc_free_ent(r->context, r->clientdb, r->client);
    if (r->server)
	_kdc_free_ent(r->context, r->serverdb, r->server);
    if (r->krbtgt)
	_kdc_free_ent(r->context, r->krbtgtdb, r->krbtgt);
    if (r->armor_crypto) {
	krb5_crypto_destroy(r->context, r->armor_crypto);
	r->armor_crypto = NULL;
    }
    if (r->armor_ticket)
	krb5_free_ticket(r->context, r->armor_ticket);
    if (r->armor_server)
	_kdc_free_ent(r->context, r->armor_serverdb, r->armor_server);
    if (r->armor_client_principal) {
	krb5_free_principal(r->context, r->armor_client_principal);
	r->armor_client_principal = NULL;
    }
    if (r->armor_client)
	_kdc_free_ent(r->context,
		      r->armor_clientdb,
		      r->armor_client);
    if (r->armor_pac)
	krb5_pac_free(r->context, r->armor_pac);
    krb5_free_keyblock_contents(r->context, &r->reply_key);
    krb5_free_keyblock_contents(r->context, &r->enc_ad_key);
    krb5_free_keyblock_contents(r->context, &r->session_key);
    krb5_free_keyblock_contents(r->context, &r->strengthen_key);
    krb5_pac_free(r->context, r->pac);

    return ret;
}
