/*
 * Copyright (c) 2011 Kungliga Tekniska Högskolan
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

#include "krb5_locl.h"
#ifndef WIN32
#include <heim-ipc.h>
#endif

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
_krb5_fast_cf2(krb5_context context,
	       krb5_keyblock *key1,
	       const char *pepper1,
	       krb5_keyblock *key2,
	       const char *pepper2,
	       krb5_keyblock *armorkey,
	       krb5_crypto *armor_crypto)
{
    krb5_crypto crypto1, crypto2;
    krb5_data pa1, pa2;
    krb5_error_code ret;

    ret = krb5_crypto_init(context, key1, 0, &crypto1);
    if (ret)
	return ret;

    ret = krb5_crypto_init(context, key2, 0, &crypto2);
    if (ret) {
	krb5_crypto_destroy(context, crypto1);
	return ret;
    }

    pa1.data = rk_UNCONST(pepper1);
    pa1.length = strlen(pepper1);
    pa2.data = rk_UNCONST(pepper2);
    pa2.length = strlen(pepper2);

    ret = krb5_crypto_fx_cf2(context, crypto1, crypto2, &pa1, &pa2,
			     key1->keytype, armorkey);
    krb5_crypto_destroy(context, crypto1);
    krb5_crypto_destroy(context, crypto2);
    if (ret)
	return ret;

    if (armor_crypto) {
	ret = krb5_crypto_init(context, armorkey, 0, armor_crypto);
	if (ret)
	    krb5_free_keyblock_contents(context, armorkey);
    }

    return ret;
}

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
_krb5_fast_armor_key(krb5_context context,
		     krb5_keyblock *subkey,
		     krb5_keyblock *sessionkey,
		     krb5_keyblock *armorkey,
		     krb5_crypto *armor_crypto)
{
    return _krb5_fast_cf2(context,
			  subkey,
			  "subkeyarmor",
			  sessionkey,
			  "ticketarmor",
			  armorkey,
			  armor_crypto);
}

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
_krb5_fast_explicit_armor_key(krb5_context context,
			      krb5_keyblock *armorkey,
			      krb5_keyblock *subkey,
			      krb5_keyblock *explicit_armorkey,
			      krb5_crypto *explicit_armor_crypto)
{
    return _krb5_fast_cf2(context,
			  armorkey,
			  "explicitarmor",
			  subkey,
			  "tgsarmor",
			  explicit_armorkey,
			  explicit_armor_crypto);
}

static krb5_error_code
check_fast(krb5_context context, struct krb5_fast_state *state)
{
    if (state && (state->flags & KRB5_FAST_EXPECTED)) {
	krb5_set_error_message(context, KRB5KRB_AP_ERR_MODIFIED,
			       "Expected FAST, but no FAST "
			       "was in the response from the KDC");
	return KRB5KRB_AP_ERR_MODIFIED;
    }
    return 0;
}

static krb5_error_code
make_local_fast_ap_fxarmor(krb5_context context,
			   krb5_ccache armor_ccache,
			   krb5_const_realm realm,
			   krb5_data *armor_value,
			   krb5_keyblock *armor_key,
			   krb5_crypto *armor_crypto)
{
    krb5_auth_context auth_context = NULL;
    krb5_creds cred, *credp = NULL;
    krb5_error_code ret;
    krb5_data empty;
    krb5_const_realm tgs_realm;

    if (armor_ccache == NULL) {
	krb5_set_error_message(context, EINVAL,
			       "Armor credential cache required");
	return EINVAL;
    }

    krb5_data_zero(&empty);
    memset(&cred, 0, sizeof(cred));

    ret = krb5_auth_con_init (context, &auth_context);
    if (ret)
	goto out;

    ret = krb5_cc_get_principal(context, armor_ccache, &cred.client);
    if (ret)
	goto out;

    /*
     * Make sure we don't ask for a krbtgt/WELLKNOWN:ANONYMOUS
     */
    if (krb5_principal_is_anonymous(context, cred.client,
				    KRB5_ANON_MATCH_UNAUTHENTICATED))
	tgs_realm = realm;
    else
	tgs_realm = cred.client->realm;

    ret = krb5_make_principal(context, &cred.server,
			      tgs_realm,
			      KRB5_TGS_NAME,
			      tgs_realm,
			      NULL);
    if (ret)
	goto out;

    ret = krb5_get_credentials(context, 0, armor_ccache, &cred, &credp);
    if (ret)
	goto out;

    ret = krb5_auth_con_add_AuthorizationData(context, auth_context,
					      KRB5_AUTHDATA_FX_FAST_ARMOR,
					      &empty);
    if (ret)
	goto out;

    ret = krb5_mk_req_extended(context,
			       &auth_context,
			       AP_OPTS_USE_SUBKEY,
			       NULL,
			       credp,
			       armor_value);
    if (ret)
	goto out;

    ret = _krb5_fast_armor_key(context,
			       auth_context->local_subkey,
			       auth_context->keyblock,
			       armor_key,
			       armor_crypto);
    if (ret)
	goto out;

 out:
    if (auth_context)
	krb5_auth_con_free(context, auth_context);
    if (credp)
	krb5_free_creds(context, credp);
    krb5_free_principal(context, cred.server);
    krb5_free_principal(context, cred.client);

    return ret;
}

#ifndef WIN32
static heim_base_once_t armor_service_once = HEIM_BASE_ONCE_INIT;
static heim_ipc armor_service = NULL;

static void
fast_armor_init_ipc(void *ctx)
{
    heim_ipc *ipc = ctx;
    heim_ipc_init_context("ANY:org.h5l.armor-service", ipc);
}
#endif

static krb5_error_code
make_fast_ap_fxarmor(krb5_context context,
		     struct krb5_fast_state *state,
		     krb5_const_realm realm,
		     KrbFastArmor **armor)
{
    KrbFastArmor *fxarmor = NULL;
    krb5_error_code ret;

    *armor = NULL;

    ALLOC(fxarmor, 1);
    if (fxarmor == NULL) {
	ret = ENOMEM;
	goto out;
    }

    if (state->flags & KRB5_FAST_AP_ARMOR_SERVICE) {
#ifdef WIN32
	krb5_set_error_message(context, ENOTSUP, "Fast armor IPC service not supportted yet on Windows");
	ret = ENOTSUP;
	goto out;
#else
	KERB_ARMOR_SERVICE_REPLY msg;
	krb5_data request, reply;

	heim_base_once_f(&armor_service_once, &armor_service, fast_armor_init_ipc);
	if (armor_service == NULL) {
	    krb5_set_error_message(context, ENOENT, "Failed to open fast armor service");
	    ret = ENOENT;
	    goto out;
	}

	krb5_data_zero(&reply);

	request.data = rk_UNCONST(realm);
	request.length = strlen(realm);

	ret = heim_ipc_call(armor_service, &request, &reply, NULL);
	if (ret) {
	    krb5_set_error_message(context, ret, "Failed to get armor service credential");
	    goto out;
	}

	ret = decode_KERB_ARMOR_SERVICE_REPLY(reply.data, reply.length, &msg, NULL);
	krb5_data_free(&reply);
	if (ret)
	    goto out;

	ret = copy_KrbFastArmor(&msg.armor, fxarmor);
	if (ret) {
	    free_KERB_ARMOR_SERVICE_REPLY(&msg);
	    goto out;
	}

	ret = krb5_copy_keyblock_contents(context, &msg.armor_key, &state->armor_key);
	free_KERB_ARMOR_SERVICE_REPLY(&msg);
	if (ret)
	    goto out;

	ret = krb5_crypto_init(context, &state->armor_key, 0, &state->armor_crypto);
	if (ret)
	    goto out;
#endif /* WIN32 */
    } else {
	fxarmor->armor_type = 1;

	ret = make_local_fast_ap_fxarmor(context,
					 state->armor_ccache,
					 realm,
					 &fxarmor->armor_value,
					 &state->armor_key,
					 &state->armor_crypto);
	if (ret)
	    goto out;
    }


    *armor = fxarmor;
    fxarmor = NULL;

 out:
    if (fxarmor) {
	free_KrbFastArmor(fxarmor);
	free(fxarmor);
    }
    return ret;
}

static krb5_error_code
unwrap_fast_rep(krb5_context context,
		struct krb5_fast_state *state,
		PA_DATA *pa,
		KrbFastResponse *fastrep)
{
    PA_FX_FAST_REPLY fxfastrep;
    krb5_error_code ret;

    memset(&fxfastrep, 0, sizeof(fxfastrep));

    ret = decode_PA_FX_FAST_REPLY(pa->padata_value.data,
				  pa->padata_value.length,
				  &fxfastrep, NULL);
    if (ret)
	return ret;

    if (fxfastrep.element == choice_PA_FX_FAST_REPLY_armored_data) {
	krb5_data data;

	ret = krb5_decrypt_EncryptedData(context,
					 state->armor_crypto,
					 KRB5_KU_FAST_REP,
					 &fxfastrep.u.armored_data.enc_fast_rep,
					 &data);
	if (ret)
	    goto out;

	ret = decode_KrbFastResponse(data.data, data.length, fastrep, NULL);
	krb5_data_free(&data);
	if (ret)
	    goto out;

    } else {
	ret = KRB5KDC_ERR_PREAUTH_FAILED;
	goto out;
    }

 out:
    free_PA_FX_FAST_REPLY(&fxfastrep);

    return ret;
}

static krb5_error_code
set_anon_principal(krb5_context context, PrincipalName **p)
{

    ALLOC((*p), 1);
    if (*p == NULL)
	goto fail;

    (*p)->name_type = KRB5_NT_PRINCIPAL;

    ALLOC_SEQ(&(*p)->name_string, 2);
    if ((*p)->name_string.val == NULL)
	goto fail;

    (*p)->name_string.val[0] = strdup(KRB5_WELLKNOWN_NAME);
    if ((*p)->name_string.val[0] == NULL)
	goto fail;

    (*p)->name_string.val[1] = strdup(KRB5_ANON_NAME);
    if ((*p)->name_string.val[1] == NULL)
	goto fail;

    return 0;
 fail:
    if (*p) {
	if ((*p)->name_string.val) {
	    free((*p)->name_string.val[0]);
	    free((*p)->name_string.val[1]);
	    free((*p)->name_string.val);
	}
	free(*p);
    }

    return krb5_enomem(context);
}

krb5_error_code
_krb5_fast_create_armor(krb5_context context,
			struct krb5_fast_state *state,
			const char *realm)
{
    krb5_error_code ret;

    if (state->armor_crypto == NULL) {
	if (state->armor_ccache || state->armor_ac || (state->flags & KRB5_FAST_AP_ARMOR_SERVICE)) {
	    /*
	     * Instead of keeping state in FX_COOKIE in the KDC, we
	     * rebuild a new armor key for every request, because this
	     * is what the MIT KDC expect and RFC6113 is vage about
	     * what the behavior should be.
	     */
	    state->type = choice_PA_FX_FAST_REQUEST_armored_data;
	} else {
	    return check_fast(context, state);
	}
    }

    if (state->type == choice_PA_FX_FAST_REQUEST_armored_data) {
	if (state->armor_crypto) {
	    krb5_crypto_destroy(context, state->armor_crypto);
	    state->armor_crypto = NULL;
	}
	if (state->strengthen_key) {
	    krb5_free_keyblock(context, state->strengthen_key);
	    state->strengthen_key = NULL;
	}
	krb5_free_keyblock_contents(context, &state->armor_key);

	/*
	 * If we have a armor auth context, its because the caller
	 * wants us to do an implicit FAST armor (TGS-REQ).
	 */
	if (state->armor_ac) {
	    heim_assert((state->flags & KRB5_FAST_AS_REQ) == 0, "FAST AS with AC");

	    ret = _krb5_fast_armor_key(context,
				       state->armor_ac->local_subkey,
				       state->armor_ac->keyblock,
				       &state->armor_key,
				       &state->armor_crypto);
	    if (ret)
		goto out;
	} else {
	    heim_assert((state->flags & KRB5_FAST_AS_REQ) != 0, "FAST TGS without AC");

	    if (state->armor_data) {
		free_KrbFastArmor(state->armor_data);
		free(state->armor_data);
                state->armor_data = NULL;
	    }
	    ret = make_fast_ap_fxarmor(context, state, realm,
				       &state->armor_data);
	    if (ret)
		goto out;
	}
    } else {
	heim_abort("unknown state type: %d", (int)state->type);
    }
 out:
    return ret;
}


krb5_error_code
_krb5_fast_wrap_req(krb5_context context,
		    struct krb5_fast_state *state,
		    KDC_REQ *req)
{
    PA_FX_FAST_REQUEST fxreq;
    krb5_error_code ret;
    KrbFastReq fastreq;
    krb5_data data, aschecksum_data, tgschecksum_data;
    const krb5_data *checksum_data = NULL;
    size_t size = 0;
    krb5_boolean readd_padata_to_outer = FALSE;

    if (state->flags & KRB5_FAST_DISABLED) {
	_krb5_debug(context, 10, "fast disabled, not doing any fast wrapping");
	return 0;
    }

    memset(&fxreq, 0, sizeof(fxreq));
    memset(&fastreq, 0, sizeof(fastreq));
    krb5_data_zero(&data);
    krb5_data_zero(&aschecksum_data);
    krb5_data_zero(&tgschecksum_data);

    if (state->armor_crypto == NULL)
	return check_fast(context, state);

    state->flags |= KRB5_FAST_EXPECTED;

    fastreq.fast_options.hide_client_names = 1;

    ret = copy_KDC_REQ_BODY(&req->req_body, &fastreq.req_body);
    if (ret)
	goto out;

    /*
     * In the case of a AS-REQ, remove all account names. Want to this
     * for TGS-REQ too, but due to layering this is tricky.
     *
     * 1. TGS-REQ need checksum of REQ-BODY
     * 2. FAST needs checksum of TGS-REQ, so, FAST needs to happen after TGS-REQ
     * 3. FAST privacy mangaling needs to happen before TGS-REQ does the checksum in 1.
     *
     * So lets not modify the bits for now for TGS-REQ
     */
    if (state->flags & KRB5_FAST_AS_REQ) {
	free_KDC_REQ_BODY(&req->req_body);

	req->req_body.realm = strdup(KRB5_ANON_REALM);
	if (req->req_body.realm == NULL) {
	    ret = krb5_enomem(context);
	    goto out;
	}

	ret = set_anon_principal(context, &req->req_body.cname);
	if (ret)
	    goto out;

	ALLOC(req->req_body.till, 1);
	*req->req_body.till = 0;

	ASN1_MALLOC_ENCODE(KDC_REQ_BODY,
			   aschecksum_data.data,
			   aschecksum_data.length,
			   &req->req_body,
			   &size, ret);
	if (ret)
	    goto out;
	heim_assert(aschecksum_data.length == size, "ASN.1 internal error");

	checksum_data = &aschecksum_data;

	if (req->padata) {
	    ret = copy_METHOD_DATA(req->padata, &fastreq.padata);
	    free_METHOD_DATA(req->padata);
	    if (ret)
		goto out;
	}
    } else {
	const PA_DATA *tgs_req_ptr = NULL;
	int tgs_req_idx = 0;
	size_t i;

	heim_assert(req->padata != NULL, "req->padata is NULL");

	tgs_req_ptr = krb5_find_padata(req->padata->val,
				       req->padata->len,
				       KRB5_PADATA_TGS_REQ,
				       &tgs_req_idx);
	heim_assert(tgs_req_ptr != NULL, "KRB5_PADATA_TGS_REQ not found");
	heim_assert(tgs_req_idx == 0, "KRB5_PADATA_TGS_REQ not first");

	tgschecksum_data.data = tgs_req_ptr->padata_value.data;
	tgschecksum_data.length = tgs_req_ptr->padata_value.length;
	checksum_data = &tgschecksum_data;

	/*
	 * Now copy all remaining once to
	 * the fastreq.padata and clear
	 * them in the outer req first,
	 * and remember to readd them later.
	 */
	readd_padata_to_outer = TRUE;

	for (i = 1; i < req->padata->len; i++) {
	    PA_DATA *val = &req->padata->val[i];

	    ret = krb5_padata_add(context,
				  &fastreq.padata,
				  val->padata_type,
				  val->padata_value.data,
				  val->padata_value.length);
	    if (ret) {
		krb5_set_error_message(context, ret,
				       N_("malloc: out of memory", ""));
		goto out;
	    }
	    val->padata_value.data = NULL;
	    val->padata_value.length = 0;
	}

	/*
	 * Only TGS-REQ remaining
	 */
	req->padata->len = 1;
    }

    if (req->padata == NULL) {
	ALLOC(req->padata, 1);
	if (req->padata == NULL) {
	    ret = krb5_enomem(context);
	    goto out;
	}
    }

    ASN1_MALLOC_ENCODE(KrbFastReq, data.data, data.length, &fastreq, &size, ret);
    if (ret)
	goto out;
    heim_assert(data.length == size, "ASN.1 internal error");

    fxreq.element = state->type;

    if (state->type == choice_PA_FX_FAST_REQUEST_armored_data) {
	fxreq.u.armored_data.armor = state->armor_data;
	state->armor_data = NULL;

	heim_assert(state->armor_crypto != NULL,
		    "FAST armor key missing when FAST started");

	ret = krb5_create_checksum(context, state->armor_crypto,
				   KRB5_KU_FAST_REQ_CHKSUM, 0,
				   checksum_data->data,
				   checksum_data->length,
				   &fxreq.u.armored_data.req_checksum);
	if (ret)
	    goto out;

	ret = krb5_encrypt_EncryptedData(context, state->armor_crypto,
					 KRB5_KU_FAST_ENC,
					 data.data,
					 data.length,
					 0,
					 &fxreq.u.armored_data.enc_fast_req);
	krb5_data_free(&data);
	if (ret)
	    goto out;

    } else {
	krb5_data_free(&data);
	heim_assert(false, "unknown FAST type, internal error");
    }

    ASN1_MALLOC_ENCODE(PA_FX_FAST_REQUEST, data.data, data.length, &fxreq, &size, ret);
    if (ret)
	goto out;
    heim_assert(data.length == size, "ASN.1 internal error");


    ret = krb5_padata_add(context, req->padata, KRB5_PADATA_FX_FAST, data.data, data.length);
    if (ret)
	goto out;
    krb5_data_zero(&data);

    if (readd_padata_to_outer) {
	size_t i;

	for (i = 0; i < fastreq.padata.len; i++) {
	    PA_DATA *val = &fastreq.padata.val[i];

	    ret = krb5_padata_add(context,
				  req->padata,
				  val->padata_type,
				  val->padata_value.data,
				  val->padata_value.length);
	    if (ret) {
		krb5_set_error_message(context, ret,
				       N_("malloc: out of memory", ""));
		goto out;
	    }
	    val->padata_value.data = NULL;
	    val->padata_value.length = 0;
	}
    }

 out:
    free_KrbFastReq(&fastreq);
    free_PA_FX_FAST_REQUEST(&fxreq);
    krb5_data_free(&data);
    krb5_data_free(&aschecksum_data);

    return ret;
}

krb5_error_code
_krb5_fast_unwrap_error(krb5_context context,
			int32_t nonce,
			struct krb5_fast_state *state,
			METHOD_DATA *md,
			KRB_ERROR *error)
{
    KrbFastResponse fastrep;
    krb5_error_code ret;
    PA_DATA *pa;
    int idx;

    if (state->armor_crypto == NULL)
	return check_fast(context, state);

    memset(&fastrep, 0, sizeof(fastrep));

    idx = 0;
    pa = krb5_find_padata(md->val, md->len, KRB5_PADATA_FX_FAST, &idx);
    if (pa == NULL) {
	/*
	 * Typically _krb5_fast_wrap_req() has set KRB5_FAST_EXPECTED, which
	 * means check_fast() will complain and return KRB5KRB_AP_ERR_MODIFIED.
	 *
	 * But for TGS-REP init_tgs_req() clears KRB5_FAST_EXPECTED and we'll
	 * ignore a missing KRB5_PADATA_FX_FAST.
	 */
	return check_fast(context, state);
    }

    ret = unwrap_fast_rep(context, state, pa, &fastrep);
    if (ret)
	goto out;

    if (fastrep.strengthen_key || nonce != (int32_t)fastrep.nonce) {
	ret = KRB5KDC_ERR_PREAUTH_FAILED;
	goto out;
    }

    idx = 0;
    pa = krb5_find_padata(fastrep.padata.val, fastrep.padata.len, KRB5_PADATA_FX_ERROR, &idx);
    if (pa == NULL) {
	ret = KRB5_KDCREP_MODIFIED;
	krb5_set_error_message(context, ret, N_("No wrapped error", ""));
	goto out;
    }

    free_KRB_ERROR(error);

    ret = krb5_rd_error(context, &pa->padata_value, error);
    if (ret)
	goto out;

    if (error->e_data)
	_krb5_debug(context, 10, "FAST wrapped KBB_ERROR contained e_data: %d",
		     (int)error->e_data->length);

    free_METHOD_DATA(md);
    md->val = fastrep.padata.val;
    md->len = fastrep.padata.len;

    fastrep.padata.val = NULL;
    fastrep.padata.len = 0;

 out:
    free_KrbFastResponse(&fastrep);
    return ret;
}

krb5_error_code
_krb5_fast_unwrap_kdc_rep(krb5_context context, int32_t nonce,
			  krb5_data *chksumdata,
			  struct krb5_fast_state *state, AS_REP *rep)
{
    KrbFastResponse fastrep;
    krb5_error_code ret;
    PA_DATA *pa = NULL;
    int idx = 0;

    if (state == NULL || state->armor_crypto == NULL || rep->padata == NULL)
	return check_fast(context, state);

    /* find PA_FX_FAST_REPLY */

    pa = krb5_find_padata(rep->padata->val, rep->padata->len,
			  KRB5_PADATA_FX_FAST, &idx);
    if (pa == NULL)
	return check_fast(context, state);

    memset(&fastrep, 0, sizeof(fastrep));

    ret = unwrap_fast_rep(context, state, pa, &fastrep);
    if (ret)
	goto out;

    free_METHOD_DATA(rep->padata);
    ret = copy_METHOD_DATA(&fastrep.padata, rep->padata);
    if (ret)
	goto out;

    if (fastrep.strengthen_key) {
	if (state->strengthen_key)
	    krb5_free_keyblock(context, state->strengthen_key);

	ret = krb5_copy_keyblock(context, fastrep.strengthen_key, &state->strengthen_key);
	if (ret)
	    goto out;
    }

    if (nonce != (int32_t)fastrep.nonce) {
	ret = KRB5KDC_ERR_PREAUTH_FAILED;
	goto out;
    }
    if (fastrep.finished) {
	PrincipalName cname;
	krb5_realm crealm = NULL;

	if (chksumdata == NULL) {
	    ret = KRB5KDC_ERR_PREAUTH_FAILED;
	    goto out;
	}

	ret = krb5_verify_checksum(context, state->armor_crypto,
				   KRB5_KU_FAST_FINISHED,
				   chksumdata->data, chksumdata->length,
				   &fastrep.finished->ticket_checksum);
	if (ret)
	    goto out;

	/* update */
	ret = copy_Realm(&fastrep.finished->crealm, &crealm);
	if (ret)
	    goto out;
	free_Realm(&rep->crealm);
	rep->crealm = crealm;

	ret = copy_PrincipalName(&fastrep.finished->cname, &cname);
	if (ret)
	    goto out;
	free_PrincipalName(&rep->cname);
	rep->cname = cname;
    } else if (chksumdata) {
	/* expected fastrep.finish but didn't get it */
	ret = KRB5KDC_ERR_PREAUTH_FAILED;
    }

 out:
    free_KrbFastResponse(&fastrep);
    return ret;
}

void
_krb5_fast_free(krb5_context context, struct krb5_fast_state *state)
{
    if (state->armor_ccache) {
	if (state->flags & KRB5_FAST_ANON_PKINIT_ARMOR)
	    krb5_cc_destroy(context, state->armor_ccache);
	else
	    krb5_cc_close(context, state->armor_ccache);
    }
    if (state->armor_service)
	krb5_free_principal(context, state->armor_service);
    if (state->armor_crypto)
	krb5_crypto_destroy(context, state->armor_crypto);
    if (state->strengthen_key)
	krb5_free_keyblock(context, state->strengthen_key);
    krb5_free_keyblock_contents(context, &state->armor_key);
    if (state->armor_data) {
	free_KrbFastArmor(state->armor_data);
	free(state->armor_data);
    }

    if (state->anon_pkinit_ctx)
	krb5_init_creds_free(context, state->anon_pkinit_ctx);
    if (state->anon_pkinit_opt)
	krb5_get_init_creds_opt_free(context, state->anon_pkinit_opt);

    memset(state, 0, sizeof(*state));
}

krb5_error_code
_krb5_fast_anon_pkinit_step(krb5_context context,
			    krb5_init_creds_context ctx,
			    struct krb5_fast_state *state,
			    const krb5_data *in,
			    krb5_data *out,
			    krb5_realm *out_realm,
			    unsigned int *flags)
{
    krb5_error_code ret;
    krb5_const_realm realm = _krb5_init_creds_get_cred_client(context, ctx)->realm;
    krb5_init_creds_context anon_pk_ctx;
    krb5_principal principal = NULL, anon_pk_client;
    krb5_ccache ccache = NULL;
    krb5_creds cred;
    krb5_data data = { 3, rk_UNCONST("yes") };

    krb5_data_zero(out);
    *out_realm = NULL;

    memset(&cred, 0, sizeof(cred));

    if (state->anon_pkinit_opt == NULL) {
	ret = krb5_get_init_creds_opt_alloc(context, &state->anon_pkinit_opt);
	if (ret)
	    goto out;

	krb5_get_init_creds_opt_set_tkt_life(state->anon_pkinit_opt, 60);
	krb5_get_init_creds_opt_set_anonymous(state->anon_pkinit_opt, TRUE);

	ret = krb5_make_principal(context, &principal, realm,
				  KRB5_WELLKNOWN_NAME, KRB5_ANON_NAME, NULL);
	if (ret)
	    goto out;

	ret = krb5_get_init_creds_opt_set_pkinit(context,
						 state->anon_pkinit_opt,
						 principal,
						 NULL, NULL, NULL, NULL,
						 KRB5_GIC_OPT_PKINIT_ANONYMOUS |
						 KRB5_GIC_OPT_PKINIT_NO_KDC_ANCHOR,
						 NULL, NULL, NULL);
	if (ret)
	    goto out;

	ret = krb5_init_creds_init(context, principal, NULL, NULL,
				   _krb5_init_creds_get_cred_starttime(context, ctx),
				   state->anon_pkinit_opt,
				   &state->anon_pkinit_ctx);
	if (ret)
	    goto out;
    }

    anon_pk_ctx = state->anon_pkinit_ctx;

    ret = krb5_init_creds_step(context, anon_pk_ctx, in, out, out_realm, flags);
    if (ret ||
	(*flags & KRB5_INIT_CREDS_STEP_FLAG_CONTINUE))
	goto out;

    ret = krb5_process_last_request(context, state->anon_pkinit_opt, anon_pk_ctx);
    if (ret)
	goto out;

    ret = krb5_cc_new_unique(context, "MEMORY", NULL, &ccache);
    if (ret)
	goto out;

    ret = krb5_init_creds_get_creds(context, anon_pk_ctx, &cred);
    if (ret)
	goto out;

    if (!cred.flags.b.enc_pa_rep) {
	ret = KRB5KDC_ERR_BADOPTION; /* KDC does not support FAST */
	goto out;
    }

    anon_pk_client = _krb5_init_creds_get_cred_client(context, anon_pk_ctx);

    ret = krb5_cc_initialize(context, ccache, anon_pk_client);
    if (ret)
	goto out;

    ret = krb5_cc_store_cred(context, ccache, &cred);
    if (ret)
	goto out;

    ret = krb5_cc_set_config(context, ccache, cred.server,
			     "fast_avail", &data);
    if (ret && ret != KRB5_CC_NOSUPP)
	return ret;

    if (_krb5_pk_is_kdc_verified(context, state->anon_pkinit_opt))
	state->flags |= KRB5_FAST_KDC_VERIFIED;
    else
	state->flags &= ~(KRB5_FAST_KDC_VERIFIED);

    state->armor_ccache = ccache;
    ccache = NULL;

    krb5_init_creds_free(context, state->anon_pkinit_ctx);
    state->anon_pkinit_ctx = NULL;

    krb5_get_init_creds_opt_free(context, state->anon_pkinit_opt);
    state->anon_pkinit_opt = NULL;

out:
    krb5_free_principal(context, principal);
    krb5_free_cred_contents(context, &cred);
    if (ccache)
	krb5_cc_destroy(context, ccache);

    return ret;
}
