/*
 * Copyright (c) 1997 - 2008 Kungliga Tekniska Högskolan
 * (Royal Institute of Technology, Stockholm, Sweden).
 * All rights reserved.
 *
 * Portions Copyright (c) 2009 - 2010 Apple Inc. All rights reserved.
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
#include <assert.h>

static krb5_error_code
get_cred_kdc_capath(krb5_context, krb5_kdc_flags,
		    krb5_ccache, struct krb5_fast_state *,
		    krb5_creds *, krb5_principal,
		    Ticket *, const char *, const char *,
		    krb5_creds **, krb5_creds ***);

/*
 * Take the `body' and encode it into `padata' using the credentials
 * in `creds'.
 */

static krb5_error_code
make_pa_tgs_req(krb5_context context,
		krb5_auth_context *ac,
		KDC_REQ_BODY *body,
		krb5_ccache ccache,
		krb5_creds *creds,
		krb5_data *tgs_req)
{
    krb5_error_code ret;
    krb5_data in_data;
    size_t buf_size;
    size_t len = 0;
    uint8_t *buf;

    ASN1_MALLOC_ENCODE(KDC_REQ_BODY, buf, buf_size, body, &len, ret);
    if (ret)
	return ret;

    if(buf_size != len)
	krb5_abortx(context, "internal error in ASN.1 encoder");

    in_data.length = len;
    in_data.data   = buf;
    ret = _krb5_mk_req_internal(context, ac, 0, &in_data,
				creds, tgs_req,
				KRB5_KU_TGS_REQ_AUTH_CKSUM,
				KRB5_KU_TGS_REQ_AUTH);
    free (buf);
    return ret;
}

/*
 * Set the `enc-authorization-data' in `req_body' based on `authdata'
 */

static krb5_error_code
set_auth_data (krb5_context context,
	       KDC_REQ_BODY *req_body,
	       krb5_authdata *authdata,
	       krb5_keyblock *subkey)
{
    if(authdata->len) {
	size_t len = 0, buf_size;
	unsigned char *buf;
	krb5_crypto crypto;
	krb5_error_code ret;

	ASN1_MALLOC_ENCODE(AuthorizationData, buf, buf_size, authdata,
			   &len, ret);
	if (ret)
	    return ret;
	if (buf_size != len)
	    krb5_abortx(context, "internal error in ASN.1 encoder");

	ALLOC(req_body->enc_authorization_data, 1);
	if (req_body->enc_authorization_data == NULL) {
	    free (buf);
	    return krb5_enomem(context);
	}
	ret = krb5_crypto_init(context, subkey, 0, &crypto);
	if (ret) {
	    free (buf);
	    free (req_body->enc_authorization_data);
	    req_body->enc_authorization_data = NULL;
	    return ret;
	}
        ret = krb5_encrypt_EncryptedData(context,
                                         crypto,
                                         KRB5_KU_TGS_REQ_AUTH_DAT_SUBKEY,
                                         buf,
                                         len,
                                         0,
                                         req_body->enc_authorization_data);
	free (buf);
	krb5_crypto_destroy(context, crypto);
        return ret;
    } else {
	req_body->enc_authorization_data = NULL;
        return 0;
    }
}

/*
 * Create a tgs-req in `t' with `addresses', `flags', `second_ticket'
 * (if not-NULL), `in_creds', `krbtgt', and returning the generated
 * subkey in `subkey'.
 */

static krb5_error_code
init_tgs_req (krb5_context context,
	      krb5_ccache ccache,
	      struct krb5_fast_state *state,
	      krb5_addresses *addresses,
	      krb5_kdc_flags flags,
	      Ticket *second_ticket,
	      krb5_creds *in_creds,
	      krb5_creds *krbtgt,
	      unsigned nonce,
	      const METHOD_DATA *padata,
	      krb5_keyblock **subkey,
	      TGS_REQ *t)
{
    krb5_auth_context ac = NULL;
    krb5_error_code ret = 0;
    krb5_data tgs_req;

    krb5_data_zero(&tgs_req);
    memset(t, 0, sizeof(*t));

    t->pvno = 5;
    t->msg_type = krb_tgs_req;
    if (in_creds->session.keytype) {
	ALLOC_SEQ(&t->req_body.etype, 1);
	if(t->req_body.etype.val == NULL) {
	    ret = krb5_enomem(context);
	    goto fail;
	}
	t->req_body.etype.val[0] = in_creds->session.keytype;
    } else {
	ret = _krb5_init_etype(context,
			       KRB5_PDU_TGS_REQUEST,
			       &t->req_body.etype.len,
			       &t->req_body.etype.val,
			       NULL);
    }
    if (ret)
	goto fail;
    t->req_body.addresses = addresses;
    t->req_body.kdc_options = flags.b;
    t->req_body.kdc_options.forwardable = krbtgt->flags.b.forwardable;
    t->req_body.kdc_options.renewable = krbtgt->flags.b.renewable;
    t->req_body.kdc_options.proxiable = krbtgt->flags.b.proxiable;
    ret = copy_Realm(&in_creds->server->realm, &t->req_body.realm);
    if (ret)
	goto fail;
    ALLOC(t->req_body.sname, 1);
    if (t->req_body.sname == NULL) {
	ret = krb5_enomem(context);
	goto fail;
    }

    /* some versions of some code might require that the client be
       present in TGS-REQs, but this is clearly against the spec */

    ret = copy_PrincipalName(&in_creds->server->name, t->req_body.sname);
    if (ret)
	goto fail;

    if (krbtgt->times.starttime) {
        ALLOC(t->req_body.from, 1);
        if(t->req_body.from == NULL){
            ret = krb5_enomem(context);
            goto fail;
        }
        *t->req_body.from = in_creds->times.starttime;
    }

    /* req_body.till should be NULL if there is no endtime specified,
       but old MIT code (like DCE secd) doesn't like that */
    ALLOC(t->req_body.till, 1);
    if(t->req_body.till == NULL){
	ret = krb5_enomem(context);
	goto fail;
    }
    *t->req_body.till = in_creds->times.endtime;

    if (t->req_body.kdc_options.renewable && krbtgt->times.renew_till) {
        ALLOC(t->req_body.rtime, 1);
        if(t->req_body.rtime == NULL){
            ret = krb5_enomem(context);
            goto fail;
        }
        *t->req_body.rtime = in_creds->times.renew_till;
    }

    t->req_body.nonce = nonce;
    if(second_ticket){
	ALLOC(t->req_body.additional_tickets, 1);
	if (t->req_body.additional_tickets == NULL) {
	    ret = krb5_enomem(context);
	    goto fail;
	}
	ALLOC_SEQ(t->req_body.additional_tickets, 1);
	if (t->req_body.additional_tickets->val == NULL) {
	    ret = krb5_enomem(context);
	    goto fail;
	}
	ret = copy_Ticket(second_ticket, t->req_body.additional_tickets->val);
	if (ret)
	    goto fail;
    }

    ret = krb5_auth_con_init(context, &ac);
    if(ret)
	goto fail;

    ret = krb5_auth_con_generatelocalsubkey(context, ac, &krbtgt->session);
    if (ret)
	goto fail;

    if (state) {
	krb5_data empty;

	krb5_data_zero(&empty);
	ret = krb5_auth_con_add_AuthorizationData(context, ac,
						  KRB5_AUTHDATA_FX_FAST_USED,
						   &empty);
	if (ret)
	    goto fail;
    }

    ret = set_auth_data(context, &t->req_body,
			&in_creds->authdata, ac->local_subkey);
    if (ret)
	goto fail;

    ret = make_pa_tgs_req(context,
			  &ac,
			  &t->req_body,
			  ccache,
			  krbtgt,
			  &tgs_req);
    if(ret)
	goto fail;

    /*
     * Add KRB5_PADATA_TGS_REQ first
     * followed by all others.
     */

    if (t->padata == NULL) {
	ALLOC(t->padata, 1);
	if (t->padata == NULL) {
	    ret = krb5_enomem(context);
	    goto fail;
	}
    }

    ret = krb5_padata_add(context, t->padata, KRB5_PADATA_TGS_REQ,
			  tgs_req.data, tgs_req.length);
    if (ret)
	goto fail;

    krb5_data_zero(&tgs_req);

    {
	size_t i;
	for (i = 0; i < padata->len; i++) {
	    const PA_DATA *val1 = &padata->val[i];
	    PA_DATA val2;

	    ret = copy_PA_DATA(val1, &val2);
	    if (ret) {
		krb5_set_error_message(context, ret,
				       N_("malloc: out of memory", ""));
		goto fail;
	    }

	    ret = krb5_padata_add(context, t->padata,
				  val2.padata_type,
				  val2.padata_value.data,
				  val2.padata_value.length);
	    if (ret) {
		free_PA_DATA(&val2);

		krb5_set_error_message(context, ret,
				       N_("malloc: out of memory", ""));
		goto fail;
	    }
	}
    }

    if (state) {
	state->armor_ac = ac;
	ret = _krb5_fast_create_armor(context, state, NULL);
	state->armor_ac = NULL;
	if (ret)
	    goto fail;

	ret = _krb5_fast_wrap_req(context, state, t);
	if (ret)
	    goto fail;

	/* Its ok if there is no fast in the TGS-REP, older heimdal only support it in the AS code path */
	state->flags &= ~KRB5_FAST_EXPECTED;
    }

    ret = krb5_auth_con_getlocalsubkey(context, ac, subkey);
    if (ret)
	goto fail;

fail:
    if (ac)
	krb5_auth_con_free(context, ac);
    if (ret) {
	t->req_body.addresses = NULL;
	free_TGS_REQ (t);
    }
    krb5_data_free(&tgs_req);

    return ret;
}

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
_krb5_get_krbtgt(krb5_context context,
		 krb5_ccache  id,
		 krb5_realm realm,
		 krb5_creds **cred)
{
    krb5_error_code ret;
    krb5_creds tmp_cred;

    memset(&tmp_cred, 0, sizeof(tmp_cred));

    ret = krb5_cc_get_principal(context, id, &tmp_cred.client);
    if (ret)
	return ret;

    if (realm == NULL)
	realm = tmp_cred.client->realm;

    ret = krb5_make_principal(context,
			      &tmp_cred.server,
			      realm,
			      KRB5_TGS_NAME,
			      realm,
			      NULL);
    if(ret) {
	krb5_free_principal(context, tmp_cred.client);
	return ret;
    }
    /*
     * The forwardable TGT might not be the start TGT, in which case, it is
     * generally, but not always already cached.  Just in case, get it again if
     * lost.
     */
    ret = krb5_get_credentials(context,
			       0,
			       id,
			       &tmp_cred,
			       cred);
    krb5_free_principal(context, tmp_cred.client);
    krb5_free_principal(context, tmp_cred.server);
    if(ret)
	return ret;
    return 0;
}

static krb5_error_code
fast_tgs_strengthen_key(krb5_context context,
			struct krb5_fast_state *state,
			krb5_keyblock *reply_key,
			krb5_keyblock *extract_key)
{
    krb5_error_code ret;

    if (state && state->strengthen_key) {
	_krb5_debug(context, 5, "_krb5_fast_tgs_strengthen_key");
	
	if (state->strengthen_key->keytype != reply_key->keytype) {
	    krb5_set_error_message(context, KRB5KRB_AP_ERR_MODIFIED,
				   N_("strengthen_key %d not same enctype as reply key %d", ""),
				   state->strengthen_key->keytype, reply_key->keytype);
	    return KRB5KRB_AP_ERR_MODIFIED;
	}

	ret = _krb5_fast_cf2(context,
			     state->strengthen_key,
			     "strengthenkey",
			     reply_key,
			     "replykey",
			     extract_key,
			     NULL);
	if (ret)
	    return ret;
    } else {
	ret = krb5_copy_keyblock_contents(context, reply_key, extract_key);
	if (ret)
	    return ret;
    }

    return 0;
}

/* DCE compatible decrypt proc */
static krb5_error_code KRB5_CALLCONV
decrypt_tkt_with_subkey (krb5_context context,
			 krb5_keyblock *key,
			 krb5_key_usage usage,
			 krb5_const_pointer skey,
			 krb5_kdc_rep *dec_rep)
{
    struct krb5_decrypt_tkt_with_subkey_state *state;
    krb5_error_code ret = 0;
    krb5_data data;
    size_t size;
    krb5_crypto crypto;
    krb5_keyblock extract_key;

    state = (struct krb5_decrypt_tkt_with_subkey_state *)skey;

    assert(usage == 0);

    krb5_data_zero(&data);

    /*
     * start out with trying with subkey if we have one
     */
    if (state->subkey) {
	ret = fast_tgs_strengthen_key(context, state->fast_state,
				      state->subkey, &extract_key);
	if (ret)
	    return ret;

	ret = krb5_crypto_init(context, &extract_key, 0, &crypto);
	krb5_free_keyblock_contents(context, &extract_key);
	if (ret)
	    return ret;
	ret = krb5_decrypt_EncryptedData (context,
					  crypto,
					  KRB5_KU_TGS_REP_ENC_PART_SUB_KEY,
					  &dec_rep->kdc_rep.enc_part,
					  &data);
	/*
	 * If the is Windows 2000 DC, we need to retry with key usage
	 * 8 when doing ARCFOUR.
	 */
	if (ret && state->subkey->keytype == ETYPE_ARCFOUR_HMAC_MD5) {
	    ret = krb5_decrypt_EncryptedData(context,
					     crypto,
					     8,
					     &dec_rep->kdc_rep.enc_part,
					     &data);
	}
	krb5_crypto_destroy(context, crypto);
    }
    if (state->subkey == NULL || ret) {
	ret = fast_tgs_strengthen_key(context, state->fast_state, key, &extract_key);
	if (ret)
	    return ret;

	ret = krb5_crypto_init(context, key, 0, &crypto);
	if (ret)
	    return ret;
	ret = krb5_decrypt_EncryptedData (context,
					  crypto,
					  KRB5_KU_TGS_REP_ENC_PART_SESSION,
					  &dec_rep->kdc_rep.enc_part,
					  &data);
	krb5_crypto_destroy(context, crypto);
    }
    if (ret)
	return ret;

    ret = decode_EncASRepPart(data.data,
			      data.length,
			      &dec_rep->enc_part,
			      &size);
    if (ret)
	ret = decode_EncTGSRepPart(data.data,
				   data.length,
				   &dec_rep->enc_part,
				   &size);
    if (ret)
      krb5_set_error_message(context, ret,
			     N_("Failed to decode encpart in ticket", ""));
    krb5_data_free (&data);
    return ret;
}

static krb5_error_code
get_cred_kdc(krb5_context context,
	     krb5_ccache id,
	     struct krb5_fast_state *fast_state,
	     krb5_kdc_flags flags,
	     krb5_addresses *addresses,
	     krb5_creds *in_creds,
	     krb5_creds *krbtgt,
	     krb5_principal impersonate_principal,
	     Ticket *second_ticket,
	     const char *kdc_hostname,
	     const char *sitename,
	     krb5_creds *out_creds)
{
    TGS_REQ req;
    krb5_data enc;
    krb5_data resp;
    krb5_kdc_rep rep;
    krb5_error_code ret;
    unsigned nonce;
    krb5_keyblock *subkey = NULL;
    size_t len = 0;
    Ticket second_ticket_data;
    METHOD_DATA padata;

    memset(&rep, 0, sizeof(rep));
    krb5_data_zero(&resp);
    krb5_data_zero(&enc);
    padata.val = NULL;
    padata.len = 0;

    krb5_generate_random_block(&nonce, sizeof(nonce));
    nonce &= 0xffffffff;

    if(flags.b.enc_tkt_in_skey && second_ticket == NULL){
	ret = decode_Ticket(in_creds->second_ticket.data,
			    in_creds->second_ticket.length,
			    &second_ticket_data, &len);
	if(ret)
	    return ret;
	second_ticket = &second_ticket_data;
    }


    if (impersonate_principal) {
	krb5_crypto crypto;
	PA_S4U2Self self;
	krb5_data data;
	void *buf;
	size_t size = 0;

	self.name = impersonate_principal->name;
	self.realm = impersonate_principal->realm;
	self.auth = estrdup("Kerberos");

	ret = _krb5_s4u2self_to_checksumdata(context, &self, &data);
	if (ret) {
	    free(self.auth);
	    goto out;
	}

	ret = krb5_crypto_init(context, &krbtgt->session, 0, &crypto);
	if (ret) {
	    free(self.auth);
	    krb5_data_free(&data);
	    goto out;
	}

	ret = krb5_create_checksum(context,
				   crypto,
				   KRB5_KU_OTHER_CKSUM,
				   0,
				   data.data,
				   data.length,
				   &self.cksum);
	krb5_crypto_destroy(context, crypto);
	krb5_data_free(&data);
	if (ret) {
	    free(self.auth);
	    goto out;
	}

	ASN1_MALLOC_ENCODE(PA_S4U2Self, buf, len, &self, &size, ret);
	free(self.auth);
	free_Checksum(&self.cksum);
	if (ret)
	    goto out;
	if (len != size)
	    krb5_abortx(context, "internal asn1 error");

	ret = krb5_padata_add(context, &padata, KRB5_PADATA_FOR_USER, buf, len);
	if (ret)
	    goto out;
    }

    ret = init_tgs_req (context,
			id,
			fast_state,
			addresses,
			flags,
			second_ticket,
			in_creds,
			krbtgt,
			nonce,
			&padata,
			&subkey,
			&req);
    if (ret)
	goto out;

    ASN1_MALLOC_ENCODE(TGS_REQ, enc.data, enc.length, &req, &len, ret);
    if (ret)
	goto out;
    if(enc.length != len)
	krb5_abortx(context, "internal error in ASN.1 encoder");

    /* don't free addresses */
    req.req_body.addresses = NULL;
    free_TGS_REQ(&req);

    /*
     * Send and receive
     */
    {
	krb5_sendto_ctx stctx;
	ret = krb5_sendto_ctx_alloc(context, &stctx);
	if (ret)
	    return ret;
	krb5_sendto_ctx_set_func(stctx, _krb5_kdc_retry, NULL);

	if (kdc_hostname)
	    krb5_sendto_set_hostname(context, stctx, kdc_hostname);
	if (sitename)
	    krb5_sendto_set_sitename(context, stctx, sitename);

	ret = krb5_sendto_context (context, stctx, &enc,
				   krbtgt->server->name.name_string.val[1],
				   &resp);
	krb5_sendto_ctx_free(context, stctx);
    }
    if(ret)
	goto out;

    if(decode_TGS_REP(resp.data, resp.length, &rep.kdc_rep, &len) == 0) {
	struct krb5_decrypt_tkt_with_subkey_state state;
	unsigned eflags = 0;
	krb5_data data;
	size_t size;

	ASN1_MALLOC_ENCODE(Ticket, data.data, data.length,
			   &rep.kdc_rep.ticket, &size, ret);
	if (ret)
	    goto out;
	heim_assert(data.length == size, "ASN.1 internal error");

	ret = _krb5_fast_unwrap_kdc_rep(context, nonce, &data,
					fast_state, &rep.kdc_rep);
	krb5_data_free(&data);
	if (ret)
	    goto out;

	ret = krb5_copy_principal(context,
				  in_creds->client,
				  &out_creds->client);
	if(ret)
	    goto out;
	ret = krb5_copy_principal(context,
				  in_creds->server,
				  &out_creds->server);
	if(ret)
	    goto out;
	/* this should go someplace else */
	out_creds->times.endtime = in_creds->times.endtime;

	/* XXX should do better testing */
	if (flags.b.cname_in_addl_tkt || impersonate_principal)
	    eflags |= EXTRACT_TICKET_ALLOW_CNAME_MISMATCH;
	if (flags.b.request_anonymous)
	    eflags |= EXTRACT_TICKET_MATCH_ANON;

	state.subkey = subkey;
	state.fast_state = fast_state;

	ret = _krb5_extract_ticket(context,
				   &rep,
				   out_creds,
				   &krbtgt->session,
				   NULL,
				   0,
				   &krbtgt->addresses,
				   nonce,
				   eflags,
				   NULL,
				   decrypt_tkt_with_subkey,
				   &state);
    } else if(krb5_rd_error(context, &resp, &rep.error) == 0) {
	METHOD_DATA md;

	memset(&md, 0, sizeof(md));

	if (rep.error.e_data) {
	    KERB_ERROR_DATA error_data;

	    memset(&error_data, 0, sizeof(error_data));

	    /* First try to decode the e-data as KERB-ERROR-DATA. */
	    ret = decode_KERB_ERROR_DATA(rep.error.e_data->data,
					 rep.error.e_data->length,
					 &error_data,
					 &len);
	    if (ret) {
		/* That failed, so try to decode it as METHOD-DATA. */
		ret = decode_METHOD_DATA(rep.error.e_data->data,
					 rep.error.e_data->length,
					 &md, NULL);
		if (ret) {
		    krb5_set_error_message(context, ret,
					   N_("Failed to decode METHOD-DATA", ""));
		    goto out;
		}
	    } else if (len != rep.error.e_data->length) {
		/* Trailing data — just ignore the error. */
		free_KERB_ERROR_DATA(&error_data);
	    } else {
		/* OK. */
		free_KERB_ERROR_DATA(&error_data);
	    }
	}

	ret = _krb5_fast_unwrap_error(context, nonce, fast_state, &md, &rep.error);
	free_METHOD_DATA(&md);
	if (ret)
	    goto out;

	ret = krb5_error_from_rd_error(context, &rep.error, in_creds);

	/* log the failure */
	if (_krb5_have_debug(context, 5)) {
	    const char *str = krb5_get_error_message(context, ret);
	    _krb5_debug(context, 5, "parse_tgs_rep: KRB-ERROR %d/%s", ret, str);
	    krb5_free_error_message(context, str);
	}
    } else if(resp.length > 0 && ((char*)resp.data)[0] == 4) {
	ret = KRB5KRB_AP_ERR_V4_REPLY;
	krb5_clear_error_message(context);
    } else {
	ret = KRB5KRB_AP_ERR_MSG_TYPE;
	krb5_clear_error_message(context);
    }

out:
    krb5_free_kdc_rep(context, &rep);
    if (second_ticket == &second_ticket_data)
	free_Ticket(&second_ticket_data);
    free_METHOD_DATA(&padata);
    krb5_data_free(&resp);
    krb5_data_free(&enc);
    if(subkey)
	krb5_free_keyblock(context, subkey);
    return ret;

}

/*
 * same as above, just get local addresses first if the krbtgt have
 * them and the realm is not addressless
 */

static krb5_error_code
get_cred_kdc_address(krb5_context context,
		     krb5_ccache id,
		     struct krb5_fast_state *fast_state,
		     krb5_kdc_flags flags,
		     krb5_addresses *addrs,
		     krb5_creds *in_creds,
		     krb5_creds *krbtgt,
		     krb5_principal impersonate_principal,
		     Ticket *second_ticket,
		     const char *kdc_hostname,
		     const char *sitename,
		     krb5_creds *out_creds)
{
    krb5_error_code ret;
    krb5_addresses addresses = { 0, NULL };

    /*
     * Inherit the address-ness of the krbtgt if the address is not
     * specified.
     */

    if (addrs == NULL && krbtgt->addresses.len != 0) {
	krb5_boolean noaddr;

	krb5_appdefault_boolean(context, NULL, krbtgt->server->realm,
				"no-addresses", FALSE, &noaddr);

	if (!noaddr) {
	    ret = krb5_get_all_client_addrs(context, &addresses);
            if (ret)
                return ret;
	    /* XXX this sucks. */
	    addrs = &addresses;
	    if(addresses.len == 0)
		addrs = NULL;
	}
    }
    ret = get_cred_kdc(context, id, fast_state, flags, addrs,
		       in_creds, krbtgt, impersonate_principal,
		       second_ticket, kdc_hostname, sitename, out_creds);
    krb5_free_addresses(context, &addresses);
    return ret;
}

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_get_kdc_cred(krb5_context context,
		  krb5_ccache id,
		  krb5_kdc_flags flags,
		  krb5_addresses *addresses,
		  Ticket  *second_ticket,
		  krb5_creds *in_creds,
		  krb5_creds **out_creds
		  )
{
    krb5_error_code ret;
    krb5_creds *krbtgt;
    struct krb5_fast_state fast_state;

    memset(&fast_state, 0, sizeof(fast_state));

    *out_creds = calloc(1, sizeof(**out_creds));
    if(*out_creds == NULL)
	return krb5_enomem(context);
    ret = _krb5_get_krbtgt (context,
			    id,
			    in_creds->server->realm,
			    &krbtgt);
    if(ret) {
	free(*out_creds);
	*out_creds = NULL;
	return ret;
    }
    ret = get_cred_kdc(context, id, &fast_state, flags,
		       addresses, in_creds, krbtgt,
		       NULL, NULL, NULL, NULL, *out_creds);
    krb5_free_creds (context, krbtgt);
    _krb5_fast_free(context, &fast_state);
    if(ret) {
	free(*out_creds);
	*out_creds = NULL;
    }
    return ret;
}

static int
not_found(krb5_context context, krb5_const_principal p, krb5_error_code code)
{
    krb5_error_code ret;
    char *str;
    const char *err;

    ret = krb5_unparse_name(context, p, &str);
    if(ret) {
	krb5_clear_error_message(context);
	return code;
    }
    err = krb5_get_error_message(context, code);
    krb5_set_error_message(context, code, N_("%s (%s)", ""), err, str);
    krb5_free_error_message(context, err);
    free(str);
    return code;
}

static krb5_error_code
find_cred(krb5_context context,
	  krb5_ccache id,
	  krb5_principal server,
	  krb5_creds **tgts,
	  krb5_creds *out_creds)
{
    krb5_error_code ret;
    krb5_creds mcreds;

    krb5_cc_clear_mcred(&mcreds);
    mcreds.server = server;
    krb5_timeofday(context, &mcreds.times.endtime);
    ret = krb5_cc_retrieve_cred(context, id,
				KRB5_TC_DONT_MATCH_REALM |
				KRB5_TC_MATCH_TIMES,
				&mcreds, out_creds);
    if(ret == 0)
	return 0;
    while(tgts && *tgts){
	if(krb5_compare_creds(context, KRB5_TC_DONT_MATCH_REALM,
			      &mcreds, *tgts)){
	    ret = krb5_copy_creds_contents(context, *tgts, out_creds);
	    return ret;
	}
	tgts++;
    }
    return not_found(context, server, KRB5_CC_NOTFOUND);
}

static krb5_error_code
add_cred(krb5_context context, krb5_creds const *tkt, krb5_creds ***tgts)
{
    int i;
    krb5_error_code ret;
    krb5_creds **tmp = *tgts;

    for(i = 0; tmp && tmp[i]; i++); /* XXX */
    tmp = realloc(tmp, (i+2)*sizeof(*tmp));
    if(tmp == NULL)
	return krb5_enomem(context);
    *tgts = tmp;
    ret = krb5_copy_creds(context, tkt, &tmp[i]);
    tmp[i+1] = NULL;
    return ret;
}

static krb5_error_code
get_cred_kdc_capath_worker(krb5_context context,
                           krb5_kdc_flags flags,
                           krb5_ccache ccache,
			   struct krb5_fast_state *fast_state,
                           krb5_creds *in_creds,
                           krb5_const_realm try_realm,
                           krb5_principal impersonate_principal,
                           Ticket *second_ticket,
			   const char *kdc_hostname,
			   const char *sitename,
                           krb5_creds **out_creds,
                           krb5_creds ***ret_tgts)
{
    krb5_error_code ret;
    krb5_creds *tgt = NULL;
    krb5_creds tmp_creds;
    krb5_const_realm client_realm, server_realm;
    int ok_as_delegate = 1;

    *out_creds = calloc(1, sizeof(**out_creds));
    if (*out_creds == NULL)
	return krb5_enomem(context);

    memset(&tmp_creds, 0, sizeof(tmp_creds));

    client_realm = krb5_principal_get_realm(context, in_creds->client);
    server_realm = krb5_principal_get_realm(context, in_creds->server);
    ret = krb5_copy_principal(context, in_creds->client, &tmp_creds.client);
    if (ret)
	goto out;

    ret = krb5_make_principal(context,
			      &tmp_creds.server,
			      try_realm,
			      KRB5_TGS_NAME,
			      server_realm,
			      NULL);
    if (ret)
	goto out;

    {
	krb5_creds tgts;

	/*
	 * If we have krbtgt/server_realm@try_realm cached, use it and we're
	 * done.
	 */
	ret = find_cred(context, ccache, tmp_creds.server,
			*ret_tgts, &tgts);
	if (ret == 0) {
	    /* only allow implicit ok_as_delegate if the realm is the clients realm */
	    if (strcmp(try_realm, client_realm) != 0
		 || strcmp(try_realm, server_realm) != 0) {
		ok_as_delegate = tgts.flags.b.ok_as_delegate;
	    }

	    ret = get_cred_kdc_address(context, ccache, fast_state,
				       flags, NULL,
				       in_creds, &tgts,
				       impersonate_principal,
				       second_ticket,
				       kdc_hostname,
				       sitename,
				       *out_creds);
            krb5_free_cred_contents(context, &tgts);
	    if (ret == 0 &&
                !krb5_principal_compare(context, in_creds->server,
                                        (*out_creds)->server)) {
		ret = KRB5KDC_ERR_S_PRINCIPAL_UNKNOWN;
	    }
	    if (ret == 0 && ok_as_delegate == 0)
		(*out_creds)->flags.b.ok_as_delegate = 0;

	    goto out;
	}
    }

    if (krb5_realm_compare(context, in_creds->client, in_creds->server)) {
	ret = not_found(context, in_creds->server, KRB5_CC_NOTFOUND);
	goto out;
    }

    /*
     * XXX This can loop forever, plus we recurse, so we can't just keep a
     * count here.  The count would have to get passed around by reference.
     *
     * The KDCs check for transit loops for us, and capath data is finite, so
     * in fact we'll fall out of this loop at some point.  We should do our own
     * transit loop checking (like get_cred_kdc_referral()), and we should
     * impose a max number of iterations altogether.  But barring malicious or
     * broken KDCs, this is good enough.
     */
    while (1) {
	heim_general_string tgt_inst;

	ret = get_cred_kdc_capath(context, flags, ccache, fast_state,
				  &tmp_creds, NULL, NULL,
				  kdc_hostname, sitename,
				  &tgt, ret_tgts);
	if (ret)
	    goto out;

	/*
	 * if either of the chain or the ok_as_delegate was stripped
	 * by the kdc, make sure we strip it too.
	 */
	if (ok_as_delegate == 0 || tgt->flags.b.ok_as_delegate == 0) {
	    ok_as_delegate = 0;
	    tgt->flags.b.ok_as_delegate = 0;
	}

	ret = add_cred(context, tgt, ret_tgts);
	if (ret)
	    goto out;
	tgt_inst = tgt->server->name.name_string.val[1];
	if (strcmp(tgt_inst, server_realm) == 0)
	    break;
	krb5_free_principal(context, tmp_creds.server);
	tmp_creds.server = NULL;
	ret = krb5_make_principal(context, &tmp_creds.server,
				  tgt_inst, KRB5_TGS_NAME, server_realm, NULL);
	if (ret)
	    goto out;
	ret = krb5_free_creds(context, tgt);
	tgt = NULL;
	if (ret)
	    goto out;
    }

    ret = get_cred_kdc_address(context, ccache, fast_state, flags, NULL,
			       in_creds, tgt, impersonate_principal,
			       second_ticket, kdc_hostname, sitename, *out_creds);
    if (ret == 0 &&
        !krb5_principal_compare(context, in_creds->server,
                                    (*out_creds)->server)) {
        krb5_free_cred_contents(context, *out_creds);
        ret = KRB5KDC_ERR_S_PRINCIPAL_UNKNOWN;
    }
    if (ret == 0 && ok_as_delegate == 0)
        (*out_creds)->flags.b.ok_as_delegate = 0;

out:
    if (ret) {
	krb5_free_creds(context, *out_creds);
        *out_creds = NULL;
    }
    if (tmp_creds.server)
	krb5_free_principal(context, tmp_creds.server);
    if (tmp_creds.client)
	krb5_free_principal(context, tmp_creds.client);
    if (tgt)
	krb5_free_creds(context, tgt);
    return ret;
}

/*
get_cred(server)
	creds = cc_get_cred(server)
	if(creds) return creds
	tgt = cc_get_cred(krbtgt/server_realm@any_realm)
	if(tgt)
		return get_cred_tgt(server, tgt)
	if(client_realm == server_realm)
		return NULL
	tgt = get_cred(krbtgt/server_realm@client_realm)
	while(tgt_inst != server_realm)
		tgt = get_cred(krbtgt/server_realm@tgt_inst)
	return get_cred_tgt(server, tgt)
	*/

static krb5_error_code
get_cred_kdc_capath(krb5_context context,
		    krb5_kdc_flags flags,
		    krb5_ccache ccache,
		    struct krb5_fast_state *fast_state,
		    krb5_creds *in_creds,
		    krb5_principal impersonate_principal,
		    Ticket *second_ticket,
		    const char *kdc_hostname,
		    const char *sitename,
		    krb5_creds **out_creds,
		    krb5_creds ***ret_tgts)
{
    krb5_error_code ret;
    krb5_const_realm client_realm, server_realm, try_realm;

    client_realm = krb5_principal_get_realm(context, in_creds->client);
    server_realm = krb5_principal_get_realm(context, in_creds->server);

    try_realm = client_realm;
    ret = get_cred_kdc_capath_worker(context, flags, ccache, fast_state,
				     in_creds, try_realm, impersonate_principal,
				     second_ticket, kdc_hostname, sitename,
				     out_creds, ret_tgts);

    if (ret == KRB5KDC_ERR_S_PRINCIPAL_UNKNOWN) {
        try_realm = krb5_config_get_string(context, NULL, "capaths",
                                           client_realm, server_realm, NULL);

        if (try_realm != NULL && strcmp(try_realm, client_realm) != 0) {
            ret = get_cred_kdc_capath_worker(context, flags, ccache, fast_state,
					     in_creds, try_realm, impersonate_principal,
                                             second_ticket, kdc_hostname, sitename,
					     out_creds, ret_tgts);
        }
    }

    return ret;
}

static krb5_boolean skip_referrals(krb5_principal server,
				   krb5_kdc_flags *flags)
{
    return server->name.name_string.len < 2 && !flags->b.canonicalize;
}

/*
 * Get a service ticket from a KDC by chasing referrals from a start realm.
 *
 * All referral TGTs produced in the process are thrown away when we're done.
 * We don't store them, and we don't allow other search mechanisms (capaths) to
 * use referral TGTs produced here.
 */
static krb5_error_code
get_cred_kdc_referral(krb5_context context,
		      krb5_kdc_flags flags,
		      krb5_ccache ccache,
		      struct krb5_fast_state *fast_state,
		      krb5_creds *in_creds,
		      krb5_principal impersonate_principal,
		      Ticket *second_ticket,
		      const char *kdc_hostname,
		      const char *sitename,
		      krb5_creds **out_creds)
{
    krb5_realm start_realm = NULL;
    krb5_data config_start_realm;
    krb5_error_code ret;
    krb5_creds tgt, referral, ticket;
    krb5_creds **referral_tgts = NULL;  /* used for loop detection */
    int loop = 0;
    int ok_as_delegate = 1;
    int want_tgt;
    size_t i;

    if (skip_referrals(in_creds->server, &flags)) {
	krb5_set_error_message(context, KRB5KDC_ERR_PATH_NOT_ACCEPTED,
			       N_("Name too short to do referals, skipping", ""));
	return KRB5KDC_ERR_PATH_NOT_ACCEPTED;
    }

    memset(&tgt, 0, sizeof(tgt));
    memset(&ticket, 0, sizeof(ticket));

    flags.b.canonicalize = 1;

    *out_creds = NULL;


    ret = krb5_cc_get_config(context, ccache, NULL, "start_realm", &config_start_realm);
    if (ret == 0) {
        start_realm = strndup(config_start_realm.data, config_start_realm.length);
	krb5_data_free(&config_start_realm);
    } else {
        start_realm = strdup(krb5_principal_get_realm(context, in_creds->client));
    }
    if (start_realm == NULL)
        return krb5_enomem(context);

    /* find tgt for the clients base realm */
    {
	krb5_principal tgtname;

	ret = krb5_make_principal(context, &tgtname,
				  start_realm,
				  KRB5_TGS_NAME,
				  start_realm,
				  NULL);
	if (ret) {
            free(start_realm);
	    return ret;
        }

	ret = find_cred(context, ccache, tgtname, NULL, &tgt);
	krb5_free_principal(context, tgtname);
	if (ret) {
            free(start_realm);
	    return ret;
        }
    }

    /*
     * If the desired service principal service/host@REALM is not a TGT, start
     * by asking for a ticket for service/host@START_REALM and process referrals
     * from there.
     *
     * However, when we ask for a TGT, krbtgt/A@B, we're actually looking for a
     * path to realm B, so that we can explicitly obtain a ticket for krbtgt/A
     * from B, and not some other realm.  Therefore, in this case our starting
     * point will be krbtgt/B@START_REALM.  Only once we obtain a ticket for
     * krbtgt/B@some-transit, do we switch to requesting krbtgt/A@B on our
     * final request.
     */
    referral = *in_creds;
    want_tgt = in_creds->server->realm[0] != '\0' &&
               krb5_principal_is_krbtgt(context, in_creds->server);
    if (!want_tgt)
        ret = krb5_copy_principal(context, in_creds->server, &referral.server);
    else
	ret = krb5_make_principal(context, &referral.server, start_realm,
                                  KRB5_TGS_NAME, in_creds->server->realm, NULL);

    if (ret) {
	krb5_free_cred_contents(context, &tgt);
        free(start_realm);
	return ret;
    }
    if (!want_tgt)
        ret = krb5_principal_set_realm(context, referral.server, start_realm);
    free(start_realm);
    start_realm = NULL;
    if (ret) {
	krb5_free_cred_contents(context, &tgt);
	krb5_free_principal(context, referral.server);
	return ret;
    }

    while (loop++ < 17) {
	krb5_creds **tickets;
	krb5_creds mcreds;
	char *referral_realm;

	/* Use cache if we are not doing impersonation or contrained deleg */
	if (impersonate_principal == NULL && !flags.b.cname_in_addl_tkt) {
	    krb5_cc_clear_mcred(&mcreds);
	    mcreds.server = referral.server;
	    krb5_timeofday(context, &mcreds.times.endtime);
	    ret = krb5_cc_retrieve_cred(context, ccache, KRB5_TC_MATCH_TIMES,
					&mcreds, &ticket);
	} else
	    ret = EINVAL;

	if (ret) {
	    ret = get_cred_kdc_address(context, ccache, fast_state, flags, NULL,
				       &referral, &tgt, impersonate_principal,
				       second_ticket, kdc_hostname, sitename, &ticket);
	    if (ret)
		goto out;
	}

        /*
         * Did we get the right ticket?
         *
         * If we weren't asking for a TGT, then we don't mind if we took a realm
         * change (referral.server has a referral realm, not necessarily the
         * original).
         *
         * However, if we were looking for a TGT (which wouldn't be the start
         * TGT, since that one must be in the ccache) then we actually want the
         * one from the realm we wanted, since otherwise a _referral_ will
         * confuse us and we will store that referral.  In Heimdal we mostly
         * never ask krb5_get_cred*() for TGTs, but some sites have code to ask
         * for a ktbgt/REMOTE.REALM@REMOTE.REALM, and one could always use
         * kgetcred(1) to get here asking for a krbtgt/C@D and we need to handle
         * the case where last hop we get is krbtgt/C@B (in which case we must
         * stop so we don't beat up on B for the remaining tries).
         */
        if (!want_tgt &&
            krb5_principal_compare(context, referral.server, ticket.server))
	    break;

	if (!krb5_principal_is_krbtgt(context, ticket.server)) {
	    krb5_set_error_message(context, KRB5KRB_AP_ERR_NOT_US,
				   N_("Got back an non krbtgt "
				      "ticket referrals", ""));
	    ret = KRB5KRB_AP_ERR_NOT_US;
	    goto out;
	}

	referral_realm = ticket.server->name.name_string.val[1];

	/* check that there are no referrals loops */
	tickets = referral_tgts;

	krb5_cc_clear_mcred(&mcreds);
	mcreds.server = ticket.server;

	while (tickets && *tickets){
	    if (krb5_compare_creds(context,
				  KRB5_TC_DONT_MATCH_REALM,
				  &mcreds,
				  *tickets)) {
		krb5_set_error_message(context, KRB5_GET_IN_TKT_LOOP,
				       N_("Referral from %s "
					  "loops back to realm %s", ""),
				       tgt.server->realm,
				       referral_realm);
		ret = KRB5_GET_IN_TKT_LOOP;
                goto out;
	    }
	    tickets++;
	}

	/*
	 * if either of the chain or the ok_as_delegate was stripped
	 * by the kdc, make sure we strip it too.
	 */

	if (ok_as_delegate == 0 || ticket.flags.b.ok_as_delegate == 0) {
	    ok_as_delegate = 0;
	    ticket.flags.b.ok_as_delegate = 0;
	}

        _krb5_debug(context, 6, "get_cred_kdc_referral: got referral "
                    "to %s from %s", referral_realm, referral.server->realm);
	ret = add_cred(context, &ticket, &referral_tgts);
	if (ret)
	    goto out;

	/* try realm in the referral */
        if (!want_tgt || strcmp(referral_realm, in_creds->server->realm) != 0)
            ret = krb5_principal_set_realm(context,
                                           referral.server,
                                           referral_realm);
        else {
            /*
             * Now that we have a ticket for the desired realm, we reset
             * want_tgt and reinstate the desired principal so that the we can
             * match it and break out of the loop.
             */
            want_tgt = 0;
            krb5_free_principal(context, referral.server);
            referral.server = NULL;
            ret = krb5_copy_principal(context, in_creds->server, &referral.server);
        }
	krb5_free_cred_contents(context, &tgt);
	tgt = ticket;
	memset(&ticket, 0, sizeof(ticket));
	if (ret)
	    goto out;
    }

    ret = krb5_copy_creds(context, &ticket, out_creds);

out:
    for (i = 0; referral_tgts && referral_tgts[i]; i++)
	krb5_free_creds(context, referral_tgts[i]);
    free(referral_tgts);
    krb5_free_principal(context, referral.server);
    krb5_free_cred_contents(context, &tgt);
    krb5_free_cred_contents(context, &ticket);
    return ret;
}


/*
 * Glue function between referrals version and old client chasing
 * codebase.
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
_krb5_get_cred_kdc_any(krb5_context context,
		       krb5_kdc_flags flags,
		       krb5_ccache ccache,
		       struct krb5_fast_state *fast_state,
		       krb5_creds *in_creds,
		       krb5_principal impersonate_principal,
		       Ticket *second_ticket,
		       krb5_creds **out_creds,
		       krb5_creds ***ret_tgts)
{
    char *kdc_hostname = NULL;
    char *sitename = NULL;
    krb5_error_code ret;
    krb5_deltat offset;
    krb5_data data;

    krb5_data_zero(&data);

    /*
     * If we are using LKDC, lets pull out the addresses from the
     * ticket and use that.
     */
    
    ret = krb5_cc_get_config(context, ccache, NULL, "lkdc-hostname", &data);
    if (ret == 0) {
	if ((kdc_hostname = strndup(data.data, data.length)) == NULL) {
            ret = krb5_enomem(context);
            goto out;
        }
	krb5_data_free(&data);
    }

    ret = krb5_cc_get_config(context, ccache, NULL, "sitename", &data);
    if (ret == 0) {
	if ((sitename = strndup(data.data, data.length)) == NULL) {
	    ret = krb5_enomem(context);
            goto out;
        }
	krb5_data_free(&data);
    }

    ret = krb5_cc_get_kdc_offset(context, ccache, &offset);
    if (ret == 0) {
	context->kdc_sec_offset = offset;
	context->kdc_usec_offset = 0;
    }

    if (strcmp(in_creds->server->realm, "") != 0) {
        /*
         * Non-empty realm?  Try capaths first.  We might have local
         * policy (capaths) to honor.
         */
        ret = get_cred_kdc_capath(context,
                                  flags,
				  ccache,
				  fast_state,
				  in_creds,
				  impersonate_principal,
				  second_ticket,
				  kdc_hostname,
				  sitename,
				  out_creds,
				  ret_tgts);
        if (ret == 0 || skip_referrals(in_creds->server, &flags))
	    goto out;
    }

    /* Otherwise try referrals */
    ret = get_cred_kdc_referral(context,
                                flags,
                                ccache,
				fast_state,
                                in_creds,
                                impersonate_principal,
                                second_ticket,
				kdc_hostname,
				sitename,
                                out_creds);
    
out:
    krb5_data_free(&data);
    free(kdc_hostname);
    free(sitename);
    return ret;
}

static krb5_error_code
check_cc(krb5_context context, krb5_flags options, krb5_ccache ccache,
	 krb5_creds *in_creds, krb5_creds *out_creds)
{
    krb5_error_code ret;
    krb5_timestamp now;
    krb5_creds mcreds = *in_creds;

    krb5_timeofday(context, &now);

    if (!(options & KRB5_GC_EXPIRED_OK) &&
	mcreds.times.endtime < now) {
	mcreds.times.renew_till = 0;
	krb5_timeofday(context, &mcreds.times.endtime);
	options |= KRB5_TC_MATCH_TIMES;
    }

    if (mcreds.server->name.name_type == KRB5_NT_SRV_HST_NEEDS_CANON) {
        /* Avoid name canonicalization in krb5_cc_retrieve_cred() */
        krb5_principal_set_type(context, mcreds.server, KRB5_NT_SRV_HST);
    }

    if (options & KRB5_GC_ANONYMOUS) {
	ret = krb5_make_principal(context,
				  &mcreds.client,
				  krb5_principal_get_realm(context, mcreds.client),
				  KRB5_WELLKNOWN_NAME,
				  KRB5_ANON_NAME,
				  NULL);
	if (ret)
	    return ret;
    }

    ret = krb5_cc_retrieve_cred(context, ccache,
				(options &
				 (KRB5_TC_DONT_MATCH_REALM |
                                  KRB5_TC_MATCH_KEYTYPE |
				  KRB5_TC_MATCH_TIMES)),
				&mcreds, out_creds);

    if (options & KRB5_GC_ANONYMOUS)
	krb5_free_principal(context, mcreds.client);

    if (ret == 0 && out_creds->server->realm &&
        out_creds->server->realm[0] == '\0') {
        Ticket ticket;

        /*
         * We only write tickets to the ccache that have been validated, as in,
         * the sname/srealm from the KDC-REP enc-part have been checked to
         * match the sname/realm from the Ticket from the KDC-REP.
         *
         * Our caller needs the canonical realm of the service in order to be
         * able to get forwarded credentials for it when destination-TGT
         * forwarding is enabled.
         *
         * As well, gss_init_sec_context() ought to arrange for
         * gss_inquire_context() to output the canonical acceptor name on the
         * initiator side.
         */
        ret = decode_Ticket(out_creds->ticket.data, out_creds->ticket.length,
                            &ticket, NULL);
        if (ret == 0) {
            ret = krb5_principal_set_realm(context, out_creds->server,
                                           ticket.realm);
            free_Ticket(&ticket);
        } else {
            krb5_free_cred_contents(context, out_creds);
        }
    }
    return ret;
}

static void
store_cred(krb5_context context, krb5_ccache ccache,
	   krb5_const_principal server_princ, krb5_creds *creds)
{
    if (context->no_ticket_store)
        return;
    if (!krb5_principal_compare(context, creds->server, server_princ) &&
        !krb5_principal_is_krbtgt(context, server_princ)) {
        krb5_principal tmp_princ = creds->server;
        /*
         * Store the cred with the pre-canon server princ first so it
         * can be found quickly in the future.
         */
        creds->server = (krb5_principal)server_princ;
        krb5_cc_store_cred(context, ccache, creds);
        creds->server = tmp_princ;
        /* Then store again with the canonicalized server princ */
    }
    krb5_cc_store_cred(context, ccache, creds);
}


KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_get_credentials_with_flags(krb5_context context,
				krb5_flags options,
				krb5_kdc_flags flags,
				krb5_ccache ccache,
				krb5_creds *in_creds,
				krb5_creds **out_creds)
{
    struct krb5_fast_state fast_state;
    krb5_error_code ret;
    krb5_name_canon_iterator name_canon_iter = NULL;
    krb5_name_canon_rule_options rule_opts;
    krb5_const_principal try_princ = NULL;
    krb5_principal save_princ = in_creds->server;
    krb5_creds **tgts;
    krb5_creds *res_creds;
    int i;

    memset(&fast_state, 0, sizeof(fast_state));

    if (_krb5_have_debug(context, 5)) {
        char *unparsed;

        ret = krb5_unparse_name(context, in_creds->server, &unparsed);
        if (ret) {
            _krb5_debug(context, 5, "krb5_get_creds: unable to display "
                        "requested service principal");
        } else {
            _krb5_debug(context, 5, "krb5_get_creds: requesting a ticket "
                        "for %s", unparsed);
            free(unparsed);
        }
    }

    if (in_creds->session.keytype) {
	ret = krb5_enctype_valid(context, in_creds->session.keytype);
	if (ret)
	    return ret;
	options |= KRB5_TC_MATCH_KEYTYPE;
    }

    *out_creds = NULL;
    res_creds = calloc(1, sizeof(*res_creds));
    if (res_creds == NULL)
	return krb5_enomem(context);

    ret = krb5_name_canon_iterator_start(context, in_creds->server,
					 &name_canon_iter);
    if (ret)
	goto out;

next_rule:
    krb5_free_cred_contents(context, res_creds);
    memset(res_creds, 0, sizeof (*res_creds));
    ret = krb5_name_canon_iterate(context, &name_canon_iter, &try_princ,
                                  &rule_opts);
    in_creds->server = rk_UNCONST(try_princ);
    if (ret)
	goto out;

    if (name_canon_iter == NULL) {
	if (options & KRB5_GC_CACHED)
	    ret = KRB5_CC_NOTFOUND;
	else
	    ret = KRB5KDC_ERR_S_PRINCIPAL_UNKNOWN;
	goto out;
    }

    ret = check_cc(context, options, ccache, in_creds, res_creds);
    if (ret == 0) {
	*out_creds = res_creds;
        res_creds = NULL;
	goto out;
    } else if(ret != KRB5_CC_END) {
        goto out;
    }
    if (options & KRB5_GC_CACHED)
	goto next_rule;

    if(options & KRB5_GC_USER_USER)
	flags.b.enc_tkt_in_skey = 1;
    if (flags.b.enc_tkt_in_skey)
	options |= KRB5_GC_NO_STORE;

    tgts = NULL;
    ret = _krb5_get_cred_kdc_any(context, flags, ccache, &fast_state,
				 in_creds, NULL, NULL, out_creds, &tgts);
    for (i = 0; tgts && tgts[i]; i++) {
	if ((options & KRB5_GC_NO_STORE) == 0)
	    krb5_cc_store_cred(context, ccache, tgts[i]);
	krb5_free_creds(context, tgts[i]);
    }
    free(tgts);

    /* We don't yet have TGS w/ FAST, so we can't protect KBR-ERRORs */
    if (ret == KRB5KDC_ERR_S_PRINCIPAL_UNKNOWN &&
	!(rule_opts & KRB5_NCRO_USE_FAST))
	goto next_rule;

    if(ret == 0 && (options & KRB5_GC_NO_STORE) == 0)
	store_cred(context, ccache, in_creds->server, *out_creds);

    if (ret == 0 && _krb5_have_debug(context, 5)) {
        char *unparsed;

        ret = krb5_unparse_name(context, (*out_creds)->server, &unparsed);
        if (ret) {
            _krb5_debug(context, 5, "krb5_get_creds: unable to display "
                        "service principal");
        } else {
            _krb5_debug(context, 5, "krb5_get_creds: got a ticket for %s",
                        unparsed);
            free(unparsed);
        }
    }

out:
    in_creds->server = save_princ;
    krb5_free_creds(context, res_creds);
    krb5_free_name_canon_iterator(context, name_canon_iter);
    _krb5_fast_free(context, &fast_state);
    if (ret)
	return not_found(context, in_creds->server, ret);
    return 0;
}

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_get_credentials(krb5_context context,
		     krb5_flags options,
		     krb5_ccache ccache,
		     krb5_creds *in_creds,
		     krb5_creds **out_creds)
{
    krb5_kdc_flags flags;
    flags.i = 0;
    return krb5_get_credentials_with_flags(context, options, flags,
					   ccache, in_creds, out_creds);
}

struct krb5_get_creds_opt_data {
    krb5_principal self;
    krb5_flags options;
    krb5_enctype enctype;
    Ticket *ticket;
};


KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_get_creds_opt_alloc(krb5_context context, krb5_get_creds_opt *opt)
{
    *opt = calloc(1, sizeof(**opt));
    if (*opt == NULL)
	return krb5_enomem(context);
    return 0;
}

KRB5_LIB_FUNCTION void KRB5_LIB_CALL
krb5_get_creds_opt_free(krb5_context context, krb5_get_creds_opt opt)
{
    if (opt->self)
	krb5_free_principal(context, opt->self);
    if (opt->ticket) {
	free_Ticket(opt->ticket);
	free(opt->ticket);
    }
    memset(opt, 0, sizeof(*opt));
    free(opt);
}

KRB5_LIB_FUNCTION void KRB5_LIB_CALL
krb5_get_creds_opt_set_options(krb5_context context,
			       krb5_get_creds_opt opt,
			       krb5_flags options)
{
    opt->options = options;
}

KRB5_LIB_FUNCTION void KRB5_LIB_CALL
krb5_get_creds_opt_add_options(krb5_context context,
			       krb5_get_creds_opt opt,
			       krb5_flags options)
{
    opt->options |= options;
}

KRB5_LIB_FUNCTION void KRB5_LIB_CALL
krb5_get_creds_opt_set_enctype(krb5_context context,
			       krb5_get_creds_opt opt,
			       krb5_enctype enctype)
{
    opt->enctype = enctype;
}

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_get_creds_opt_set_impersonate(krb5_context context,
				   krb5_get_creds_opt opt,
				   krb5_const_principal self)
{
    if (opt->self)
	krb5_free_principal(context, opt->self);
    return krb5_copy_principal(context, self, &opt->self);
}

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_get_creds_opt_set_ticket(krb5_context context,
			      krb5_get_creds_opt opt,
			      const Ticket *ticket)
{
    if (opt->ticket) {
	free_Ticket(opt->ticket);
	free(opt->ticket);
	opt->ticket = NULL;
    }
    if (ticket) {
	krb5_error_code ret;

	opt->ticket = malloc(sizeof(*ticket));
	if (opt->ticket == NULL)
	    return krb5_enomem(context);
	ret = copy_Ticket(ticket, opt->ticket);
	if (ret) {
	    free(opt->ticket);
	    opt->ticket = NULL;
	    krb5_set_error_message(context, ret,
				   N_("malloc: out of memory", ""));
	    return ret;
	}
    }
    return 0;
}


KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_get_creds(krb5_context context,
	       krb5_get_creds_opt opt,
	       krb5_ccache ccache,
	       krb5_const_principal inprinc,
	       krb5_creds **out_creds)
{
    struct krb5_fast_state fast_state;
    krb5_kdc_flags flags;
    krb5_flags options;
    krb5_creds in_creds;
    krb5_error_code ret;
    krb5_creds **tgts;
    krb5_creds *res_creds;
    krb5_const_principal try_princ = NULL;
    krb5_name_canon_iterator name_canon_iter = NULL;
    krb5_name_canon_rule_options rule_opts;
    int i;
    int type;
    const char *comp;

    memset(&fast_state, 0, sizeof(fast_state));
    memset(&in_creds, 0, sizeof(in_creds));
    in_creds.server = rk_UNCONST(inprinc);

    if (_krb5_have_debug(context, 5)) {
        char *unparsed;

        ret = krb5_unparse_name(context, in_creds.server, &unparsed);
        if (ret) {
            _krb5_debug(context, 5, "krb5_get_creds: unable to display "
                        "requested service principal");
        } else {
            _krb5_debug(context, 5, "krb5_get_creds: requesting a ticket "
                        "for %s", unparsed);
            free(unparsed);
        }
    }

    if (opt && opt->enctype) {
	ret = krb5_enctype_valid(context, opt->enctype);
	if (ret)
	    return ret;
    }

    ret = krb5_cc_get_principal(context, ccache, &in_creds.client);
    if (ret)
	return ret;

    if (opt)
	options = opt->options;
    else
	options = 0;
    flags.i = 0;

    *out_creds = NULL;
    res_creds = calloc(1, sizeof(*res_creds));
    if (res_creds == NULL) {
	krb5_free_principal(context, in_creds.client);
	return krb5_enomem(context);
    }

    if (opt && opt->enctype) {
	in_creds.session.keytype = opt->enctype;
	options |= KRB5_TC_MATCH_KEYTYPE;
    }

    ret = krb5_name_canon_iterator_start(context, in_creds.server,
					 &name_canon_iter);
    if (ret)
	goto out;

next_rule:
    ret = krb5_name_canon_iterate(context, &name_canon_iter, &try_princ,
                                  &rule_opts);
    in_creds.server = rk_UNCONST(try_princ);
    if (ret)
	goto out;

    if (name_canon_iter == NULL) {
	if (options & KRB5_GC_CACHED)
	    ret = KRB5_CC_NOTFOUND;
	else
	    ret = KRB5KDC_ERR_S_PRINCIPAL_UNKNOWN;
	goto out;
    }

    if ((options & KRB5_GC_CONSTRAINED_DELEGATION) == 0) {
	ret = check_cc(context, options, ccache, &in_creds, res_creds);
	if (ret == 0) {
	    *out_creds = res_creds;
	    res_creds = NULL;
	    goto out;
	} else if (ret != KRB5_CC_END) {
	    goto out;
	}
    }
    if (options & KRB5_GC_CACHED)
	goto next_rule;

    type = krb5_principal_get_type(context, try_princ);
    comp = krb5_principal_get_comp_string(context, try_princ, 0);
    if ((type == KRB5_NT_SRV_HST || type == KRB5_NT_UNKNOWN) &&
        comp != NULL && strcmp(comp, "host") == 0)
	flags.b.canonicalize = 1;
    if (rule_opts & KRB5_NCRO_NO_REFERRALS)
	flags.b.canonicalize = 0;
    else
	flags.b.canonicalize = (options & KRB5_GC_CANONICALIZE) ? 1 : 0;
    if (options & KRB5_GC_USER_USER) {
	flags.b.enc_tkt_in_skey = 1;
	options |= KRB5_GC_NO_STORE;
    }
    if (options & KRB5_GC_FORWARDABLE)
	flags.b.forwardable = 1;
    if (options & KRB5_GC_NO_TRANSIT_CHECK)
	flags.b.disable_transited_check = 1;
    if (options & KRB5_GC_CONSTRAINED_DELEGATION)
	flags.b.cname_in_addl_tkt = 1;
    if (options & KRB5_GC_ANONYMOUS)
	flags.b.request_anonymous = 1;

    tgts = NULL;
    ret = _krb5_get_cred_kdc_any(context, flags, ccache, &fast_state,
				 &in_creds, opt ? opt->self : 0,
				 opt ? opt->ticket : 0, out_creds,
				 &tgts);
    for (i = 0; tgts && tgts[i]; i++) {
	if ((options & KRB5_GC_NO_STORE) == 0)
	    krb5_cc_store_cred(context, ccache, tgts[i]);
	krb5_free_creds(context, tgts[i]);
    }
    free(tgts);

    /* We don't yet have TGS w/ FAST, so we can't protect KBR-ERRORs */
    if (ret == KRB5KDC_ERR_S_PRINCIPAL_UNKNOWN &&
	!(rule_opts & KRB5_NCRO_USE_FAST))
	goto next_rule;

    if (ret == 0 && (options & KRB5_GC_NO_STORE) == 0)
	store_cred(context, ccache, inprinc, *out_creds);

    if (ret == 0 && _krb5_have_debug(context, 5)) {
        char *unparsed;

        ret = krb5_unparse_name(context, (*out_creds)->server, &unparsed);
        if (ret) {
            _krb5_debug(context, 5, "krb5_get_creds: unable to display "
                        "service principal");
        } else {
            _krb5_debug(context, 5, "krb5_get_creds: got a ticket for %s",
                        unparsed);
            free(unparsed);
        }
    }

out:
    _krb5_fast_free(context, &fast_state);
    krb5_free_creds(context, res_creds);
    krb5_free_principal(context, in_creds.client);
    krb5_free_name_canon_iterator(context, name_canon_iter);
    if (ret)
	return not_found(context, inprinc, ret);
    return ret;
}

/*
 *
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_get_renewed_creds(krb5_context context,
		       krb5_creds *creds,
		       krb5_const_principal client,
		       krb5_ccache ccache,
		       const char *in_tkt_service)
{
    krb5_error_code ret;
    krb5_kdc_flags flags;
    krb5_creds in, *template, *out = NULL;

    memset(&in, 0, sizeof(in));
    memset(creds, 0, sizeof(*creds));

    ret = krb5_copy_principal(context, client, &in.client);
    if (ret)
	return ret;

    if (in_tkt_service) {
	ret = krb5_parse_name(context, in_tkt_service, &in.server);
	if (ret) {
	    krb5_free_principal(context, in.client);
	    return ret;
	}
    } else {
	const char *realm = krb5_principal_get_realm(context, client);

	ret = krb5_make_principal(context, &in.server, realm, KRB5_TGS_NAME,
				  realm, NULL);
	if (ret) {
	    krb5_free_principal(context, in.client);
	    return ret;
	}
    }

    flags.i = 0;
    flags.b.renewable = flags.b.renew = 1;

    /*
     * Get template from old credential cache for the same entry, if
     * this failes, no worries.
     */
    ret = krb5_get_credentials(context, KRB5_GC_CACHED, ccache, &in, &template);
    if (ret == 0) {
	flags.b.forwardable = template->flags.b.forwardable;
	flags.b.proxiable = template->flags.b.proxiable;
	krb5_free_creds (context, template);
    }

    ret = krb5_get_kdc_cred(context, ccache, flags, NULL, NULL, &in, &out);
    krb5_free_principal(context, in.client);
    krb5_free_principal(context, in.server);
    if (ret)
	return ret;

    ret = krb5_copy_creds_contents(context, out, creds);
    krb5_free_creds(context, out);

    return ret;
}
