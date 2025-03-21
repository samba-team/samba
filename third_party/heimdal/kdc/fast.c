/*
 * Copyright (c) 1997-2011 Kungliga Tekniska Högskolan
 * (Royal Institute of Technology, Stockholm, Sweden).
 * All rights reserved.
 *
 * Portions Copyright (c) 2010 - 2011 Apple Inc. All rights reserved.
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

static krb5_error_code
salt_fastuser_crypto(astgs_request_t r,
		     krb5_const_principal salt_principal,
		     krb5_enctype enctype,
		     krb5_crypto fast_crypto,
		     krb5_crypto *salted_crypto)
{
    krb5_error_code ret;
    krb5_principal client_princ = NULL;
    krb5_data salt;
    krb5_keyblock dkey;
    size_t size;

    *salted_crypto = NULL;

    krb5_data_zero(&salt);
    krb5_keyblock_zero(&dkey);

    if (salt_principal == NULL) {
	if (r->req.req_body.cname == NULL) {
	    ret = KRB5KRB_ERR_GENERIC;
	    goto out;
	}

	ret = _krb5_principalname2krb5_principal(r->context, &client_princ,
						 *(r->req.req_body.cname),
						 r->req.req_body.realm);
	if (ret)
	    goto out;

	salt_principal = client_princ;
    }

    ret = krb5_unparse_name(r->context, salt_principal, (char **)&salt.data);
    if (ret)
	goto out;

    salt.length = strlen(salt.data);

    kdc_log(r->context, r->config, 10,
	    "salt_fastuser_crypto: salt principal is %s (%d)",
	    (char *)salt.data, enctype);

    ret = krb5_enctype_keysize(r->context, enctype, &size);
    if (ret)
	goto out;

    ret = krb5_crypto_prfplus(r->context, fast_crypto, &salt,
			      size, &dkey.keyvalue);
    if (ret)
	goto out;

    dkey.keytype = enctype;

    ret = krb5_crypto_init(r->context, &dkey, ENCTYPE_NULL, salted_crypto);
    if (ret)
	goto out;

out:
    krb5_free_keyblock_contents(r->context, &dkey);
    krb5_data_free(&salt);
    krb5_free_principal(r->context, client_princ);

    return ret;
}

static krb5_error_code
get_fastuser_crypto(astgs_request_t r,
		    krb5_const_principal ticket_client,
		    krb5_enctype enctype,
		    krb5_crypto *crypto)
{
    krb5_principal fast_princ;
    HDB *fast_db;
    hdb_entry *fast_user = NULL;
    Key *cookie_key = NULL;
    krb5_crypto fast_crypto = NULL;
    krb5_error_code ret;

    *crypto = NULL;

    ret = krb5_make_principal(r->context, &fast_princ,
			      KRB5_WELLKNOWN_ORG_H5L_REALM,
			      KRB5_WELLKNOWN_NAME, "org.h5l.fast-cookie", NULL);
    if (ret)
	goto out;

    ret = _kdc_db_fetch(r->context, r->config, fast_princ,
			HDB_F_GET_FAST_COOKIE, NULL, &fast_db, &fast_user);
    if (ret)
	goto out;

    if (enctype == KRB5_ENCTYPE_NULL)
	ret = _kdc_get_preferred_key(r->context, r->config, fast_user,
				     "fast-cookie", &enctype, &cookie_key);
    else
	ret = hdb_enctype2key(r->context, fast_user, NULL,
			      enctype, &cookie_key);
    if (ret)
	goto out;

    ret = krb5_crypto_init(r->context, &cookie_key->key,
			   ENCTYPE_NULL, &fast_crypto);
    if (ret)
	goto out;

    ret = salt_fastuser_crypto(r, ticket_client,
			       cookie_key->key.keytype,
			       fast_crypto, crypto);
    if (ret)
	goto out;

 out:
    if (fast_user)
	_kdc_free_ent(r->context, fast_db, fast_user);
    if (fast_crypto)
	krb5_crypto_destroy(r->context, fast_crypto);
    krb5_free_principal(r->context, fast_princ);

    return ret;
}


static krb5_error_code
fast_parse_cookie(astgs_request_t r,
		  krb5_const_principal ticket_client,
		  const PA_DATA *pa)
{
    krb5_crypto crypto = NULL;
    krb5_error_code ret;
    KDCFastCookie data;
    krb5_data d1;
    size_t len;

    ret = decode_KDCFastCookie(pa->padata_value.data,
			       pa->padata_value.length,
			       &data, &len);
    if (ret)
	return ret;

    if (len != pa->padata_value.length || strcmp("H5L1", data.version) != 0) {
	free_KDCFastCookie(&data);
	return KRB5KDC_ERR_POLICY;
    }

    ret = get_fastuser_crypto(r, ticket_client, data.cookie.etype, &crypto);
    if (ret)
	goto out;

    ret = krb5_decrypt_EncryptedData(r->context, crypto,
				     KRB5_KU_H5L_COOKIE,
				     &data.cookie, &d1);
    krb5_crypto_destroy(r->context, crypto);
    if (ret)
	goto out;

    ret = decode_KDCFastState(d1.data, d1.length, &r->fast, &len);
    krb5_data_free(&d1);
    if (ret)
	goto out;

    if (r->fast.expiration < kdc_time) {
	kdc_log(r->context, r->config, 2, "FAST cookie expired");
	ret = KRB5KDC_ERR_POLICY;
	goto out;
    }

 out:
    free_KDCFastCookie(&data);

    return ret;
}

static krb5_error_code
fast_add_cookie(astgs_request_t r,
		krb5_const_principal ticket_client,
		METHOD_DATA *method_data)
{
    krb5_crypto crypto = NULL;
    KDCFastCookie shell;
    krb5_error_code ret;
    krb5_data data;
    size_t size;

    memset(&shell, 0, sizeof(shell));

    r->fast.expiration = kdc_time + FAST_EXPIRATION_TIME;

    ASN1_MALLOC_ENCODE(KDCFastState, data.data, data.length,
		       &r->fast, &size, ret);
    if (ret)
	return ret;
    heim_assert(size == data.length, "internal asn.1 encoder error");

    ret = get_fastuser_crypto(r, ticket_client, KRB5_ENCTYPE_NULL, &crypto);
    if (ret) {
	kdc_log(r->context, r->config, 0,
		"Failed to find FAST principal for cookie encryption: %d", ret);
	goto out;
    }

    ret = krb5_encrypt_EncryptedData(r->context, crypto,
				     KRB5_KU_H5L_COOKIE,
				     data.data, data.length, 0,
				     &shell.cookie);
    krb5_crypto_destroy(r->context, crypto);
    if (ret)
	goto out;

    krb5_data_free(&data);

    shell.version = "H5L1";

    ASN1_MALLOC_ENCODE(KDCFastCookie, data.data, data.length,
		       &shell, &size, ret);
    free_EncryptedData(&shell.cookie);
    if (ret)
	goto out;
    heim_assert(size == data.length, "internal asn.1 encoder error");

    ret = krb5_padata_add(r->context, method_data,
			  KRB5_PADATA_FX_COOKIE,
			  data.data, data.length);
    if (ret == 0)
	krb5_data_zero(&data);

 out:
    krb5_data_free(&data);
    return ret;
}

static krb5_error_code
fast_add_dummy_cookie(astgs_request_t r,
		      METHOD_DATA *method_data)
{
    krb5_error_code ret;
    krb5_data data;
    const krb5_data *dummy_fast_cookie = &r->config->dummy_fast_cookie;

    if (dummy_fast_cookie->data == NULL)
	return 0;

    ret = krb5_data_copy(&data,
			 dummy_fast_cookie->data,
			 dummy_fast_cookie->length);
    if (ret)
	return ret;

    ret = krb5_padata_add(r->context, method_data,
			  KRB5_PADATA_FX_COOKIE,
			  data.data, data.length);
    if (ret) {
	krb5_data_free(&data);
    }

    return ret;
}

krb5_error_code
_kdc_fast_mk_response(krb5_context context,
		      krb5_crypto armor_crypto,
		      METHOD_DATA *pa_data,
		      krb5_keyblock *strengthen_key,
		      KrbFastFinished *finished,
		      krb5uint32 nonce,
		      krb5_data *data)
{
    PA_FX_FAST_REPLY fxfastrep;
    KrbFastResponse fastrep;
    krb5_error_code ret;
    krb5_data buf;
    size_t size;

    memset(&fxfastrep, 0, sizeof(fxfastrep));
    memset(&fastrep, 0, sizeof(fastrep));
    krb5_data_zero(data);

    if (pa_data) {
	fastrep.padata.val = pa_data->val;
	fastrep.padata.len = pa_data->len;
    }
    fastrep.strengthen_key = strengthen_key;
    fastrep.finished = finished;
    fastrep.nonce = nonce;

    ASN1_MALLOC_ENCODE(KrbFastResponse, buf.data, buf.length,
		       &fastrep, &size, ret);
    if (ret)
	return ret;
    heim_assert(size == buf.length, "internal asn.1 encoder error");

    fxfastrep.element = choice_PA_FX_FAST_REPLY_armored_data;

    ret = krb5_encrypt_EncryptedData(context,
				     armor_crypto,
				     KRB5_KU_FAST_REP,
				     buf.data,
				     buf.length,
				     0,
				     &fxfastrep.u.armored_data.enc_fast_rep);
    krb5_data_free(&buf);
    if (ret)
	return ret;

    ASN1_MALLOC_ENCODE(PA_FX_FAST_REPLY, data->data, data->length,
		       &fxfastrep, &size, ret);
    free_PA_FX_FAST_REPLY(&fxfastrep);
    if (ret)
	return ret;
    heim_assert(size == data->length, "internal asn.1 encoder error");

    return 0;
}


static krb5_error_code
_kdc_fast_mk_e_data(astgs_request_t r,
		   METHOD_DATA *error_method,
		   krb5_crypto armor_crypto,
		   const KDC_REQ_BODY *req_body,
		   krb5_error_code outer_error,
		   krb5_principal error_client,
		   krb5_principal error_server,
		   time_t *csec, int *cusec,
		   krb5_data *e_data)
{
    krb5_error_code ret = 0;
    size_t size;

    /*
     * FX-COOKIE can be used outside of FAST, e.g. SRP or GSS.
     */
    if (armor_crypto || r->fast.fast_state.len) {
	if (r->config->enable_fast_cookie) {
	    kdc_log(r->context, r->config, 5, "Adding FAST cookie for KRB-ERROR");
	    ret = fast_add_cookie(r, error_client, error_method);
	    if (ret) {
		kdc_log(r->context, r->config, 1,
			"Failed to add FAST cookie: %d", ret);
		free_METHOD_DATA(error_method);
		return ret;
	    }
	} else {
	    kdc_log(r->context, r->config, 5, "Adding dummy FAST cookie for KRB-ERROR");
	    ret = fast_add_dummy_cookie(r, error_method);
	    if (ret) {
		kdc_log(r->context, r->config, 1,
			"Failed to add dummy FAST cookie: %d", ret);
		free_METHOD_DATA(error_method);
		return ret;
	    }
	}
    }

    if (armor_crypto) {
	PA_FX_FAST_REPLY fxfastrep;
	KrbFastResponse fastrep;

	memset(&fxfastrep, 0, sizeof(fxfastrep));
	memset(&fastrep, 0, sizeof(fastrep));

        kdc_log(r->context, r->config, 5, "Making FAST inner KRB-ERROR");

	/* first add the KRB-ERROR to the fast errors */

	ret = krb5_mk_error(r->context,
			    outer_error,
			    r->e_text,
			    NULL,
			    error_client,
			    error_server,
			    csec,
			    cusec,
			    e_data);
	if (ret) {
	    kdc_log(r->context, r->config, 1,
		    "Failed to make inner KRB-ERROR: %d", ret);
	    return ret;
        }

	ret = krb5_padata_add(r->context, error_method,
			      KRB5_PADATA_FX_ERROR,
			      e_data->data, e_data->length);
	if (ret) {
	    kdc_log(r->context, r->config, 1,
		    "Failed to make add FAST PADATA to inner KRB-ERROR: %d", ret);
	    krb5_data_free(e_data);
	    return ret;
	}

	r->e_text = NULL;

	ret = _kdc_fast_mk_response(r->context, armor_crypto,
				    error_method, NULL, NULL,
				    req_body->nonce, e_data);
	free_METHOD_DATA(error_method);
	if (ret) {
	    kdc_log(r->context, r->config, 1,
		    "Failed to make outer KRB-ERROR: %d", ret);
	    return ret;
        }

	ret = krb5_padata_add(r->context, error_method,
			      KRB5_PADATA_FX_FAST,
			      e_data->data, e_data->length);
	if (ret) {
	    kdc_log(r->context, r->config, 1,
		    "Failed to make add FAST PADATA to outer KRB-ERROR: %d", ret);
	    return ret;
        }
    } else
        kdc_log(r->context, r->config, 5, "Making non-FAST KRB-ERROR");

    if (error_method && error_method->len) {
	ASN1_MALLOC_ENCODE(METHOD_DATA, e_data->data, e_data->length,
			   error_method, &size, ret);
	if (ret) {
	    kdc_log(r->context, r->config, 1,
		    "Failed to make encode METHOD-DATA: %d", ret);
	    return ret;
        }
	heim_assert(size == e_data->length, "internal asn.1 encoder error");
    }

    return ret;
}


krb5_error_code
_kdc_fast_mk_error(astgs_request_t r,
		   METHOD_DATA *error_method,
		   krb5_crypto armor_crypto,
		   const KDC_REQ_BODY *req_body,
		   krb5_error_code outer_error,
		   krb5_principal error_client,
		   krb5_principal error_server,
		   time_t *csec, int *cusec,
		   krb5_data *error_msg)
{
    krb5_error_code ret;
    krb5_data _e_data;
    krb5_data *e_data = NULL;

    krb5_data_zero(&_e_data);

    heim_assert(r != NULL, "invalid request in _kdc_fast_mk_error");

    if (!armor_crypto && r->e_data.length) {
	/*
	 * If we’re not armoring the response with FAST, r->e_data
	 * takes precedence over the e‐data that would normally be
	 * generated. r->e_data typically contains a
	 * Microsoft‐specific NTSTATUS code.
	 *
	 * But if FAST is in use, Windows Server suppresses the
	 * NTSTATUS code in favour of an armored response
	 * encapsulating an ordinary KRB‐ERROR. So we ignore r->e_data
	 * in that case.
	 */
	e_data = &r->e_data;
    } else {
	ret = _kdc_fast_mk_e_data(r,
				  error_method,
				  armor_crypto,
				  req_body,
				  outer_error,
				  error_client,
				  error_server,
				  csec, cusec,
				  &_e_data);
	if (ret) {
	    kdc_log(r->context, r->config, 1,
		    "Failed to make FAST e-data: %d", ret);
	    return ret;
	}

	e_data = &_e_data;
    }

    if (armor_crypto) {
	if (r->fast.flags.requested_hidden_names) {
	    error_client = NULL;
	    error_server = NULL;
	}
	csec = NULL;
	cusec = NULL;
    }

    ret = krb5_mk_error(r->context,
			outer_error,
			r->e_text,
			(e_data->length ? e_data : NULL),
			error_client,
			error_server,
			csec,
			cusec,
			error_msg);
    krb5_data_free(&_e_data);

    if (ret)
        kdc_log(r->context, r->config, 1,
                "Failed to make encode KRB-ERROR: %d", ret);

    return ret;
}

static krb5_error_code
fast_unwrap_request(astgs_request_t r,
		    krb5_ticket *tgs_ticket,
		    krb5_auth_context tgs_ac)
{
    krb5_principal armor_server_principal = NULL;
    char *armor_client_principal_name = NULL;
    char *armor_server_principal_name = NULL;
    PA_FX_FAST_REQUEST fxreq;
    krb5_auth_context ac = NULL;
    krb5_ticket *ticket = NULL;
    krb5_flags ap_req_options;
    krb5_keyblock armorkey;
    krb5_keyblock explicit_armorkey;
    krb5_error_code ret;
    krb5_ap_req ap_req;
    KrbFastReq fastreq;
    const PA_DATA *pa;
    krb5_data data;
    size_t len;
    int i = 0;

    memset(&fxreq, 0, sizeof(fxreq));
    memset(&fastreq, 0, sizeof(fastreq));

    pa = _kdc_find_padata(&r->req, &i, KRB5_PADATA_FX_FAST);
    if (pa == NULL) {
	if (tgs_ac && r->fast_asserted) {
	    kdc_log(r->context, r->config, 1,
		    "Client asserted FAST but did not include FX-FAST pa-data");
	    ret = KRB5KRB_AP_ERR_MODIFIED;
	    goto out;
	}

	kdc_log(r->context, r->config, 10, "Not a FAST request");
	return 0;
    }

    ret = decode_PA_FX_FAST_REQUEST(pa->padata_value.data,
				    pa->padata_value.length,
				    &fxreq,
				    &len);
    if (ret) {
	kdc_log(r->context, r->config, 4,
		"Failed to decode PA-FX-FAST-REQUEST: %d", ret);
	goto out;
    }

    if (fxreq.element != choice_PA_FX_FAST_REQUEST_armored_data) {
	kdc_log(r->context, r->config, 4,
		"PA-FX-FAST-REQUEST contains unknown type: %d",
		(int)fxreq.element);
	ret = KRB5KDC_ERR_PREAUTH_FAILED;
	goto out;
    }

    /*
     * If check for armor data or it's not a TGS-REQ with implicit
     * armor.
     */
    if (fxreq.u.armored_data.armor == NULL && tgs_ac == NULL) {
	kdc_log(r->context, r->config, 4,
		"AS-REQ armor missing");
	ret = KRB5KDC_ERR_PREAUTH_FAILED;
	goto out;
    }

    r->explicit_armor_present = fxreq.u.armored_data.armor != NULL && tgs_ac != NULL;

    /*
     *
     */
    if (fxreq.u.armored_data.armor != NULL) {
	krb5uint32 kvno;
	krb5uint32 *kvno_ptr = NULL;

	if (fxreq.u.armored_data.armor->armor_type != 1) {
	    kdc_log(r->context, r->config, 4,
		    "Incorrect AS-REQ armor type");
	    ret = KRB5KDC_ERR_PREAUTH_FAILED;
	    goto out;
	}

	ret = krb5_decode_ap_req(r->context,
				 &fxreq.u.armored_data.armor->armor_value,
				 &ap_req);
	if(ret) {
	    kdc_log(r->context, r->config, 4, "Failed to decode AP-REQ");
	    goto out;
	}

	/* Save that principal that was in the request */
	ret = _krb5_principalname2krb5_principal(r->context,
						 &armor_server_principal,
						 ap_req.ticket.sname,
						 ap_req.ticket.realm);
	if (ret) {
	    free_AP_REQ(&ap_req);
	    goto out;
	}

	if (ap_req.ticket.enc_part.kvno != NULL) {
	    kvno = *ap_req.ticket.enc_part.kvno;
	    kvno_ptr = &kvno;
	}

	ret = _kdc_db_fetch(r->context, r->config, armor_server_principal,
			    HDB_F_GET_KRBTGT | HDB_F_DELAY_NEW_KEYS,
			    kvno_ptr,
			    &r->armor_serverdb, &r->armor_server);
	if(ret == HDB_ERR_NOT_FOUND_HERE) {
	    free_AP_REQ(&ap_req);
	    kdc_log(r->context, r->config, 5,
		    "Armor key does not have secrets at this KDC, "
		    "need to proxy");
	    goto out;
	} else if (ret) {
	    free_AP_REQ(&ap_req);
	    ret = KRB5KDC_ERR_S_PRINCIPAL_UNKNOWN;
	    goto out;
	}

	ret = hdb_enctype2key(r->context, r->armor_server, NULL,
			      ap_req.ticket.enc_part.etype,
			      &r->armor_key);
	if (ret) {
	    free_AP_REQ(&ap_req);
	    goto out;
	}

	ret = krb5_verify_ap_req2(r->context, &ac,
				  &ap_req,
				  armor_server_principal,
				  &r->armor_key->key,
				  0,
				  &ap_req_options,
				  &r->armor_ticket,
				  KRB5_KU_AP_REQ_AUTH);
	free_AP_REQ(&ap_req);
	if (ret)
	    goto out;

	ret = krb5_unparse_name(r->context, armor_server_principal,
				&armor_server_principal_name);
	if (ret)
	    goto out;

	/* FIXME krb5_verify_ap_req2() also checks this */
	ret = _kdc_verify_flags(r->context, r->config,
				&r->armor_ticket->ticket,
				armor_server_principal_name);
	if (ret) {
	    kdc_audit_addreason((kdc_request_t)r,
				"Armor TGT expired or invalid");
	    goto out;
	}
	ticket = r->armor_ticket;
    } else {
	heim_assert(tgs_ticket != NULL, "TGS authentication context without ticket");
	ac = tgs_ac;
	ticket = tgs_ticket;
    }

    (void) krb5_unparse_name(r->context, ticket->client, &armor_client_principal_name);
    kdc_audit_addkv((kdc_request_t)r, 0, "armor_client_name", "%s",
		    armor_client_principal_name ?
			armor_client_principal_name :
			"<out of memory>");

    if (ac->remote_subkey == NULL) {
	krb5_auth_con_free(r->context, ac);
	kdc_log(r->context, r->config, 2,
		"FAST AP-REQ remote subkey missing");
	ret = KRB5KDC_ERR_PREAUTH_FAILED;
	goto out;
    }

    r->fast.flags.kdc_verified =
	!_kdc_is_anonymous_pkinit(r->context, ticket->client);

    ret = _krb5_fast_armor_key(r->context,
			       ac->remote_subkey,
			       &ticket->ticket.key,
			       &armorkey,
			       r->explicit_armor_present ? NULL : &r->armor_crypto);
    if (ret)
	goto out;

    if (r->explicit_armor_present) {
	ret = _krb5_fast_explicit_armor_key(r->context,
					    &armorkey,
					    tgs_ac->remote_subkey,
					    &explicit_armorkey,
					    &r->armor_crypto);
	if (ret)
	    goto out;

	krb5_free_keyblock_contents(r->context, &explicit_armorkey);
    }

    krb5_free_keyblock_contents(r->context, &armorkey);

    ret = krb5_decrypt_EncryptedData(r->context, r->armor_crypto,
				     KRB5_KU_FAST_ENC,
				     &fxreq.u.armored_data.enc_fast_req,
				     &data);
    if (ret) {
	kdc_log(r->context, r->config, 2,
		"Failed to decrypt FAST request");
	goto out;
    }

    ret = decode_KrbFastReq(data.data, data.length, &fastreq, NULL);
    krb5_data_free(&data);
    if (ret)
	goto out;

    /*
     * verify req-checksum of the outer body
     */
    if (tgs_ac) {
	/*
	 * -- For TGS, contains the checksum performed over the type
	 * -- AP-REQ in the PA-TGS-REQ padata.
	 */
	i = 0;
	pa = _kdc_find_padata(&r->req, &i, KRB5_PADATA_TGS_REQ);
	if (pa == NULL) {
	    kdc_log(r->context, r->config, 4,
		    "FAST TGS request missing TGS-REQ padata");
	    ret = KRB5KRB_ERR_GENERIC;
	    goto out;
	}

	ret = _kdc_verify_checksum(r->context, r->armor_crypto,
				   KRB5_KU_FAST_REQ_CHKSUM,
				   &pa->padata_value,
				   &fxreq.u.armored_data.req_checksum);
	if (ret) {
	    kdc_log(r->context, r->config, 2,
		    "Bad checksum in FAST TGS request");
	    goto out;
	}
    } else {
	/*
	 * -- For AS, contains the checksum performed over the type
	 * -- KDC-REQ-BODY for the req-body field of the KDC-REQ
	 * -- structure;
	 */
	ret = _kdc_verify_checksum(r->context, r->armor_crypto,
				   KRB5_KU_FAST_REQ_CHKSUM,
				   &r->req.req_body._save,
				   &fxreq.u.armored_data.req_checksum);
	if (ret) {
	    kdc_log(r->context, r->config, 2,
		    "Bad checksum in FAST AS request");
	    goto out;
	}
    }

    /*
     * check for unsupported mandatory options
     */
    if (FastOptions2int(fastreq.fast_options) & 0xfffc) {
	kdc_log(r->context, r->config, 2,
		"FAST unsupported mandatory option set");
	ret = KRB5_KDC_ERR_UNKNOWN_CRITICAL_FAST_OPTIONS;
	goto out;
    }

    r->fast.flags.requested_hidden_names = fastreq.fast_options.hide_client_names;

    /* KDC MUST ignore outer pa data preauth-14 - 6.5.5 */
    if (r->req.padata)
	free_METHOD_DATA(r->req.padata);
    else
	ALLOC(r->req.padata);

    ret = copy_METHOD_DATA(&fastreq.padata, r->req.padata);
    if (ret)
	goto out;

    free_KDC_REQ_BODY(&r->req.req_body);
    ret = copy_KDC_REQ_BODY(&fastreq.req_body, &r->req.req_body);
    if (ret)
	goto out;

    kdc_log(r->context, r->config, 5, "Client selected FAST");

 out:
    if (ac && ac != tgs_ac)
	krb5_auth_con_free(r->context, ac);

    krb5_free_principal(r->context, armor_server_principal);
    krb5_xfree(armor_client_principal_name);
    krb5_xfree(armor_server_principal_name);

    free_KrbFastReq(&fastreq);
    free_PA_FX_FAST_REQUEST(&fxreq);

    return ret;
}

/*
 *
 */
krb5_error_code
_kdc_fast_unwrap_request(astgs_request_t r,
			 krb5_ticket *tgs_ticket,
			 krb5_auth_context tgs_ac)
{
    krb5_error_code ret;
    const PA_DATA *pa;
    int i = 0;

    if (!r->config->enable_fast)
	return 0;

    ret = fast_unwrap_request(r, tgs_ticket, tgs_ac);
    if (ret)
	return ret;

    if (r->config->enable_fast_cookie) {
	/*
	 * FX-COOKIE can be used outside of FAST, e.g. SRP or GSS.
	 */
	pa = _kdc_find_padata(&r->req, &i, KRB5_PADATA_FX_COOKIE);
	if (pa) {
	    krb5_const_principal ticket_client = NULL;

	    if (tgs_ticket)
		ticket_client = tgs_ticket->client;

	    ret = fast_parse_cookie(r, ticket_client, pa);
	}
    }

    return ret;
}

/*
 * Strengthen reply key by mixing with a random key that is
 * protected by FAST.
 */
krb5_error_code
_kdc_fast_strengthen_reply_key(astgs_request_t r)
{
    if (r->armor_crypto) {
	krb5_keyblock new_reply_key;
	krb5_error_code ret;

	kdc_log(r->context, r->config, 5,
		"FAST strengthen reply key with strengthen-key");

	heim_assert(r->reply_key.keytype != KRB5_ENCTYPE_NULL, "NULL reply key enctype");

	ret = krb5_generate_random_keyblock(r->context, r->reply_key.keytype,
					    &r->strengthen_key);
	if (ret) {
	    kdc_log(r->context, r->config, 0, "failed to prepare random keyblock");
	    return ret;
	}

	ret = _krb5_fast_cf2(r->context,
			     &r->strengthen_key, "strengthenkey",
			     &r->reply_key, "replykey",
			     &new_reply_key, NULL);
	if (ret)
	    return ret;

	krb5_free_keyblock_contents(r->context, &r->reply_key);
	r->reply_key = new_reply_key;
    }

    return 0;
}

/*
 * Zero and free KDCFastState
 */
void
_kdc_free_fast_state(KDCFastState *state)
{
    size_t i;

    for (i = 0; i < state->fast_state.len; i++) {
	PA_DATA *pa = &state->fast_state.val[i];

	if (pa->padata_value.data)
	    memset_s(pa->padata_value.data, 0,
		     pa->padata_value.length, pa->padata_value.length);
    }
    free_KDCFastState(state);
}

krb5_error_code
_kdc_fast_check_armor_pac(astgs_request_t r, int flags)
{
    krb5_error_code ret;
    krb5_boolean ad_kdc_issued = FALSE;
    krb5_pac mspac = NULL;
    krb5_principal armor_client_principal = NULL;
    HDB *armor_db;
    hdb_entry *armor_client = NULL;
    char *armor_client_principal_name = NULL;

    flags |= HDB_F_ARMOR_PRINCIPAL;
    if (_kdc_synthetic_princ_used_p(r->context, r->armor_ticket))
	flags |= HDB_F_SYNTHETIC_OK;
    if (r->req.req_body.kdc_options.canonicalize)
	flags |= HDB_F_CANON;

    if (krb5_principal_is_krbtgt(r->context, r->armor_server->principal) &&
	!krb5_principal_is_root_krbtgt(r->context, r->armor_server->principal)) {
	flags |= HDB_F_CROSS_REALM_PRINCIPAL;
    }

    ret = _krb5_principalname2krb5_principal(r->context,
					     &armor_client_principal,
					     r->armor_ticket->ticket.cname,
					     r->armor_ticket->ticket.crealm);
    if (ret)
	goto out;

    ret = krb5_unparse_name(r->context, armor_client_principal,
			    &armor_client_principal_name);
    if (ret)
	goto out;

    ret = _kdc_db_fetch_client(r->context, r->config, flags,
			       armor_client_principal, armor_client_principal_name,
			       r->req.req_body.realm, &armor_db, &armor_client);
    if (ret)
	goto out;

    ret = kdc_check_flags(r, FALSE, armor_client, NULL);
    if (ret)
	goto out;

    ret = _kdc_check_pac(r, armor_client_principal, NULL,
			 armor_client, r->armor_server,
			 r->armor_server, r->armor_server,
			 &r->armor_key->key, &r->armor_key->key,
			 &r->armor_ticket->ticket, &ad_kdc_issued, &mspac, NULL, NULL);
    if (ret) {
	const char *msg = krb5_get_error_message(r->context, ret);

	kdc_log(r->context, r->config, 4,
		"Verify armor PAC (%s) failed for %s (%s) from %s with %s (%s)",
		armor_client_principal_name, r->cname, r->sname,
		r->from, msg, mspac ? "Ticket unsigned" : "No PAC");

	krb5_free_error_message(r->context, msg);

	goto out;
    }

    r->armor_clientdb = armor_db;
    armor_db = NULL;

    r->armor_client_principal = armor_client_principal;
    armor_client_principal = NULL;

    r->armor_client = armor_client;
    armor_client = NULL;

    r->armor_pac = mspac;
    mspac = NULL;

out:
    krb5_xfree(armor_client_principal_name);
    if (armor_client)
	_kdc_free_ent(r->context, armor_db, armor_client);
    krb5_free_principal(r->context, armor_client_principal);
    krb5_pac_free(r->context, mspac);

    return ret;
}
