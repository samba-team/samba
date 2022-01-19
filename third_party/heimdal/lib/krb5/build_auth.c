/*
 * Copyright (c) 1997 - 2003 Kungliga Tekniska Högskolan
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

static krb5_error_code
add_auth_data(krb5_context context,
              AuthorizationData *src,
              AuthorizationData **dst)
{
    krb5_error_code ret = 0;
    size_t i;

    if (*dst == NULL &&
        (*dst = calloc(1, sizeof(**dst))) == NULL)
        return krb5_enomem(context);
    for (i = 0; ret == 0 && i < src->len; i++)
        ret = add_AuthorizationData(*dst, &src->val[i]);
    return ret;
}

static krb5_error_code
add_etypelist(krb5_context context,
	      krb5_authdata *auth_data)
{
    AuthorizationDataElement ade;
    EtypeList etypes;
    krb5_error_code ret;
    krb5_data e;
    size_t len = 0;

    ret = _krb5_init_etype(context, KRB5_PDU_NONE,
			   &etypes.len, &etypes.val,
			   NULL);
    if (ret)
	return ret;

    ASN1_MALLOC_ENCODE(EtypeList, e.data, e.length, &etypes, &len, ret);
    if (ret) {
	free_EtypeList(&etypes);
	return ret;
    }
    if(e.length != len)
	krb5_abortx(context, "internal error in ASN.1 encoder");
    free_EtypeList(&etypes);

    ade.ad_type = KRB5_AUTHDATA_GSS_API_ETYPE_NEGOTIATION;
    ade.ad_data = e;

    ret = add_AuthorizationData(auth_data, &ade);

    krb5_data_free(&e);

    return ret;
}

static krb5_error_code
add_ap_options(krb5_context context,
	       krb5_authdata *auth_data)
{
    krb5_error_code ret;
    AuthorizationDataElement ade;
    krb5_boolean require_cb;
    uint8_t ap_options[4];

    require_cb = krb5_config_get_bool_default(context, NULL, FALSE,
					      "libdefaults",
					      "client_aware_channel_bindings",
					      NULL);

    if (!require_cb)
	return 0;

    ap_options[0] = (KERB_AP_OPTIONS_CBT >> 0 ) & 0xFF;
    ap_options[1] = (KERB_AP_OPTIONS_CBT >> 8 ) & 0xFF;
    ap_options[2] = (KERB_AP_OPTIONS_CBT >> 16) & 0xFF;
    ap_options[3] = (KERB_AP_OPTIONS_CBT >> 24) & 0xFF;

    ade.ad_type = KRB5_AUTHDATA_AP_OPTIONS;
    ade.ad_data.length = sizeof(ap_options);
    ade.ad_data.data = ap_options;

    ret = add_AuthorizationData(auth_data, &ade);

    return ret;
}

static krb5_error_code
make_ap_authdata(krb5_context context,
                 krb5_authdata **auth_data)
{
    krb5_error_code ret;
    AuthorizationData ad;
    krb5_data ir;
    size_t len;

    ad.len = 0;
    ad.val = NULL;

    ret = add_etypelist(context, &ad);
    if (ret)
	return ret;

    /*
     * Windows has a bug and only looks for first occurrence of AD-IF-RELEVANT
     * in the AP authenticator when looking for AD-AP-OPTIONS. Make sure to
     * bundle it together with etypes.
     */
    ret = add_ap_options(context, &ad);
    if (ret) {
	free_AuthorizationData(&ad);
	return ret;
    }

    ASN1_MALLOC_ENCODE(AuthorizationData, ir.data, ir.length, &ad, &len, ret);
    if (ret) {
	free_AuthorizationData(&ad);
	return ret;
    }
    if(ir.length != len)
	krb5_abortx(context, "internal error in ASN.1 encoder");

    ret = _krb5_add_1auth_data(context, KRB5_AUTHDATA_IF_RELEVANT, &ir, 1,
                               auth_data);

    free_AuthorizationData(&ad);
    krb5_data_free(&ir);

    return ret;
}

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
_krb5_build_authenticator (krb5_context context,
			   krb5_auth_context auth_context,
			   krb5_enctype enctype,
			   krb5_creds *cred,
			   Checksum *cksum,
			   krb5_data *result,
			   krb5_key_usage usage)
{
    Authenticator auth;
    u_char *buf = NULL;
    size_t buf_size;
    size_t len = 0;
    krb5_error_code ret;
    krb5_crypto crypto;

    memset(&auth, 0, sizeof(auth));

    auth.authenticator_vno = 5;
    ret = copy_Realm(&cred->client->realm, &auth.crealm);
    if (ret)
	goto fail;
    ret = copy_PrincipalName(&cred->client->name, &auth.cname);
    if (ret)
	goto fail;

    krb5_us_timeofday (context, &auth.ctime, &auth.cusec);

    ret = krb5_auth_con_getlocalsubkey(context, auth_context, &auth.subkey);
    if(ret)
	goto fail;

    if (auth_context->flags & KRB5_AUTH_CONTEXT_DO_SEQUENCE) {
	if(auth_context->local_seqnumber == 0)
	    krb5_generate_seq_number (context,
				      &cred->session,
				      &auth_context->local_seqnumber);
	ALLOC(auth.seq_number, 1);
	if(auth.seq_number == NULL) {
	    ret = krb5_enomem(context);
	    goto fail;
	}
	*auth.seq_number = auth_context->local_seqnumber;
    } else
	auth.seq_number = NULL;
    auth.authorization_data = NULL;

    if (cksum) {
	ALLOC(auth.cksum, 1);
	if (auth.cksum == NULL) {
	    ret = krb5_enomem(context);
	    goto fail;
	}
	ret = copy_Checksum(cksum, auth.cksum);
	if (ret)
	    goto fail;

	if (auth.cksum->cksumtype == CKSUMTYPE_GSSAPI) {
	    /*
	     * This is not GSS-API specific, we only enable it for
	     * GSS for now
	     */
	    ret = make_ap_authdata(context, &auth.authorization_data);
	    if (ret)
		goto fail;
	}
    }

    /* Copy other authz data from auth_context */
    if (auth_context->auth_data) {
        ret = add_auth_data(context, auth_context->auth_data, &auth.authorization_data);
        if (ret)
            goto fail;
    }

    /* XXX - Copy more to auth_context? */

    auth_context->authenticator->ctime = auth.ctime;
    auth_context->authenticator->cusec = auth.cusec;

    ASN1_MALLOC_ENCODE(Authenticator, buf, buf_size, &auth, &len, ret);
    if (ret)
	goto fail;
    if(buf_size != len)
	krb5_abortx(context, "internal error in ASN.1 encoder");

    ret = krb5_crypto_init(context, &cred->session, enctype, &crypto);
    if (ret)
	goto fail;
    ret = krb5_encrypt (context,
			crypto,
			usage /* KRB5_KU_AP_REQ_AUTH */,
			buf,
			len,
			result);
    krb5_crypto_destroy(context, crypto);

    if (ret)
	goto fail;

 fail:
    free_Authenticator (&auth);
    free (buf);

    return ret;
}
