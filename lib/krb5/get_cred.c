/*
 * Copyright (c) 1997 Kungliga Tekniska Högskolan
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
 * 3. All advertising materials mentioning features or use of this software 
 *    must display the following acknowledgement: 
 *      This product includes software developed by Kungliga Tekniska 
 *      Högskolan and its contributors. 
 *
 * 4. Neither the name of the Institute nor the names of its contributors 
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

#include <krb5_locl.h>

RCSID("$Id$");

static krb5_error_code
make_pa_tgs_req(krb5_context context, 
		KDC_REQ_BODY *body,
		PA_DATA *padata,
		krb5_creds *creds)
{
    unsigned char buf[1024];
    size_t len;
    krb5_data in_data;
    krb5_error_code ret;

    encode_KDC_REQ_BODY(buf + sizeof(buf) - 1, sizeof(buf),
			body, &len);
    in_data.length = len;
    in_data.data = buf + sizeof(buf) - len;
    ret = krb5_mk_req_extended(context, NULL, 0, &in_data, creds, 
			       &padata->padata_value);
    if(ret)
	return ret;
    padata->padata_type = pa_tgs_req;
    return 0;
}

static krb5_error_code
init_tgs_req (krb5_context context,
	      krb5_ccache ccache,
	      krb5_addresses *addresses,
	      krb5_kdc_flags flags,
	      Ticket *second_ticket,
	      krb5_creds *in_creds,
	      krb5_creds *krbtgt,
	      unsigned nonce,
	      TGS_REQ *t)
{
    krb5_error_code ret;

    memset(t, 0, sizeof(*t));
    t->pvno = 5;
    t->msg_type = krb_tgs_req;
    ret = krb5_init_etype(context, 
			  &t->req_body.etype.len, 
			  &t->req_body.etype.val, 
			  NULL);
    if (ret)
	goto fail;
    t->req_body.addresses = addresses;
    t->req_body.kdc_options = flags.b;
    ret = copy_Realm(&in_creds->server->realm, &t->req_body.realm);
    if (ret)
	goto fail;
    t->req_body.sname = malloc(sizeof(*t->req_body.sname));
    if (t->req_body.sname == NULL) {
	ret = ENOMEM;
	goto fail;
    }
    ret = copy_PrincipalName(&in_creds->server->name, t->req_body.sname);
    if (ret)
	goto fail;

    t->req_body.till = in_creds->times.endtime;
    
    t->req_body.nonce = nonce;
    if(second_ticket){
	ALLOC(t->req_body.additional_tickets, 1);
	if (t->req_body.additional_tickets == NULL) {
	    ret = ENOMEM;
	    goto fail;
	}
	t->req_body.additional_tickets->len = 1;
	ALLOC(t->req_body.additional_tickets->val, 1);
	if (t->req_body.additional_tickets->val == NULL) {
	    ret = ENOMEM;
	    goto fail;
	}
	ret = copy_Ticket(second_ticket, t->req_body.additional_tickets->val); 
	if (ret)
	    goto fail;
    }
    t->req_body.enc_authorization_data = NULL;
    
    t->padata = malloc(sizeof(*t->padata));
    if (t->padata == NULL) {
	ret = ENOMEM;
	goto fail;
    }
    t->padata->len = 1;
    t->padata->val = malloc(sizeof(*t->padata->val));
    if (t->padata->val == NULL) {
	ret = ENOMEM;
	goto fail;
    }

    ret = make_pa_tgs_req(context,
			  &t->req_body, 
			  t->padata->val,
			  krbtgt);
    if(ret)
	goto fail;
    return 0;
fail:
    free_TGS_REQ (t);
    return ret;
}

static krb5_error_code
get_krbtgt(krb5_context context,
	   krb5_ccache  id,
	   krb5_realm   realm,
	   krb5_creds **cred)
{
    krb5_error_code ret;
    krb5_creds tmp_cred;

    memset(&tmp_cred, 0, sizeof(tmp_cred));
    ret = krb5_build_principal(context, 
			       &tmp_cred.server,
			       strlen(realm),
			       realm,
			       "krbtgt",
			       realm,
			       NULL);
    if(ret)
	return ret;
    ret = krb5_get_credentials(context,
			       0, /* CACHE_ONLY */
			       id,
			       &tmp_cred,
			       cred);
    krb5_free_principal(context, tmp_cred.server);
    if(ret)
	return ret;
    return 0;
}


krb5_error_code
krb5_get_kdc_cred(krb5_context context,
		  krb5_ccache id,
		  krb5_kdc_flags flags,
		  krb5_addresses *addresses,
		  Ticket  *second_ticket,
		  krb5_creds *in_creds,
		  krb5_creds **out_creds
		  )
{
    TGS_REQ req;
    krb5_data enc;
    krb5_data resp;
    krb5_kdc_rep rep;
    KRB_ERROR error;
    krb5_error_code ret;
    krb5_creds *krbtgt;
    unsigned nonce;
    unsigned char buf[1024];
    size_t len;
    
    krb5_generate_random_block(&nonce, sizeof(nonce));

    ret = get_krbtgt (context,
		      id,
		      in_creds->server->realm,
		      &krbtgt);
    if (ret)
	return ret;

    ret = init_tgs_req (context,
			id,
			addresses,
			flags,
			second_ticket,
			in_creds,
			krbtgt,
			nonce,
			&req);
    if (ret)
	goto out;

    ret = encode_TGS_REQ  (buf + sizeof (buf) - 1, sizeof(buf),
			   &req, &enc.length);
    /* Don't free this part, it's from the caller */
    req.req_body.addresses = NULL;
    free_TGS_REQ(&req);

    enc.data = buf + sizeof(buf) - enc.length;
    if (ret)
	goto out;
    
    /*
     * Send and receive
     */

    ret = krb5_sendto_kdc (context, &enc, &in_creds->server->realm, &resp);
    if(ret)
	goto out;

    memset(&rep, 0, sizeof(rep));
    if(decode_TGS_REP(resp.data, resp.length, &rep.part1, &len) == 0){
	ret = krb5_copy_creds_contents (context,
					in_creds,
					*out_creds);
	if(ret)
	    goto out;

#if 0
	krb5_copy_principal (context,
			     in_creds->client,
			     &(*out_creds)->client);

	krb5_copy_principal (context,
			     in_creds->server,
			     &(*out_creds)->server);
#endif

	ret = extract_ticket(context,
			     &rep,
			     *out_creds,
			     &krbtgt->session,
			     NULL,
			     &krbtgt->addresses,
			     nonce,
			     NULL,
			     NULL);
	krb5_free_kdc_rep(context, &rep);
	if (ret)
	    goto out;
    }else if(krb5_rd_error(context, &resp, &error) == 0){
	ret = error.error_code;
	free_KRB_ERROR(&error);
    }else
	ret = KRB5KRB_AP_ERR_MSG_TYPE;
    krb5_data_free(&resp);
out:
    krb5_free_creds (context, krbtgt);
    return ret;
}

krb5_error_code
krb5_get_credentials (krb5_context context,
		      krb5_flags options,
		      krb5_ccache ccache,
		      krb5_creds *in_creds,
		      krb5_creds **out_creds)
{
    krb5_error_code ret;
    krb5_kdc_flags flags;
    krb5_addresses addresses;

    /*
     * Check if cred found in ccache
     */

    *out_creds = malloc(sizeof(**out_creds));
    memset(*out_creds, 0, sizeof(**out_creds));

    ret = krb5_cc_retrieve_cred(context, ccache, 0, in_creds, *out_creds);

    if (ret == 0)
      return ret;
    else if (ret != KRB5_CC_END) {
      free(*out_creds);
      return ret;
    }

    krb5_get_all_client_addrs(&addresses);

    flags.i = options; /* XXX */
    ret = krb5_get_kdc_cred(context,
			    ccache,
			    flags,
			    &addresses,
			    NULL,
			    in_creds,
			    out_creds);

    krb5_free_addresses(context, &addresses);
    if(ret)
	return ret;
    return krb5_cc_store_cred (context, ccache, *out_creds);
}
