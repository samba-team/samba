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
key_proc (krb5_context context,
	  krb5_keytype type,
	  krb5_data *salt,
	  krb5_const_pointer keyseed,
	  krb5_keyblock **key)
{
    *key = (krb5_keyblock *)keyseed;
    return 0;
}

static krb5_error_code
make_pa_tgs_req(krb5_context context, 
		krb5_ccache id, 
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

    unsigned char buf[1024];
    size_t len;

    
    memset(&req, 0, sizeof(req));
    req.pvno = 5;
    req.msg_type = krb_tgs_req;
    krb5_init_etype(context, 
		    &req.req_body.etype.len, 
		    &req.req_body.etype.val, 
		    NULL);
    req.req_body.addresses = addresses;
    req.req_body.kdc_options = flags.b;
    copy_Realm(&in_creds->server->realm, &req.req_body.realm);
    req.req_body.sname = malloc(sizeof(*req.req_body.sname));
    copy_PrincipalName(&in_creds->server->name, req.req_body.sname);
    req.req_body.till = in_creds->times.endtime;
    krb5_generate_random_block(&req.req_body.nonce, 
			       sizeof(req.req_body.nonce));
    if(second_ticket){
	ALLOC(req.req_body.additional_tickets, 1);
	req.req_body.additional_tickets->len = 1;
	ALLOC(req.req_body.additional_tickets->val, 1);
	copy_Ticket(second_ticket, req.req_body.additional_tickets->val); 
    }
    req.req_body.enc_authorization_data = NULL;
    
    req.padata = malloc(sizeof(*req.padata));
    req.padata->len = 1;
    req.padata->val = malloc(sizeof(*req.padata->val));

    {
	krb5_creds tmp_cred;
	memset(&tmp_cred, 0, sizeof(tmp_cred));
	ret = krb5_build_principal(context, 
				   &tmp_cred.server,
				   strlen(req.req_body.realm),
				   req.req_body.realm,
				   "krbtgt",
				   req.req_body.realm,
				   NULL);
	if(ret)
	    return ret;
	ret = krb5_get_credentials(context,
				   0, /* CACHE_ONLY */
				   id,
				   &tmp_cred,
				   &krbtgt);
	krb5_free_principal(context, tmp_cred.server);
	if(ret)
	    return ret;
    }

    ret = make_pa_tgs_req(context, id, &req.req_body, 
			  req.padata->val, krbtgt);
    if(ret)
	goto out;
    
    encode_TGS_REQ  (buf + sizeof (buf) - 1, sizeof(buf), &req, &enc.length);
    enc.data = buf + sizeof(buf) - enc.length;
    
    /*
     * Send and receive
     */

    ret = krb5_sendto_kdc (context, &enc, &in_creds->server->realm, &resp);
    if(ret)
	goto out;

    memset(&rep, 0, sizeof(rep));
    if(decode_TGS_REP(resp.data, resp.length, &rep.part1, &len) == 0){
	ret = extract_ticket(context, &rep, *out_creds,
			     &krbtgt->session,
			     NULL,
			     &krbtgt->addresses,
			     NULL,
			     NULL);
	krb5_free_creds(context, krbtgt);
	free(krbtgt);
	if(ret == 0 && rep.part2.nonce != req.req_body.nonce)
	    ret = KRB5KRB_AP_ERR_MODIFIED;
	krb5_free_kdc_rep(context, &rep);
    }else if(decode_KRB_ERROR(resp.data, resp.length, &error, &len) == 0){
#if 0
	krb5_principal princ;
	char *name;
	principalname2krb5_principal(&princ, error.sname, error.realm);
	krb5_unparse_name(context, princ, &name);
	fprintf(stderr, "Error: %s ", name);
	if(error.e_text)
	    fprintf(stderr, "%s", *error.e_text);
	else
	    fprintf(stderr, "%s", 
		    krb5_get_err_text(context, error.error_code));
	fprintf(stderr, " (code %d)\n", error.error_code);
#endif
	ret = error.error_code + KRB5KDC_ERR_NONE;
	free_KRB_ERROR(&error);
    }else
	ret = KRB5KRB_AP_ERR_MSG_TYPE;
    krb5_data_free(&resp);
out:
    /* Don't free this part, it's from the caller */
    req.req_body.addresses = NULL;
    free_TGS_REQ(&req);
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
