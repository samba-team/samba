/*
 * Copyright (c) 1997, 1998 Kungliga Tekniska Högskolan
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
		krb5_auth_context ac,
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
    {
	Ticket ticket;
	ret = decode_Ticket(creds->ticket.data, creds->ticket.length, 
			    &ticket, &len);
	if(ret)
	    return ret;
	/*
	 * If we get a ticket encrypted with DES-CBC-CRC, it's
	 * probably an old DCE secd and then the usual heuristics of
	 * using the best algorithm (in this case RSA-MD5 and
	 * DES-CBC-MD5) will not work.
	 */
	if(ticket.enc_part.etype == ETYPE_DES_CBC_CRC) {
	    krb5_auth_setcksumtype(context, ac, CKSUMTYPE_RSA_MD4);
	    krb5_auth_setenctype(context, ac, ETYPE_DES_CBC_CRC);
	}
	free_Ticket(&ticket);
	    
	
	ret = krb5_mk_req_extended(context, &ac, 0, &in_data, creds, 
				   &padata->padata_value);

    }
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
	      krb5_keyblock **subkey,
	      TGS_REQ *t)
{
    krb5_error_code ret;

    memset(t, 0, sizeof(*t));
    t->pvno = 5;
    t->msg_type = krb_tgs_req;
    if (in_creds->session.keytype) {
	krb5_enctype *foo;

	ret = krb5_keytype_to_etypes(context,
				     in_creds->session.keytype,
				     &foo);
	if (ret)
	    return ret;

	ret = krb5_init_etype(context,
			      &t->req_body.etype.len,
			      &t->req_body.etype.val,
			      foo);
	free (foo);
    } else {
	ret = krb5_init_etype(context, 
			      &t->req_body.etype.len, 
			      &t->req_body.etype.val, 
			      NULL);
    }
    if (ret)
	goto fail;
    t->req_body.addresses = addresses;
    t->req_body.kdc_options = flags.b;
    ret = copy_Realm(&in_creds->server->realm, &t->req_body.realm);
    if (ret)
	goto fail;
    ALLOC(t->req_body.sname, 1);
    if (t->req_body.sname == NULL) {
	ret = ENOMEM;
	goto fail;
    }
    ret = copy_PrincipalName(&in_creds->server->name, t->req_body.sname);
    if (ret)
	goto fail;

    /* req_body.till should be NULL if there is no endtime specified,
       but old MIT code (like DCE secd) doesn't like that */
    ALLOC(t->req_body.till, 1);
    if(t->req_body.till == NULL){
	ret = ENOMEM;
	goto fail;
    }
    *t->req_body.till = in_creds->times.endtime;
    
    t->req_body.nonce = nonce;
    if(second_ticket){
	ALLOC(t->req_body.additional_tickets, 1);
	if (t->req_body.additional_tickets == NULL) {
	    ret = ENOMEM;
	    goto fail;
	}
	ALLOC_SEQ(t->req_body.additional_tickets, 1);
	if (t->req_body.additional_tickets->val == NULL) {
	    ret = ENOMEM;
	    goto fail;
	}
	ret = copy_Ticket(second_ticket, t->req_body.additional_tickets->val); 
	if (ret)
	    goto fail;
    }
    ALLOC(t->padata, 1);
    if (t->padata == NULL) {
	ret = ENOMEM;
	goto fail;
    }
    ALLOC_SEQ(t->padata, 1);
    if (t->padata->val == NULL) {
	ret = ENOMEM;
	goto fail;
    }

    {
	krb5_auth_context ac;
	krb5_keyblock *key;
	ret = krb5_auth_con_init(context, &ac);
	if(ret)
	    return ret;
	ret = krb5_generate_subkey (context, &krbtgt->session, &key);
	ret = krb5_auth_con_setlocalsubkey(context, ac, key);
	if(ret == ENOMEM)
	    /* XXX */;

	if(in_creds->authdata.len){
	    size_t len;
	    unsigned char *buf;
	    krb5_enctype etype;
	    len = length_AuthorizationData(&in_creds->authdata);
	    buf = malloc(len);
	    ret = encode_AuthorizationData(buf + len - 1, len, &in_creds->authdata, &len);
	    ALLOC(t->req_body.enc_authorization_data, 1);
	    krb5_keytype_to_etype(context, key->keytype, &etype);
	    krb5_encrypt_EncryptedData(context, buf, len, etype, 0, 
				       key, t->req_body.enc_authorization_data);
	}else
	    t->req_body.enc_authorization_data = NULL;
    

	ret = make_pa_tgs_req(context,
			      ac,
			      &t->req_body, 
			      t->padata->val,
			      krbtgt);
	if(ret)
	    goto fail;
	*subkey = key;

	krb5_auth_con_free(context, ac);
    }
    return 0;
fail:
    free_TGS_REQ (t);
    return ret;
}

static krb5_error_code
get_krbtgt(krb5_context context,
	   krb5_ccache  id,
	   krb5_realm realm,
	   krb5_creds **cred)
{
    krb5_error_code ret;
    krb5_creds tmp_cred;

    memset(&tmp_cred, 0, sizeof(tmp_cred));

    ret = krb5_make_principal(context, 
			      &tmp_cred.server,
			      realm,
			      "krbtgt",
			      realm,
			      NULL);
    if(ret)
	return ret;
    ret = krb5_get_credentials(context,
			       KRB5_GC_CACHED,
			       id,
			       &tmp_cred,
			       cred);
    krb5_free_principal(context, tmp_cred.server);
    if(ret)
	return ret;
    return 0;
}

/* DCE compatible decrypt proc */
static krb5_error_code
decrypt_tkt_with_subkey (krb5_context context,
			 const krb5_keyblock *key,
			 krb5_const_pointer subkey,
			 krb5_kdc_rep *dec_rep)
{
    krb5_error_code ret;
    krb5_data data;
    size_t size;
    krb5_data save;
    
    ret = krb5_data_copy(&save, dec_rep->kdc_rep.enc_part.cipher.data,
			 dec_rep->kdc_rep.enc_part.cipher.length);
    if(ret)
	return ret;
    
    ret = krb5_decrypt (context,
			dec_rep->kdc_rep.enc_part.cipher.data,
			dec_rep->kdc_rep.enc_part.cipher.length,
			dec_rep->kdc_rep.enc_part.etype,
			key,
			&data);
    if(ret && subkey){
	ret = krb5_decrypt (context, save.data, save.length,
			    dec_rep->kdc_rep.enc_part.etype,
			    (krb5_keyblock*)subkey, /* local subkey */
			    &data);
    }
    krb5_data_free(&save);
    if (ret)
	return ret;

    ret = krb5_decode_EncASRepPart(context,
				   data.data,
				   data.length,
				   &dec_rep->enc_part, 
				   &size);
    if (ret)
	ret = krb5_decode_EncTGSRepPart(context,
					data.data,
					data.length,
					&dec_rep->enc_part, 
					&size);
    krb5_data_free (&data);
    return ret;
}

static krb5_error_code
get_cred_kdc(krb5_context context, 
	     krb5_ccache id, 
	     krb5_kdc_flags flags,
	     krb5_addresses *addresses, 
	     krb5_creds *in_creds, 
	     krb5_creds *krbtgt,
	     krb5_creds **out_creds)
{
    TGS_REQ req;
    krb5_data enc;
    krb5_data resp;
    krb5_kdc_rep rep;
    KRB_ERROR error;
    krb5_error_code ret;
    unsigned nonce;
    unsigned char buf[1024];
    krb5_keyblock *subkey = NULL;
    size_t len;
    Ticket second_ticket;
    
    krb5_generate_random_block(&nonce, sizeof(nonce));
    nonce &= 0xffffffff;
    
    if(flags.b.enc_tkt_in_skey){
	ret = decode_Ticket(in_creds->second_ticket.data, 
			    in_creds->second_ticket.length, 
			    &second_ticket, &len);
	if(ret)
	    return ret;
    }

    ret = init_tgs_req (context,
			id,
			addresses,
			flags,
			flags.b.enc_tkt_in_skey ? &second_ticket : NULL,
			in_creds,
			krbtgt,
			nonce,
			&subkey, 
			&req);
    if(flags.b.enc_tkt_in_skey)
	free_Ticket(&second_ticket);
    if (ret)
	goto out;

    ret = encode_TGS_REQ  (buf + sizeof (buf) - 1, sizeof(buf),
			   &req, &enc.length);
    /* don't free addresses */
    req.req_body.addresses = NULL;
    free_TGS_REQ(&req);

    enc.data = buf + sizeof(buf) - enc.length;
    if (ret)
	goto out;
    
    /*
     * Send and receive
     */

    ret = krb5_sendto_kdc (context, &enc, 
			   &krbtgt->server->name.name_string.val[1], &resp);
    if(ret)
	goto out;

    memset(&rep, 0, sizeof(rep));
    if(decode_TGS_REP(resp.data, resp.length, &rep.kdc_rep, &len) == 0){
	ret = krb5_copy_principal(context, 
				  in_creds->client, 
				  &(*out_creds)->client);
	if(ret)
	    goto out;
	ret = krb5_copy_principal(context, 
				  in_creds->server, 
				  &(*out_creds)->server);
	if(ret)
	    goto out;
	/* this should go someplace else */
	(*out_creds)->times.endtime = in_creds->times.endtime;

	ret = _krb5_extract_ticket(context,
				   &rep,
				   *out_creds,
				   &krbtgt->session,
				   NULL,
				   &krbtgt->addresses,
				   nonce,
				   TRUE,
				   decrypt_tkt_with_subkey,
				   subkey);
	krb5_free_kdc_rep(context, &rep);
	if (ret)
	    goto out;
    }else if(krb5_rd_error(context, &resp, &error) == 0){
	ret = error.error_code;
	free_KRB_ERROR(&error);
    }else if(resp.data && ((char*)resp.data)[0] == 4)
	ret = KRB5KRB_AP_ERR_V4_REPLY;
    else
	ret = KRB5KRB_AP_ERR_MSG_TYPE;
    krb5_data_free(&resp);
out:
    if(subkey){
	krb5_free_keyblock_contents(context, subkey);
	free(subkey);
    }
    return ret;
    
}

/* same as above, just get local addresses first */

static krb5_error_code
get_cred_kdc_la(krb5_context context, krb5_ccache id, krb5_kdc_flags flags, 
		krb5_creds *in_creds, krb5_creds *krbtgt, 
		krb5_creds **out_creds)
{
    krb5_error_code ret;
    krb5_addresses addresses;
    
    krb5_get_all_client_addrs(&addresses);
    ret = get_cred_kdc(context, id, flags, &addresses, 
		       in_creds, krbtgt, out_creds);
    krb5_free_addresses(context, &addresses);
    return ret;
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
    krb5_error_code ret;
    krb5_creds *krbtgt;
    ret = get_krbtgt (context,
		      id,
		      in_creds->server->realm,
		      &krbtgt);
    ret = get_cred_kdc(context, id, flags, addresses, 
		       in_creds, krbtgt, out_creds);
    krb5_free_creds (context, krbtgt);
    return ret;
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
    mcreds.server = server;
    ret = krb5_cc_retrieve_cred(context, id, KRB5_TC_DONT_MATCH_REALM, 
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
    return KRB5_CC_NOTFOUND;
}

static krb5_error_code
add_cred(krb5_context context, krb5_creds ***tgts, krb5_creds *tkt)
{
    int i;
    krb5_error_code ret;
    krb5_creds **tmp = *tgts;
    for(i = 0; tmp && tmp[i]; i++); /* XXX */
    tmp = realloc(tmp, (i+2)*sizeof(*tmp));
    if(tmp == NULL)
	return ENOMEM;
    *tgts = tmp;
    ret = krb5_copy_creds(context, tkt, &tmp[i]);
    tmp[i+1] = NULL;
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
get_cred_from_kdc_flags(krb5_context context,
			krb5_kdc_flags flags,
			krb5_ccache ccache,
			krb5_creds *in_creds,
			krb5_creds **out_creds,
			krb5_creds ***ret_tgts)
{
    krb5_error_code ret;
    krb5_creds *tgt, tmp_creds;
    krb5_realm client_realm, server_realm;

    *out_creds = calloc(1, sizeof(**out_creds));
    if (*out_creds == NULL)
	return ENOMEM;

    client_realm = *krb5_princ_realm(context, in_creds->client);
    server_realm = *krb5_princ_realm(context, in_creds->server);
    memset(&tmp_creds, 0, sizeof(tmp_creds));
    ret = krb5_copy_principal(context, in_creds->client, &tmp_creds.client);
    if(ret)
	return ret;
    ret = krb5_make_principal(context,
			      &tmp_creds.server,
			      client_realm,
			      "krbtgt",
			      server_realm,
			      NULL);
    if(ret){
	krb5_free_principal(context, tmp_creds.client);
	return ret;
    }
    {
	krb5_creds tgts;
	/* XXX try krb5_cc_retrieve_cred first? */
	ret = find_cred(context, ccache, tmp_creds.server, 
			*ret_tgts, &tgts);
	if(ret == 0){
	    ret = get_cred_kdc_la(context, ccache, flags, 
				  in_creds, &tgts, out_creds);
	    krb5_free_creds_contents(context, &tgts);
	    krb5_free_principal(context, tmp_creds.server);
	    krb5_free_principal(context, tmp_creds.client);
	    return ret;
	}
    }
    if(krb5_realm_compare(context, in_creds->client, in_creds->server))
	return KRB5_CC_NOTFOUND;
    /* XXX this can loop forever */
    while(1){
	general_string tgt_inst;
	krb5_kdc_flags f;
	f.i = 0;
	ret = get_cred_from_kdc_flags(context, flags, ccache, &tmp_creds, 
				      &tgt, ret_tgts);
	if(ret) return ret;
	ret = add_cred(context, ret_tgts, tgt);
	if(ret)
	    return ret;
	tgt_inst = tgt->server->name.name_string.val[1];
	if(strcmp(tgt_inst, server_realm) == 0)
	    break;
	krb5_free_principal(context, tmp_creds.server);
	ret = krb5_make_principal(context, &tmp_creds.server, 
				  tgt_inst, "krbtgt", server_realm, NULL);
	if(ret) return ret;
	ret = krb5_free_creds(context, tgt);
	if(ret) return ret;
    }
	
    krb5_free_principal(context, tmp_creds.server);
    krb5_free_principal(context, tmp_creds.client);
    ret = get_cred_kdc_la(context, ccache, flags, in_creds, tgt, out_creds);
    krb5_free_creds(context, tgt);
    return ret;
}

krb5_error_code
krb5_get_cred_from_kdc(krb5_context context,
		       krb5_ccache ccache,
		       krb5_creds *in_creds,
		       krb5_creds **out_creds,
		       krb5_creds ***ret_tgts)
{
    krb5_kdc_flags f;
    f.i = 0;
    return get_cred_from_kdc_flags(context, f, ccache, 
				   in_creds, out_creds, ret_tgts);
}
     

krb5_error_code
krb5_get_credentials_with_flags(krb5_context context,
				krb5_flags options,
				krb5_kdc_flags flags,
				krb5_ccache ccache,
				krb5_creds *in_creds,
				krb5_creds **out_creds)
{
    krb5_error_code ret;
    krb5_creds **tgts;
    int i;
    
    *out_creds = calloc(1, sizeof(**out_creds));
    if (*out_creds == NULL)
	return ENOMEM;

    ret = krb5_cc_retrieve_cred(context,
				ccache,
				in_creds->session.keytype ?
				KRB5_TC_MATCH_KEYTYPE : 0,
				in_creds, *out_creds);
    if(ret == 0)
	return 0;
    free(*out_creds);
    if(ret != KRB5_CC_END)
	return ret;
    if(options & KRB5_GC_CACHED)
	return KRB5_CC_NOTFOUND;
    if(options & KRB5_GC_USER_USER)
	flags.b.enc_tkt_in_skey = 1;
    tgts = NULL;
    ret = get_cred_from_kdc_flags(context, flags, ccache, 
				  in_creds, out_creds, &tgts);
    for(i = 0; tgts && tgts[i]; i++){
	krb5_cc_store_cred(context, ccache, tgts[i]);
	krb5_free_creds(context, tgts[i]);
    }
    free(tgts);
    if(ret == 0 && flags.b.enc_tkt_in_skey == 0)
	krb5_cc_store_cred(context, ccache, *out_creds);
    return ret;
}

krb5_error_code
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
