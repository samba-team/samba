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

#include "krb5_locl.h"

RCSID("$Id$");

krb5_error_code
krb5_init_etype (krb5_context context,
		 unsigned *len,
		 unsigned **val,
		 const krb5_enctype *etypes)
{
    int i;
    krb5_error_code ret;
    krb5_enctype *tmp;

    if (etypes)
	tmp = (krb5_enctype*)etypes;
    else {
	ret = krb5_get_default_in_tkt_etypes(context,
					     &tmp);
	if (ret)
	    return ret;
    }

    for (i = 0; tmp[i]; ++i)
	;
    *len = i;
    *val = malloc(i * sizeof(unsigned));
    memmove (*val,
	     tmp,
	     i * sizeof(*tmp));
    if (etypes == NULL)
	free (tmp);
    return 0;
}


static krb5_error_code
decrypt_tkt (krb5_context context,
	     const krb5_keyblock *key,
	     krb5_const_pointer decrypt_arg,
	     krb5_kdc_rep *dec_rep)
{
    krb5_error_code ret;
    krb5_data data;
    size_t size;

    ret = krb5_decrypt (context,
			dec_rep->part1.enc_part.cipher.data,
			dec_rep->part1.enc_part.cipher.length,
			dec_rep->part1.enc_part.etype,
			key,
			&data);
    if (ret)
	return ret;

    ret = decode_EncASRepPart(data.data,
			      data.length,
			      &dec_rep->part2, 
			      &size);
    if (ret)
	ret = decode_EncTGSRepPart(data.data,
				   data.length,
				   &dec_rep->part2, 
				   &size);
    krb5_data_free (&data);
    if (ret) return ret;
    return 0;
}

int
extract_ticket(krb5_context context, 
	       krb5_kdc_rep *rep, 
	       krb5_creds *creds,		
	       krb5_keyblock *key,
	       krb5_const_pointer keyseed,
	       krb5_addresses *addr,
	       krb5_decrypt_proc decrypt_proc,
	       krb5_const_pointer decryptarg)
{
    krb5_error_code err;

    principalname2krb5_principal(&creds->client, 
				 rep->part1.cname, 
				 rep->part1.crealm);
    {
	char buf[1024];
	size_t len;
	encode_Ticket(buf + sizeof(buf) - 1, sizeof(buf), 
			    &rep->part1.ticket, &len);
	creds->ticket.data = malloc(len);
	memcpy(creds->ticket.data, buf + sizeof(buf) - len, len);
	creds->ticket.length = len;
	creds->second_ticket.length = 0;
	creds->second_ticket.data   = NULL;
    }

    if (decrypt_proc == NULL)
	decrypt_proc = decrypt_tkt;
    
    err = (*decrypt_proc)(context, key, decryptarg, rep);
    if (err)
	return err;

    principalname2krb5_principal(&creds->server, 
				 rep->part1.ticket.sname, 
				 rep->part1.ticket.realm);

    if (rep->part2.starttime) {
	creds->times.starttime = *rep->part2.starttime;
    } else
	creds->times.starttime = rep->part2.authtime;
    if (rep->part2.renew_till) {
	creds->times.renew_till = *rep->part2.renew_till;
    } else
	creds->times.renew_till = 0;
    creds->times.authtime = rep->part2.authtime;
    creds->times.endtime  = rep->part2.endtime;
    if(rep->part2.caddr)
	copy_HostAddresses(rep->part2.caddr, &creds->addresses);
    else {
	if(addr)
	    copy_HostAddresses(addr, &creds->addresses);
	else{
	    creds->addresses.len = 0;
	    creds->addresses.val = NULL;
	}
    }
    creds->flags.b = rep->part2.flags;
	  
    creds->session.keyvalue.length = 0;
    creds->session.keyvalue.data   = NULL;
    creds->session.keytype = rep->part2.key.keytype;
    err = krb5_data_copy (&creds->session.keyvalue,
			  rep->part2.key.keyvalue.data,
			  rep->part2.key.keyvalue.length);
    memset (rep->part2.key.keyvalue.data, 0,
	    rep->part2.key.keyvalue.length);
    creds->authdata.length = 0;
    creds->authdata.data = NULL;

    return err;
}


static krb5_error_code
make_pa_enc_timestamp(krb5_context context, PA_DATA *pa, krb5_keyblock *key)
{
    PA_ENC_TS_ENC p;
    u_char buf[1024];
    size_t len;
    EncryptedData encdata;
    krb5_error_code ret;
    
    p.patimestamp = time(NULL);
    p.pausec      = NULL;

    ret = encode_PA_ENC_TS_ENC(buf + sizeof(buf) - 1,
			       sizeof(buf),
			       &p,
			       &len);
    if (ret)
	return ret;

    /*
     * According to the spec this is the only encryption method
     * that must be supported so it's the safest choice.  On the
     * other hand, old KDCs might not support it.
     */

    ret = krb5_encrypt_EncryptedData(context, 
				     buf + sizeof(buf) - len,
				     len,
				     ETYPE_DES_CBC_MD5,
				     key,
				     &encdata);
    if (ret)
	return ret;
		    
    ret = encode_EncryptedData(buf + sizeof(buf) - 1,
			       sizeof(buf),
			       &encdata, 
			       &len);
    free_EncryptedData(&encdata);
    if (ret)
	return ret;
    pa->padata_type = pa_enc_timestamp;
    pa->padata_value.length = 0;
    krb5_data_copy(&pa->padata_value,
		   buf + sizeof(buf) - len,
		   len);
    return 0;
}

krb5_error_code
krb5_get_in_cred(krb5_context context,
		 krb5_flags options,
		 const krb5_addresses *addrs,
		 const krb5_enctype *etypes,
		 const krb5_preauthtype *ptypes,
		 krb5_key_proc key_proc,
		 krb5_const_pointer keyseed,
		 krb5_decrypt_proc decrypt_proc,
		 krb5_const_pointer decryptarg,
		 krb5_creds *creds,
		 krb5_kdc_rep *ret_as_reply)
{
    krb5_error_code ret;
    AS_REQ a;
    krb5_kdc_rep rep;
    krb5_data req, resp;
    struct timeval tv;
    char buf[BUFSIZ];
    krb5_data salt;
    krb5_keyblock *key;
    size_t size;
    krb5_kdc_flags opts;
    PA_DATA *pa;
    unsigned etype;

    opts.i = options;

    memset(&a, 0, sizeof(a));

    a.pvno = 5;
    a.msg_type = krb_as_req;
    a.req_body.kdc_options = opts.b;
    a.req_body.cname = malloc(sizeof(*a.req_body.cname));
    a.req_body.sname = malloc(sizeof(*a.req_body.sname));
    krb5_principal2principalname (a.req_body.cname, creds->client);
    krb5_principal2principalname (a.req_body.sname, creds->server);
    copy_Realm(&creds->client->realm, &a.req_body.realm);

    /* XXX */
    if(creds->times.starttime){
	a.req_body.from = malloc(sizeof(*a.req_body.from));
	*a.req_body.from = creds->times.starttime;
    }
    a.req_body.till = creds->times.endtime;
    if(creds->times.renew_till){
	a.req_body.rtime = malloc(sizeof(*a.req_body.rtime));
	*a.req_body.rtime = creds->times.renew_till;
    }
    krb5_generate_random_block (&a.req_body.nonce, sizeof(a.req_body.nonce));
    krb5_init_etype (context,
		     &a.req_body.etype.len,
		     &a.req_body.etype.val,
		     etypes);

    etype = a.req_body.etype.val[0]; /* XXX */

    a.req_body.addresses = malloc(sizeof(*a.req_body.addresses));

    if (addrs)
	ret = krb5_copy_addresses(context, addrs, a.req_body.addresses);
    else
	ret = krb5_get_all_client_addrs (a.req_body.addresses);
    if (ret)
	return ret;

    a.req_body.enc_authorization_data = NULL;
    a.req_body.additional_tickets = NULL;

    /* not sure this is the way to use `ptypes' */
    if (ptypes == NULL || *ptypes == KRB5_PADATA_NONE)
	a.padata = NULL;
    else if (*ptypes ==  KRB5_PADATA_ENC_TIMESTAMP) {
	a.padata = malloc(sizeof(*a.padata));
	a.padata->len = 2;
	a.padata->val = calloc(a.padata->len, sizeof(*a.padata->val));
	
	/* make a v5 salted pa-data */
	salt.length = 0;
	salt.data = NULL;
	ret = krb5_get_salt (creds->client, &salt);
	
	if (ret)
	    return ret;
	
	ret = (*key_proc)(context, etype, &salt,
			  keyseed, &key);
	krb5_data_free (&salt);
	if (ret)
	    return ret;
	make_pa_enc_timestamp(context, &a.padata->val[0], key);
	krb5_free_keyblock (context, key);
	free (key);
	/* make a v4 salted pa-data */
	salt.length = 0;
	salt.data = NULL;
	ret = (*key_proc)(context, etype, &salt,
			  keyseed, &key);
	if (ret)
	    return ret;
	make_pa_enc_timestamp(context, &a.padata->val[1], key);
	krb5_free_keyblock (context, key);
	free (key);
    } else
	return KRB5_PREAUTH_BAD_TYPE;

    ret = encode_AS_REQ ((unsigned char*)buf + sizeof(buf) - 1,
			 sizeof(buf),
			 &a,
			 &req.length);
    free_AS_REQ(&a);
    if (ret)
	return ret;

    req.data = buf + sizeof(buf) - req.length;

    ret = krb5_sendto_kdc (context, &req, &creds->client->realm, &resp);
    if (ret)
	return ret;

    if((ret = decode_AS_REP(resp.data, resp.length, &rep.part1, &size))){
	/* let's try to parse it as a KRB-ERROR */
	KRB_ERROR error;
	int ret2;

	ret2 = krb5_rd_error(context, &resp, &error);
	krb5_data_free(&resp);
	if (ret2 == 0) {
	    /* XXX */
	    if (error.e_text)
		fprintf (stderr,
			 "get_in_tkt: KRB_ERROR: %s\n", *(error.e_text));
	    free_KRB_ERROR (&error);
	    return error.error_code;
	}
	return ret;
    }
    krb5_data_free(&resp);
    
    pa = NULL;
    if(rep.part1.padata){
	int index = 0;
	pa = krb5_find_padata(rep.part1.padata->val, rep.part1.padata->len, 
			      pa_pw_salt, &index);
    }
    if(pa)
	ret = (*key_proc)(context, etype, 
			  &pa->padata_value, keyseed, &key);
    else{
	/* make a v5 salted pa-data */
	salt.length = 0;
	salt.data = NULL;
	ret = krb5_get_salt (creds->client, &salt);
	
	if (ret)
	    return ret;
	ret = (*key_proc)(context, etype, &salt,
			  keyseed, &key);
	krb5_data_free (&salt);
	if (ret)
	    return ret;
    }
	
    ret = extract_ticket(context, &rep, creds, key, keyseed, 
			 NULL, decrypt_proc, decryptarg);
    memset (key->keyvalue.data, 0, key->keyvalue.length);
    krb5_free_keyblock (context, key);
    free (key);

    if (ret_as_reply)
	*ret_as_reply = rep;
    else
	krb5_free_kdc_rep (context, &rep);
    return 0;
}

krb5_error_code
krb5_get_in_tkt(krb5_context context,
		krb5_flags options,
		const krb5_addresses *addrs,
		const krb5_enctype *etypes,
		const krb5_preauthtype *ptypes,
		krb5_key_proc key_proc,
		krb5_const_pointer keyseed,
		krb5_decrypt_proc decrypt_proc,
		krb5_const_pointer decryptarg,
		krb5_creds *creds,
		krb5_ccache ccache,
		krb5_kdc_rep *ret_as_reply)
{
    krb5_error_code ret;

    ret = krb5_get_in_cred (context,
			    options,
			    addrs,
			    etypes,
			    ptypes,
			    key_proc,
			    keyseed,
			    decrypt_proc,
			    decryptarg,
			    creds,
			    ret_as_reply);
    if(ret) 
	return ret;
    ret = krb5_cc_store_cred (context, ccache, creds);
    krb5_free_creds (context, creds);
    return ret;
}
