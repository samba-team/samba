#include "krb5_locl.h"

RCSID("$Id$");

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
	       krb5_decrypt_proc decrypt_proc,
	       krb5_const_pointer decryptarg)
{
    krb5_error_code err;

    principalname2krb5_principal(&creds->client, 
				 rep->part1.cname, 
				 rep->part1.crealm);
    /* free (rep->part1.crealm); */
    /*     krb5_principal_free (rep.part1.cname);*/
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
    /*     krb5_free_principal (context, rep->part1.ticket.sprinc);*/

    if (decrypt_proc == NULL)
	decrypt_proc = decrypt_tkt;
    
    err = (*decrypt_proc)(context, key, decryptarg, rep);
    if (err)
	return err;
#if 0 /* moved to krb5_get_in_tkt */
    memset (key->keyvalue.data, 0, key->keyvalue.length);
    krb5_data_free (&key->keyvalue);
    free (key);
#endif

    principalname2krb5_principal(&creds->server, 
				 rep->part1.ticket.sname, 
				 rep->part1.ticket.realm);

    if (rep->part2.key_expiration)
	free (rep->part2.key_expiration);
    if (rep->part2.starttime) {
	creds->times.starttime = *rep->part2.starttime;
	free (rep->part2.starttime);
    } else
	creds->times.starttime = rep->part2.authtime;
    if (rep->part2.renew_till) {
	creds->times.renew_till = *rep->part2.renew_till;
	free (rep->part2.renew_till);
    } else
	creds->times.renew_till = 0;
    creds->times.authtime = rep->part2.authtime;
    creds->times.endtime  = rep->part2.endtime;
    creds->addresses.len = 0;
    creds->addresses.val = NULL;
#if 0 /* What? */
    if (rep->part2.req.values)
	free (rep->part2.req.values);
#endif
#if 0
    if (rep->part2.caddr.addrs) {
	int i;

	for (i = 0; i < rep->part2.caddr.number; ++i) {
	    krb5_data_free (&rep->part2.caddr.addrs[i].address);
	}
	free (rep->part2.caddr.addrs);
    }
    krb5_principal_free (rep->part2.sname);
    krb5_data_free (&rep->part2.srealm);
#endif
	  
    if (err)
	return err;

    creds->session.keyvalue.length = 0;
    creds->session.keyvalue.data   = NULL;
    creds->session.keytype = rep->part2.key.keytype;
    err = krb5_data_copy (&creds->session.keyvalue,
			  rep->part2.key.keyvalue.data,
			  rep->part2.key.keyvalue.length);
    memset (rep->part2.key.keyvalue.data, 0,
	    rep->part2.key.keyvalue.length);
    krb5_data_free (&rep->part2.key.keyvalue);
    creds->authdata.length = 0;
    creds->authdata.data = NULL;

    return err;
}

/*
 *
 */

krb5_error_code
krb5_get_in_tkt(krb5_context context,
		krb5_flags options,
		const krb5_addresses *addrs,
/*		krb5_address *const *addrs,*/
		const krb5_enctype *etypes,
		const krb5_preauthtype *ptypes,
		krb5_key_proc key_proc,
		krb5_const_pointer keyseed,
		krb5_decrypt_proc decrypt_proc,
		krb5_const_pointer decryptarg,
		krb5_creds *creds,
		krb5_ccache ccache,
		krb5_kdc_rep **ret_as_reply)
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
    union {
	krb5_flags i;
	KDCOptions f;
    } opts;
    opts.i = options;

    memset(&a, 0, sizeof(a));

    a.pvno = 5;
    a.msg_type = krb_as_req;
    a.req_body.kdc_options = opts.f;
    a.req_body.cname = malloc(sizeof(*a.req_body.cname));
    a.req_body.sname = malloc(sizeof(*a.req_body.sname));
    krb5_principal2principalname (a.req_body.cname, creds->client);
    krb5_principal2principalname (a.req_body.sname, creds->server);
#ifdef USE_ASN1_PRINCIPAL
    copy_Realm(&creds->client->realm, &a.req_body.realm);
#else
    a.req_body.realm = malloc(creds->client->realm.length + 1);
    strncpy (a.req_body.realm, creds->client->realm.data,
	     creds->client->realm.length);
    a.req_body.realm[creds->client->realm.length] = '\0';
#endif

    a.req_body.till  = creds->times.endtime;
    a.req_body.nonce = 17;	/* XXX */
    if (etypes)
	abort ();
    else {
	ret = krb5_get_default_in_tkt_etypes (context,
					      (krb5_enctype**)&a.req_body.etype.val);
	if (ret)
	    return ret;
	a.req_body.etype.len = 1;
    }
    
    a.req_body.addresses = malloc(sizeof(*a.req_body.addresses));

    if (addrs)
	ret = krb5_copy_addresses(context, addrs, a.req_body.addresses);
    else
	ret = krb5_get_all_client_addrs (a.req_body.addresses);
    if (ret)
	return ret;

    a.req_body.enc_authorization_data = NULL;
    a.req_body.additional_tickets = NULL;

    /* 
     * moved the call of `key_proc' here so that the key is available
     * when/if creating pre-authentication.  This will failed when
     * using different encryption/string-to-key algorithms for the
     * initial PA-ENC-TS-ENC and the decryption of the ticket.
     */

    salt.length = 0;
    salt.data = NULL;
    ret = krb5_get_salt (creds->client, &salt);

    if (ret)
	return ret;

    ret = (*key_proc)(context, *(a.req_body.etype.val), &salt,
		      keyseed, &key);
    krb5_data_free (&salt);
    if (ret)
	return ret;
    
    /* not sure this is the way to use `ptypes' */
    if (ptypes == NULL || *ptypes == KRB5_PADATA_NONE)
	a.padata = NULL;
    else if (*ptypes ==  KRB5_PADATA_ENC_TIMESTAMP) {
	PA_ENC_TS_ENC p;
	u_char buf[1024];
	struct timeval tv;
	size_t len;
	unsigned foo;
	EncryptedData encdata;

	gettimeofday (&tv, NULL);
	p.patimestamp = tv.tv_sec;
	foo = tv.tv_usec;
	p.pausec      = &foo;

	ret = encode_PA_ENC_TS_ENC(buf + sizeof(buf) - 1,
				   sizeof(buf),
				   &p,
				   &len);
	if (ret)
	  return ret;

	a.padata = malloc(sizeof(*a.padata));
	a.padata->len = 1;
	a.padata->val = malloc(sizeof(*a.padata->val));
	a.padata->val->padata_type = pa_enc_timestamp;
	a.padata->val->padata_value.length = 0;

	encdata.etype = ETYPE_DES_CBC_CRC;
	encdata.kvno  = NULL;
	ret = krb5_encrypt (context,
			    buf + sizeof(buf) - len,
			    len,
			    encdata.etype,
			    key,
			    &encdata.cipher);
	if (ret)
	    return ret;

	ret = encode_EncryptedData(buf + sizeof(buf) - 1,
				   sizeof(buf),
				   &encdata, 
				   &len);
	krb5_data_free(&encdata.cipher);
	if (ret)
	    return ret;
	krb5_data_copy(&a.padata->val->padata_value,
		       buf + sizeof(buf) - len,
		       len);
    } else
	return KRB5_PREAUTH_BAD_TYPE;

    ret = encode_AS_REQ ((unsigned char*)buf + sizeof(buf) - 1,
			 sizeof(buf),
			 &a,
			 &req.length);
    if (ret){
	free_AS_REQ(&a);
	return ret;
    }
    free_AS_REQ(&a);
    req.data = buf + sizeof(buf) - req.length;

    ret = krb5_sendto_kdc (context, &req, &creds->client->realm, &resp);
    if (ret) {
	return ret;
    }
    if((ret = decode_AS_REP(resp.data, resp.length, &rep.part1, &size))){
	/* let's try to parse it as a KRB-ERROR */
	KRB_ERROR error;
	int ret2;

	ret2 = decode_KRB_ERROR(resp.data, resp.length, &error, &size);
	krb5_data_free(&resp);
	if (ret2 == 0) {
	    /* XXX */
	    fprintf (stderr, "get_in_tkt: KRB_ERROR: %s\n", *(error.e_text));
	    return error.error_code;
	}
	return ret;
    }
    krb5_data_free(&resp);
    
    ret = extract_ticket(context, &rep, creds, key, keyseed, 
			 decrypt_proc, decryptarg);
    memset (key->keyvalue.data, 0, key->keyvalue.length);
    krb5_data_free (&key->keyvalue);
    free (key);

    free_KDC_REP(&rep.part1);
    if(ret) 
	return ret;
    return krb5_cc_store_cred (context, ccache, creds);
}
