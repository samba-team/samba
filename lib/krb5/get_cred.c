#include <krb5_locl.h>
#include <krb5_error.h>
#include <md4.h>

/*
 *
 */



static krb5_error_code
key_proc (krb5_context context,
	  krb5_keytype type,
	  krb5_data *salt,
	  krb5_const_pointer keyseed,
	  krb5_keyblock **key)
{
    *key = malloc (sizeof (**key));
    if (*key == NULL)
	return ENOMEM;
    (*key)->keytype = type;
    (*key)->contents.length = 8;
    (*key)->contents.data   = malloc(8);
    memcpy((*key)->contents.data, keyseed, 8);
    return 0;
}

int
extract_ticket(krb5_context context, 
	 krb5_kdc_rep *rep, 
	 krb5_creds **creds,		
	 krb5_key_proc key_proc,
	 krb5_const_pointer keyseed,
	 krb5_decrypt_proc decrypt_proc,
	 krb5_const_pointer decryptarg);


krb5_error_code
krb5_get_credentials (krb5_context context,
		      krb5_flags options,
		      krb5_ccache ccache,
		      krb5_creds *in_creds,
		      krb5_creds **out_creds)
{
    krb5_error_code err;
    TGS_REQ a;
    Authenticator auth;
    krb5_data authenticator;
    Checksum c;
    AP_REQ ap;
    krb5_kdc_rep rep;
    KRB_ERROR error;
    krb5_data req, resp;
    char buf[BUFSIZ];
    int i;
    unsigned char data[1024], buf2[1024];
    int len;

    PA_DATA foo;


    des_key_schedule schedule;
    des_cblock key;
    
    /*
     * XXX - Check if cred found in ccache
     */

    /*
     * Prepare Tgs_Req.
     */

    err = krb5_get_default_in_tkt_etypes (context,
					  (krb5_enctype**)&a.req_body.etype.val);
    if (err)
	return err;
    a.req_body.etype.len = 1;


    a.req_body.addresses = malloc(sizeof(*a.req_body.addresses));

    err = krb5_get_all_client_addrs ((krb5_addresses*)a.req_body.addresses);
    if (err)
	return err;

    a.pvno = 5;
    a.msg_type = krb_tgs_req;
    memset (&a.req_body.kdc_options, 0, sizeof(a.req_body.kdc_options));
    /* a.kdc_options */

    a.req_body.realm = malloc(in_creds->server->realm.length + 1);
    strncpy (a.req_body.realm, in_creds->server->realm.data,
	     in_creds->server->realm.length);
    a.req_body.realm[in_creds->server->realm.length] = '\0';
    
    a.req_body.sname = malloc(sizeof(*a.req_body.sname));
    krb5_principal2principalname(a.req_body.sname, in_creds->server);
    a.req_body.from = NULL;
    a.req_body.till = in_creds->times.endtime;
    a.req_body.rtime = NULL;
    a.req_body.nonce = getpid();
    a.req_body.additional_tickets = NULL;
    a.req_body.enc_authorization_data = NULL;

    {
      char buf[1024];
      int len;
      struct md4 m;
      Checksum c;

      len = encode_KDC_REQ_BODY(buf + sizeof(buf) - 1, sizeof(buf),
				&a.req_body);
      md4_init(&m);
      md4_update(&m, buf + sizeof(buf) - len, len);
      c.cksumtype = rsa_md4;
      c.checksum.length = 16;
      c.checksum.data = malloc(16);
      md4_finito(&m, c.checksum.data);
      krb5_build_authenticator (context, in_creds->client,
				&c, NULL, &authenticator);
    }

#if 0
    {
	struct timeval tv;
	auth.authenticator_vno = 5;
	krb5_cc_get_principal(context, ccache, &out_creds->client);

	auth.crealm = malloc(out_creds->client->realm.length + 1);
	strncpy (auth.crealm, out_creds->client->realm.data, 
		 out_creds->client->realm.length);
	auth.crealm[out_creds->client->realm.length] = 0;
	krb5_principal2principalname(&auth.cname, out_creds->client);
	gettimeofday(&tv, NULL);
	{
	    char buf[1024];
	    int len;
	    struct md4 m;
	    len = encode_KDC_REQ_BODY(buf + sizeof(buf) - 1, sizeof(buf),
				      &a.req_body);
	    md4_init(&m);
	    md4_update(&m, buf + sizeof(buf) - len, len);
	    c.cksumtype = rsa_md4;
	    c.checksum.length = 16;
	    c.checksum.data = malloc(16);
	    md4_finito(&m, c.checksum.data);
	    auth.cksum = &c;
	}
	auth.cusec = tv.tv_usec;
	auth.ctime = tv.tv_sec;
	auth.subkey = NULL;
	auth.seq_number = NULL;
	auth.authorization_data = NULL;
	
    }
#endif
    
#if 0
    /*
AP-REQ ::=      [APPLICATION 14] SEQUENCE {
                pvno[0]                       INTEGER,
                msg-type[1]                   INTEGER,
                ap-options[2]                 APOptions,
                ticket[3]                     Ticket,
                authenticator[4]              EncryptedData
}
*/
    {
	krb5_creds cred, mcred;
	ap.pvno = 5;
	ap.msg_type = krb_ap_req;
	memset(&ap.ap_options, 0, sizeof(ap.ap_options));
	/*	ap.ap_options.use_session_key = 1;*/
	krb5_build_principal(context, &mcred.server, 
			     out_creds->client.realm.length,
			     out_creds->client.realm.data,
			     "krbtgt", a.req_body.realm, NULL);
	krb5_cc_retrieve_cred(context, ccache, 0, &mcred, &cred);
	
	/*
                              tkt-vno[0]                   INTEGER,
                              realm[1]                     Realm,
                              sname[2]                     PrincipalName,
                              enc-part[3]                  EncryptedData
			      */
	ap.ticket.tkt_vno = 5;
	ap.ticket.realm = (char*)malloc(cred.server->realm.length + 1);
	strncpy(ap.ticket.realm, cred.server->realm.data, 
		cred.server->realm.length);
	ap.ticket.realm[cred.server->realm.length] = 0;
	krb5_principal2principalname(&ap.ticket.sname, cred.server);

	{
	    Ticket t;
	    decode_Ticket(cred.ticket.data,
			  cred.ticket.length, 
			  &t);

	    ap.ticket.enc_part.etype = t.enc_part.etype;
	    ap.ticket.enc_part.kvno = NULL;
	    ap.ticket.enc_part.cipher = t.enc_part.cipher;
	}
	memcpy(&key, cred.session.contents.data, sizeof(key));
	des_set_key(cred.session.contents.data, schedule);
    }
#endif

#if 0
    {
	u_int32_t crc;
	unsigned char *p;

	memset(data, 0, sizeof(data));
	len = encode_Authenticator(data + sizeof(data) - 9, 
				   sizeof(data) - 8 - 12, &auth);
	p = data + sizeof(data) - 8 - len;
	
	p -= 12;
	len += 12;
	len = (len + 7) & ~7;
	crc_init_table();
	crc = crc_update(p, len, 0);
	/* crc = htonl(crc); */
	memcpy(p + 8, &crc, 4);
#if 0
	des_cbc_encrypt((void*)p, (void*)p, len, schedule, &key, DES_ENCRYPT);
#endif
#if 0
	ap.authenticator.etype = ap.ticket.enc_part.etype;
	ap.authenticator.kvno = NULL;
	ap.authenticator.cipher.data = p; /* p */
	ap.authenticator.cipher.length = len; /* len */
#endif

	authenticator.data   = p;
	authenticator.length = len;
    }
#endif	

    {
	krb5_creds cred, mcred;

	krb5_build_principal(context, &mcred.server, 
			     in_creds->client->realm.length,
			     in_creds->client->realm.data,
			     "krbtgt", a.req_body.realm, NULL);
	krb5_cc_retrieve_cred(context, ccache, 0, &mcred, &cred);
	memcpy(&key, cred.session.contents.data, sizeof(key));

	foo.padata_type = pa_tgs_req;
	err = krb5_build_ap_req(context, &cred, 
				0,
				authenticator,
				&foo.padata_value);
	if(err)
	  return err;
    }

    a.padata = malloc(sizeof(*a.padata));
    a.padata->len = 1;
    a.padata->val = &foo;


#if 0
    foo.padata_value.length = encode_AP_REQ(buf2 + sizeof(buf2) - 1, 
					    sizeof(buf2), &ap);
    foo.padata_value.data = buf2 + sizeof(buf2) - foo.padata_value.length;
    a.padata = malloc(sizeof(*a.padata));
    a.padata->len = 1;
    a.padata->val = &foo;
#endif
	
    /*
     * Encode
     */

    req.length = encode_TGS_REQ  (buf + sizeof (buf) - 1, sizeof(buf), &a);
    req.data   = buf + sizeof(buf) - req.length;

    for (i = 0; i < a.req_body.addresses->len; ++i)
	krb5_data_free (&a.req_body.addresses->val[i].address);
    free (a.req_body.addresses->val);

    /*
     * Send and receive
     */

    {
	TGS_REQ xx;
	decode_TGS_REQ (req.data, req.length, &xx);
	req.length = req.length;
    }

    err = krb5_sendto_kdc (context, &req, &in_creds->server->realm, &resp);
    if (err) {
	return err;
    }
    switch(((unsigned char*)resp.data)[0] & 0x1f){
    case krb_error:
	len = decode_TGS_REP(resp.data, resp.length, &error);
	if(len < 0)
	    return ASN1_PARSE_ERROR;
	break;
    case krb_tgs_rep:
	len = decode_TGS_REP(resp.data, resp.length, &rep.part1);
	if(len < 0)
	    return ASN1_PARSE_ERROR;
	out_creds = malloc(sizeof(*out_creds));
	*out_creds = NULL;
	err = extract_ticket(context, &rep, *out_creds, key_proc, key, NULL, NULL);
	if(err)
	    return err;
	return krb5_cc_store_cred (context, ccache, out_creds);
	break;
    }
}
