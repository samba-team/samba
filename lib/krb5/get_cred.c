#include <krb5_locl.h>
#include <krb5_error.h>
#include <md4.h>

RCSID("$Id$");

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
	 krb5_creds *creds,		
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
    case krb_error:{
	krb5_principal princ;
	char *name;
	len = decode_KRB_ERROR(resp.data, resp.length, &error);
	if(len < 0)
	    return ASN1_PARSE_ERROR;
	principalname2krb5_principal(&princ, error.sname, error.realm);
	krb5_unparse_name(context, princ, &name);
	fprintf(stderr, "Error: %s", name);
	if(error.e_text)
	    fprintf(stderr, " \"%s\"", *error.e_text);
	fprintf(stderr, " (code %d)\n", error.error_code);
	abort();
	break;
    }
    case krb_tgs_rep:
	len = decode_TGS_REP(resp.data, resp.length, &rep.part1);
	if(len < 0)
	    return ASN1_PARSE_ERROR;
	*out_creds = malloc(sizeof(**out_creds));
	memset(*out_creds, 0, sizeof(**out_creds));
	err = extract_ticket(context, &rep, *out_creds, key_proc, key, NULL, NULL);
	if(err)
	    return err;
	return krb5_cc_store_cred (context, ccache, *out_creds);
	break;
    }
}
