#include <krb5_locl.h>

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
    *key = (krb5_keyblock *)keyseed;
    return 0;
}

krb5_error_code
krb5_get_credentials (krb5_context context,
		      krb5_flags options,
		      krb5_ccache ccache,
		      krb5_creds *in_creds,
		      krb5_creds **out_creds)
{
    krb5_error_code ret;
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
    size_t len;

    PA_DATA *foo;

    krb5_kdc_flags flags;

    /*
     * XXX - Check if cred found in ccache
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

    /*
     * Prepare Tgs_Req.
     */

    memset(&a, 0, sizeof(a));

    ret = krb5_get_default_in_tkt_etypes (context,
					  (krb5_enctype**)&a.req_body.etype.val);
    if (ret)
	return ret;
    a.req_body.etype.len = 1;

    a.req_body.addresses = malloc(sizeof(*a.req_body.addresses));

    ret = krb5_get_all_client_addrs (a.req_body.addresses);
    if (ret)
	return ret;

    a.pvno = 5;
    a.msg_type = krb_tgs_req;

    flags.i = options;
    a.req_body.kdc_options = flags.b;

#ifdef USE_ASN1_PRINCIPAL
    copy_Realm(&in_creds->server->realm, &a.req_body.realm);
    a.req_body.sname = malloc(sizeof(*a.req_body.sname));
    copy_PrincipalName(&in_creds->server->name, a.req_body.sname);
#else
    a.req_body.realm = malloc(in_creds->server->realm.length + 1);
    strncpy (a.req_body.realm, in_creds->server->realm.data,
	     in_creds->server->realm.length);
    a.req_body.realm[in_creds->server->realm.length] = '\0';
    
    a.req_body.sname = malloc(sizeof(*a.req_body.sname));
    krb5_principal2principalname(a.req_body.sname, in_creds->server);
#endif
    a.req_body.from = NULL;
    a.req_body.till = in_creds->times.endtime;
    a.req_body.rtime = NULL;
    krb5_generate_random_block (&a.req_body.nonce, sizeof(a.req_body.nonce));
    a.req_body.additional_tickets = NULL;
    a.req_body.enc_authorization_data = NULL;

    {
	krb5_data in_data;
	unsigned char buf[1024];
	krb5_auth_context ac = NULL;
	size_t len;
	krb5_creds tmp_cred;

	foo = malloc (sizeof(*foo));

	ret = encode_KDC_REQ_BODY(buf + sizeof(buf) - 1, sizeof(buf),
				  &a.req_body, &len);
	in_data.length = len;
	in_data.data = buf + sizeof(buf) - len;
	
	tmp_cred.client = NULL;
	ret = krb5_build_principal(context,
				   &tmp_cred.server,
				   strlen(a.req_body.realm),
				   a.req_body.realm,
				   "krbtgt",
				   a.req_body.realm,
				   NULL);
	if (ret)
	  return ret;

	ret = krb5_get_credentials (context,
				    0,
				    ccache,
				    &tmp_cred,
				    out_creds);
	if (ret)
	  return ret;

	ret = krb5_mk_req_extended(context,
				   &ac,
				   0,
				   &in_data,
				   *out_creds,
				   &foo->padata_value);
	if(ret)
	    return ret;

	foo->padata_type = pa_tgs_req;
    }

    a.padata = malloc(sizeof(*a.padata));
    a.padata->len = 1;
    a.padata->val = foo;
	
    /*
     * Encode
     */

    encode_TGS_REQ  (buf + sizeof (buf) - 1, sizeof(buf), &a, &req.length);
    req.data = buf + sizeof(buf) - req.length;

    free_TGS_REQ (&a);

    /*
     * Send and receive
     */

    ret = krb5_sendto_kdc (context, &req, &in_creds->server->realm, &resp);
    if (ret) {
	return ret;
    }
    switch(((unsigned char*)resp.data)[0] & 0x1f){
    case krb_error:{
	krb5_principal princ;
	char *name;
	ret = decode_KRB_ERROR(resp.data, resp.length, &error, &len);
	if(ret) return ret;
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
	ret = decode_TGS_REP(resp.data, resp.length, &rep.part1, &len);
	if(ret) return ret;
	ret = extract_ticket(context, &rep, *out_creds,
			     &(*out_creds)->session,
			     NULL,
			     NULL,
			     NULL);
	if(ret)
	    return ret;
	return krb5_cc_store_cred (context, ccache, *out_creds);
	break;
    default:
	return KRB5KRB_AP_ERR_MSG_TYPE;
    }
}
