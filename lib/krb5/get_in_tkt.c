#include "krb5_locl.h"

RCSID("$Id$");

static krb5_error_code
krb5_get_salt (krb5_principal princ,
	       krb5_data *salt)
{
    size_t len;
    int i;
    krb5_error_code err;
    char *p;
     
    len = princ->realm.length;
    for (i = 0; i < princ->ncomp; ++i)
	len += princ->comp[i].length;
    err = krb5_data_alloc (salt, len);
    if (err)
	return err;
    p = salt->data;
    strncpy (p, princ->realm.data, princ->realm.length);
    p += princ->realm.length;
    for (i = 0; i < princ->ncomp; ++i) {
	strncpy (p, princ->comp[i].data, princ->comp[i].length);
	p += princ->comp[i].length;
    }
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

    ret = krb5_decrypt (context,
			dec_rep->part1.enc_part.cipher.data,
			dec_rep->part1.enc_part.cipher.length,
			key,
			&data);
    if (ret)
      return ret;

    ret = decode_EncTGSRepPart(data.data,
			       data.length,
			       &dec_rep->part2);
    krb5_data_free (&data);
    if (ret < 0)
      return ASN1_PARSE_ERROR;
    return 0;
}

int
extract_ticket(krb5_context context, 
	       krb5_kdc_rep *rep, 
	       krb5_creds *creds,		
	       krb5_key_proc key_proc,
	       krb5_const_pointer keyseed,
	       krb5_decrypt_proc decrypt_proc,
	       krb5_const_pointer decryptarg)
{
    krb5_keyblock *key;
    krb5_error_code err;
    krb5_data salt;

    principalname2krb5_principal(&creds->client, 
				 rep->part1.cname, 
				 rep->part1.crealm);
    free (rep->part1.crealm);
    /*     krb5_principal_free (rep.part1.cname);*/
    {
	char buf[1024];
	int len;
	len = encode_Ticket(buf + sizeof(buf) - 1, sizeof(buf), 
			    &rep->part1.ticket);
	creds->ticket.data = malloc(len);
	memcpy(creds->ticket.data, buf + sizeof(buf) - len, len);
	creds->ticket.length = len;
	creds->second_ticket.length = 0;
    }
    /*     krb5_free_principal (rep->part1.ticket.sprinc);*/

    salt.length = 0;
    salt.data = NULL;
    err = krb5_get_salt (creds->client, &salt);

    if (err)
	return err;

    err = (*key_proc)(context, rep->part1.enc_part.etype, &salt,
		      keyseed, &key);
    krb5_data_free (&salt);
    if (err)
	return err;
    
    if (decrypt_proc == NULL)
	decrypt_proc = decrypt_tkt;
    
    err = (*decrypt_proc)(context, key, decryptarg, rep);
    if (err)
	return err;
    memset (key->contents.data, 0, key->contents.length);
    krb5_data_free (&key->contents);
    free (key);

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
    creds->addresses.number = 0;
    creds->addresses.addrs = NULL;
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

    creds->session.contents.length = 0;
    creds->session.contents.data   = NULL;
    creds->session.keytype = rep->part2.key.keytype;
    err = krb5_data_copy (&creds->session.contents,
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
		krb5_address *const *addrs,
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
    krb5_error_code err;
    AS_REQ a;
    krb5_kdc_rep rep;
    krb5_data req, resp;
    char buf[BUFSIZ];

    memset(&a, 0, sizeof(a));

    a.pvno = 5;
    a.msg_type = krb_as_req;
    a.req_body.cname = malloc(sizeof(*a.req_body.cname));
    a.req_body.sname = malloc(sizeof(*a.req_body.sname));
    krb5_principal2principalname (a.req_body.cname, creds->client);
    krb5_principal2principalname (a.req_body.sname, creds->server);
    a.req_body.realm = malloc(creds->client->realm.length + 1);
    strncpy (a.req_body.realm, creds->client->realm.data,
	     creds->client->realm.length);
    a.req_body.realm[creds->client->realm.length] = '\0';

    a.req_body.till  = creds->times.endtime;
    a.req_body.nonce = 17;
    if (etypes)
	abort ();
    else {
	err = krb5_get_default_in_tkt_etypes (context,
					      (krb5_enctype**)&a.req_body.etype.val);
	if (err)
	    return err;
	a.req_body.etype.len = 1;
    }
    if (addrs){
    } else {
	a.req_body.addresses = malloc(sizeof(*a.req_body.addresses));

	err = krb5_get_all_client_addrs ((krb5_addresses*)a.req_body.addresses);
	if (err)
	    return err;
    }
    a.req_body.enc_authorization_data = NULL;
    a.req_body.additional_tickets = NULL;
    a.padata = NULL;

    req.length = encode_AS_REQ ((unsigned char*)buf + sizeof(buf) - 1,
				sizeof(buf),
				&a);
    if (req.length < 0)
	return ASN1_PARSE_ERROR;
    req.data = buf + sizeof(buf) - req.length;
    if (addrs == NULL) {
	int i;

	for (i = 0; i < a.req_body.addresses->len; ++i)
	    krb5_data_free (&a.req_body.addresses->val[i].address);
	free (a.req_body.addresses->val);
    }

    err = krb5_sendto_kdc (context, &req, &creds->client->realm, &resp);
    if (err) {
	return err;
    }
    if(decode_AS_REP(resp.data, resp.length, &rep.part1) < 0)
	return ASN1_PARSE_ERROR;

    err = extract_ticket(context, &rep, creds, key_proc, keyseed, 
			 decrypt_proc, decryptarg);
    if(err)
	return err;
    return krb5_cc_store_cred (context, ccache, creds);
}
