#include <krb5_locl.h>

RCSID("$Id$");

static krb5_error_code
decrypt_tkt_enc_part (krb5_context context,
		      const krb5_keyblock *key,
		      EncryptedData *enc_part,
		      EncTicketPart *decr_part)
{
    krb5_error_code ret;
    krb5_data plain;
    int len;

    ret = krb5_decrypt (context, enc_part->cipher.data, enc_part->cipher.length, key, &plain);
    if (ret)
	return ret;

    len = decode_EncTicketPart(plain.data, plain.length, decr_part);
    krb5_data_free (&plain);
    if (len < 0)
      return ASN1_PARSE_ERROR;
    return 0;
}

static krb5_error_code
decrypt_authenticator (krb5_context context,
		       EncryptionKey *key,
		       EncryptedData *enc_part,
		       Authenticator *authenticator)
{
    krb5_error_code ret;
    krb5_data plain;
    int len;

    ret = krb5_decrypt (context, enc_part->cipher.data, enc_part->cipher.length, key, &plain);
    if (ret)
	return ret;

    len = decode_Authenticator(plain.data, plain.length, authenticator);
    krb5_data_free (&plain);
    if (len < 0)
      return ASN1_PARSE_ERROR;
    return 0;
}

krb5_error_code
krb5_rd_req_with_keyblock(krb5_context context,
			  krb5_auth_context *auth_context,
			  const krb5_data *inbuf,
			  krb5_const_principal server,
			  krb5_keyblock *keyblock,
			  krb5_flags *ap_req_options,
			  krb5_ticket **ticket)
{
  krb5_error_code ret;
  AP_REQ ap_req;
  int len;
  struct timeval now;

  if (*auth_context == NULL) {
    ret = krb5_auth_con_init(context, auth_context);
    if (ret)
      return ret;
  }

  len = decode_AP_REQ(inbuf->data, inbuf->length, &ap_req);
  if (len < 0)
    return ASN1_PARSE_ERROR;
  if (ap_req.pvno != 5)
    return KRB5KRB_AP_ERR_BADVERSION;
  if (ap_req.msg_type != krb_ap_req)
    return KRB5KRB_AP_ERR_MSG_TYPE;
  if (ap_req.ticket.tkt_vno != 5)
    return KRB5KRB_AP_ERR_BADVERSION;
  if (ap_req.ap_options.use_session_key)
    abort ();
  else {
    Authenticator authenticator;
    krb5_ticket *t;

    t = malloc(sizeof(*t));
    ret = decrypt_tkt_enc_part (context,
				keyblock,
				&ap_req.ticket.enc_part,
				&t->tkt);
    if (ret)
	return ret;

    principalname2krb5_principal(&t->enc_part2.client,
				 t->tkt.cname,
				 t->tkt.crealm);
    if (ticket)
	*ticket = t;

    /* save key */

    (*auth_context)->key.keytype = t->tkt.key.keytype;
    krb5_data_copy(&(*auth_context)->key.contents,
		   t->tkt.key.keyvalue.data,
		   t->tkt.key.keyvalue.length);

    ret = decrypt_authenticator (context,
				 &t->tkt.key,
				 &ap_req.authenticator,
				 &authenticator);
    if (ret)
	return ret;

    memset((*auth_context)->authenticator, 0, 
	   sizeof((*auth_context)->authenticator));
    {
	krb5_principal p2;
	
	principalname2krb5_principal(&(*auth_context)->authenticator->cname, 
				     authenticator.cname,
				     authenticator.crealm);
	principalname2krb5_principal(&p2, 
				     t->tkt.cname,
				     t->tkt.crealm);
	if (!krb5_principal_compare (context, 
				     (*auth_context)->authenticator->cname, 
				     p2))
	    return KRB5KRB_AP_ERR_BADMATCH;
    }
    (*auth_context)->authenticator->cusec = authenticator.cusec;
    (*auth_context)->authenticator->ctime = authenticator.ctime;

    if (authenticator.seq_number)
      (*auth_context)->remote_seqnumber = *(authenticator.seq_number);

    /* XXX - Xor sequence numbers */

    /* XXX - check addresses */

    if (ap_req_options) {
      *ap_req_options = 0;
      if (ap_req.ap_options.use_session_key)
	*ap_req_options |= AP_OPTS_USE_SESSION_KEY;
      if (ap_req.ap_options.mutual_required)
	*ap_req_options |= AP_OPTS_MUTUAL_REQUIRED;
    }

    /* Check address and time */
    gettimeofday (&now, NULL);
    if ((t->tkt.starttime ? *t->tkt.starttime : t->tkt.authtime)
	- now.tv_sec > 600 ||
	t->tkt.flags.invalid)
      return KRB5KRB_AP_ERR_TKT_NYV;
    if (now.tv_sec - t->tkt.endtime > 600)
      return KRB5KRB_AP_ERR_TKT_EXPIRED;

    return 0;
  }
}

krb5_error_code
krb5_rd_req(krb5_context context,
	    krb5_auth_context *auth_context,
	    const krb5_data *inbuf,
	    krb5_const_principal server,
	    krb5_keytab keytab,
	    krb5_flags *ap_req_options,
	    krb5_ticket **ticket)
{
    krb5_keytab_entry entry;
    krb5_error_code ret;
    if(keytab == NULL)
	krb5_kt_default(context, &keytab);
    ret = krb5_kt_get_entry(context,
			    keytab,
			    (krb5_principal)server,
			    0,
			    KEYTYPE_DES,
			    &entry);
    if(ret)
	return ret;
    
    return krb5_rd_req_with_keyblock(context,
				     auth_context,
				     inbuf,
				     server,
				     &entry.keyblock,
				     ap_req_options,
				     ticket);
}
