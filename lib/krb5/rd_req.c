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
krb5_rd_req(krb5_context context,
	    krb5_auth_context *auth_context,
	    const krb5_data *inbuf,
	    krb5_const_principal server,
	    krb5_keytab keytab,
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
    krb5_keytab_entry entry;
    EncTicketPart decr_part;
    Authenticator authenticator;

    if (keytab == NULL)
      krb5_kt_default (context, &keytab);

    ret = krb5_kt_get_entry(context,
			    keytab,
			    server,
			    0,
			    KEYTYPE_DES,
			    &entry);
    if (ret)
      return ret;
    ret = decrypt_tkt_enc_part (context,
				&entry.keyblock,
				&ap_req.ticket.enc_part,
				&decr_part);
    if (ret)
      return ret;

    if (ticket) {
      *ticket = malloc(sizeof(**ticket));

      principalname2krb5_principal(&(*ticket)->enc_part2.client,
				   decr_part.cname,
				   decr_part.crealm);
    }

    /* save key */

    (*auth_context)->key.keytype = decr_part.key.keytype;
    krb5_data_copy(&(*auth_context)->key.contents,
		   decr_part.key.keyvalue.data,
		   decr_part.key.keyvalue.length);

    ret = decrypt_authenticator (context,
				 &decr_part.key,
				 &ap_req.authenticator,
				 &authenticator);
    if (ret)
      return ret;

    if (strcmp (authenticator.crealm, decr_part.crealm) != 0)
      return KRB5KRB_AP_ERR_BADMATCH;
    {
      krb5_principal p1, p2;

      principalname2krb5_principal(&p1, authenticator.cname,
				   authenticator.crealm);
      principalname2krb5_principal(&p2, decr_part.cname,
				   decr_part.crealm);
      if (!krb5_principal_compare (context, p1, p2))
	return KRB5KRB_AP_ERR_BADMATCH;
    }
    (*auth_context)->authenticator->cusec = authenticator.cusec;
    (*auth_context)->authenticator->ctime = authenticator.ctime;

    if (ap_req_options) {
      *ap_req_options = 0;
      if (ap_req.ap_options.use_session_key)
	*ap_req_options |= AP_OPTS_USE_SESSION_KEY;
      if (ap_req.ap_options.mutual_required)
	*ap_req_options |= AP_OPTS_MUTUAL_REQUIRED;
    }

    /* Check address and time */
    gettimeofday (&now, NULL);
    if ((decr_part.starttime ? *decr_part.starttime : decr_part.authtime)
	- now.tv_sec > 600 ||
	decr_part.flags.invalid)
      return KRB5KRB_AP_ERR_TKT_NYV;
    if (now.tv_sec - decr_part.endtime > 600)
      return KRB5KRB_AP_ERR_TKT_EXPIRED;

    return 0;
  }
}
