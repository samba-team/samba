#include <krb5_locl.h>

RCSID("$Id$");

krb5_error_code
krb5_rd_priv(krb5_context context,
	     krb5_auth_context auth_context,
	     const krb5_data *inbuf,
	     krb5_data *outbuf,
	     /*krb5_replay_data*/ void *outdata)
{
  krb5_error_code r;
  KRB_PRIV priv;
  EncKrbPrivPart part;
  int len;
  krb5_data plain;

  len = decode_KRB_PRIV (inbuf->data, inbuf->length, &priv);
  if (len < 0)
    return ASN1_PARSE_ERROR;
  if (priv.pvno != 5)
    return KRB5KRB_AP_ERR_BADVERSION;
  if (priv.msg_type != krb_safe)
    return KRB5KRB_AP_ERR_MSG_TYPE;

  r = krb5_decrypt (context,
		    priv.enc_part.cipher.data,
		    priv.enc_part.cipher.length,
		    &auth_context->key,
		    &plain);
  if (r)
    return r;

  len = decode_EncKrbPrivPart (plain.data, plain.length, &part);
  if (len < 0)
    return ASN1_PARSE_ERROR;

  /* check timestamp */
  if (auth_context->flags & KRB5_AUTH_CONTEXT_DO_TIME) {
    struct timeval tv;

    gettimeofday (&tv, NULL);
    if (part.timestamp == NULL ||
	part.usec      == NULL ||
	*part.timestamp - tv.tv_sec > 600)
      return KRB5KRB_AP_ERR_SKEW;
  }

  /* XXX - check replay cache */

  /* check sequence number */
  if (auth_context->flags & KRB5_AUTH_CONTEXT_DO_SEQUENCE) {
    if (part.seq_number == NULL ||
	*part.seq_number != ++auth_context->remote_seqnumber)
      return KRB5KRB_AP_ERR_BADORDER;
  }

  r = krb5_data_copy (outbuf, part.user_data.data, part.user_data.length);
  if (r)
    return r;

  return 0;
}
