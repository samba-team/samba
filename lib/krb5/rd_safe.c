#include <krb5_locl.h>

RCSID("$Id$");

krb5_error_code
krb5_rd_safe(krb5_context context,
	     krb5_auth_context auth_context,
	     const krb5_data *inbuf,
	     krb5_data *outbuf,
	     /*krb5_replay_data*/ void *outdata)
{
  krb5_error_code r;
  KRB_SAFE safe;
  int len;

  len = decode_KRB_SAFE (inbuf->data, inbuf->length, &safe);
  if (len < 0)
    return ASN1_PARSE_ERROR;
  if (safe.pvno != 5)
    return KRB5KRB_AP_ERR_BADVERSION;
  if (safe.msg_type != krb_safe)
    return KRB5KRB_AP_ERR_MSG_TYPE;
  if (safe.cksum.cksumtype != CKSUMTYPE_RSA_MD4)
    return KRB5KRB_AP_ERR_INAPP_CKSUM;
  /* check timestamp */
  if (auth_context->flags & KRB5_AUTH_CONTEXT_DO_TIME) {
    struct timeval tv;

    gettimeofday (&tv, NULL);
    if (safe.safe_body.timestamp == NULL ||
	safe.safe_body.usec      == NULL ||
	*(safe.safe_body.timestamp) - tv.tv_sec > 600)
      return KRB5KRB_AP_ERR_SKEW;
  }
  /* XXX - check replay cache */

  /* check sequence number */
  if (auth_context->flags & KRB5_AUTH_CONTEXT_DO_SEQUENCE) {
    if (safe.safe_body.seq_number == NULL ||
	*safe.safe_body.seq_number != ++auth_context->remote_seqnumber)
      return KRB5KRB_AP_ERR_BADORDER;
  }

  r = krb5_verify_checksum (context,
			    safe.safe_body.user_data.data,
			    safe.safe_body.user_data.length,
			    &safe.cksum);
  if (r)
    return r;
  outbuf->length = safe.safe_body.user_data.length;
  outbuf->data   = malloc(outbuf->length);
  if (outbuf->data == NULL)
    return ENOMEM;
  memcpy (outbuf->data, safe.safe_body.user_data.data, outbuf->length);
  return 0;
}
