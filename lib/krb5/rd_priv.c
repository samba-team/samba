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
  size_t len;
  krb5_data plain;

  r = decode_KRB_PRIV (inbuf->data, inbuf->length, &priv, &len);
  if (r) 
      goto failure;
  if (priv.pvno != 5) {
      r = KRB5KRB_AP_ERR_BADVERSION;
      goto failure;
  }
  if (priv.msg_type != krb_safe) {
      r = KRB5KRB_AP_ERR_MSG_TYPE;
      goto failure;
  }

  r = krb5_decrypt (context,
		    priv.enc_part.cipher.data,
		    priv.enc_part.cipher.length,
		    priv.enc_part.etype,
		    &auth_context->key,
		    &plain);
  if (r) 
      goto failure;

  r = decode_EncKrbPrivPart (plain.data, plain.length, &part, &len);
  if (r) 
      return r;
  
  /* check sender address */

  if (part.s_address
      && !krb5_address_compare (context,
				auth_context->remote_address,
				part.s_address)) {
      r = KRB5KRB_AP_ERR_BADADDR;
      goto failure_part;
  }

  /* check receiver address */

  if (part.r_address
      && !krb5_address_compare (context,
				auth_context->local_address,
				part.r_address)) {
      r = KRB5KRB_AP_ERR_BADADDR;
      goto failure_part;
  }

  /* check timestamp */
  if (auth_context->flags & KRB5_AUTH_CONTEXT_DO_TIME) {
    struct timeval tv;

    gettimeofday (&tv, NULL);
    if (part.timestamp == NULL ||
	part.usec      == NULL ||
	*part.timestamp - tv.tv_sec > 600) {
	r = KRB5KRB_AP_ERR_SKEW;
	goto failure_part;
    }
  }

  /* XXX - check replay cache */

  /* check sequence number */
  if (auth_context->flags & KRB5_AUTH_CONTEXT_DO_SEQUENCE) {
    if (part.seq_number == NULL ||
	*part.seq_number != ++auth_context->remote_seqnumber) {
      r = KRB5KRB_AP_ERR_BADORDER;
      goto failure_part;
    }
  }

  r = krb5_data_copy (outbuf, part.user_data.data, part.user_data.length);
  if (r)
      goto failure_part;

  free_EncKrbPrivPart (&part);
  free_KRB_PRIV (&priv);
  return 0;

failure_part:
  free_EncKrbPrivPart (&part);

failure:
  free_KRB_PRIV (&priv);
  return r;
}
