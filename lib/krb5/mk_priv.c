#include <krb5_locl.h>

RCSID("$Id$");

krb5_error_code
krb5_mk_priv(krb5_context context,
	     krb5_auth_context auth_context,
	     const krb5_data *userdata,
	     krb5_data *outbuf,
	     /*krb5_replay_data*/ void *outdata)
{
  krb5_error_code r;
  KRB_PRIV s;
  EncKrbPrivPart part;
  struct timeval tv;
  unsigned usec;
  u_char buf[1024];
  size_t len;
  unsigned tmp_seq;

  part.user_data = *userdata;
  gettimeofday (&tv, NULL);
  usec = tv.tv_usec;
  part.timestamp  = &tv.tv_sec;
  part.usec       = &usec;
  if (auth_context->flags & KRB5_AUTH_CONTEXT_DO_SEQUENCE) {
    tmp_seq = ++auth_context->local_seqnumber;
    part.seq_number = &tmp_seq;
  } else {
    part.seq_number = NULL;
  }

  part.s_address = auth_context->local_address;
  part.r_address = auth_context->remote_address;

  r = encode_EncKrbPrivPart (buf + sizeof(buf) - 1, sizeof(buf), &part, &len);
  if (r)
      return r;

  s.pvno = 5;
  s.msg_type = krb_priv;
  s.enc_part.etype = ETYPE_DES_CBC_CRC;
  s.enc_part.kvno = NULL;

  r = krb5_encrypt (context, buf + sizeof(buf) - len, len,
		    s.enc_part.etype, &auth_context->key, &s.enc_part.cipher);
  if (r)
    return r;

  r = encode_KRB_PRIV (buf + sizeof(buf) - 1, sizeof(buf), &s, &len);
  if (r)
    return r;
  outbuf->length = len;
  outbuf->data   = malloc (len);
  if (outbuf->data == NULL)
    return ENOMEM;
  memcpy (outbuf->data, buf + sizeof(buf) - len, len);
  return 0;
}
