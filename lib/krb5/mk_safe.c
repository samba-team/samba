#include <krb5_locl.h>

RCSID("$Id$");

krb5_error_code
krb5_mk_safe(krb5_context context,
	     krb5_auth_context auth_context,
	     const krb5_data *userdata,
	     krb5_data *outbuf,
	     /*krb5_replay_data*/ void *outdata)
{
  krb5_error_code r;
  KRB_SAFE s;
  struct timeval tv;
  unsigned usec;
  u_char buf[1024];
  size_t len;
  unsigned tmp_seq;

  s.pvno = 5;
  s.msg_type = krb_safe;

  s.safe_body.user_data = *userdata;
  gettimeofday (&tv, NULL);
  usec = tv.tv_usec;
  s.safe_body.timestamp  = &tv.tv_sec;
  s.safe_body.usec       = &usec;
  if (auth_context->flags & KRB5_AUTH_CONTEXT_DO_SEQUENCE) {
      tmp_seq = ++auth_context->local_seqnumber;
      s.safe_body.seq_number = &tmp_seq;
  } else 
      s.safe_body.seq_number = NULL;

  s.safe_body.s_address = auth_context->local_address;
  s.safe_body.r_address = auth_context->remote_address;

  s.cksum.cksumtype       = 0;
  s.cksum.checksum.data   = NULL;
  s.cksum.checksum.length = 0;

  r = encode_KRB_SAFE (buf + sizeof(buf) - 1,
		       sizeof(buf),
		       &s,
		       &len);

  if (r)
    return r;

  r = krb5_create_checksum (context,
			    auth_context->cksumtype,
			    buf + sizeof(buf) - len,
			    len,
			    &auth_context->key,
			    &s.cksum);
  if (r)
    return r;

  r = encode_KRB_SAFE (buf + sizeof(buf) - 1, sizeof(buf), &s, &len);
  if (r)
    return r;

  outbuf->length = len;
  outbuf->data   = malloc (len);
  if (outbuf->data == NULL)
    return ENOMEM;
  memcpy (outbuf->data, buf + sizeof(buf) - len, len);
  return 0;
}
