#include <krb5_locl.h>

RCSID("$Id$");

krb5_error_code
krb5_mk_rep(krb5_context context,
	    krb5_auth_context *auth_context,
	    krb5_data *outbuf)
{
  krb5_error_code ret;
  AP_REP ap;
  EncAPRepPart body;
  u_char buf[1024], *p;
  size_t len;
  des_cblock key;
  des_key_schedule schedule;

  ap.pvno = 5;
  ap.msg_type = krb_ap_rep;

  body.ctime = (*auth_context)->authenticator->ctime;
  body.cusec = (*auth_context)->authenticator->cusec;
  body.subkey = NULL;
  if ((*auth_context)->flags & KRB5_AUTH_CONTEXT_DO_SEQUENCE) {
    krb5_generate_seq_number (context,
			      &(*auth_context)->key,
			      &(*auth_context)->local_seqnumber);
    body.seq_number = malloc (sizeof(*body.seq_number));
    *(body.seq_number) = (*auth_context)->local_seqnumber;
  } else
    body.seq_number = NULL;

  ap.enc_part.etype = (*auth_context)->key.keytype;
  ap.enc_part.kvno  = NULL;
  encode_EncAPRepPart (buf + sizeof(buf) - 1, sizeof(buf), &body, &len);
  ret = krb5_encrypt (context, buf + sizeof(buf) - len, len,
		      ap.enc_part.etype,
		      &(*auth_context)->key, &ap.enc_part.cipher);
  if (ret)
    return ret;

  encode_AP_REP (buf + sizeof(buf) - 1, sizeof(buf), &ap, &len);
  free (ap.enc_part.cipher.data);
  outbuf->length = len;
  outbuf->data = malloc(len);
  memcpy(outbuf->data, buf + sizeof(buf) - len, len);
  return 0;
}
