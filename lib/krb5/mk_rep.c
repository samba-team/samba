#include <krb5_locl.h>
#include <krb5_error.h>

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
  body.seq_number = NULL;

  ap.enc_part.etype = (*auth_context)->key.keytype;
  ap.enc_part.kvno  = NULL;
  len = encode_EncAPRepPart (buf + sizeof(buf) - 1,
			     sizeof(buf), &body);
  ret = krb5_encrypt (context, buf + sizeof(buf) - len, len,
		      &(*auth_context)->key, &ap.enc_part.cipher);
  if (ret)
    return ret;

#if 0
  len += 12;			/* XXX */
  ap.enc_part.cipher.length = len;
  ap.enc_part.cipher.data   = malloc(len);
  memcpy(ap.enc_part.cipher.data, buf +sizeof(buf) - len, len);

  memcpy(&key, (*auth_context)->key.contents.data, sizeof(key));
  des_set_key (&key, schedule);

  des_cbc_encrypt (ap.enc_part.cipher.data,
		   ap.enc_part.cipher.data,
		   ap.enc_part.cipher.length,
		   schedule, &key, DES_ENCRYPT);
#endif

  len = encode_AP_REP (buf + sizeof(buf) - 1,
		       sizeof(buf), &ap);
  free (ap.enc_part.cipher.data);
  outbuf->length = len;
  outbuf->data = malloc(len);
  memcpy(outbuf->data, buf + sizeof(buf) - len, len);
  return 0;
}
