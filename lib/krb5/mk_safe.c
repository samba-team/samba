#include <krb5_locl.h>
#include <krb5_error.h>
#include "md4.h"

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
  krb5_addresses addr;
  Checksum c;
  u_char buf[1024];
  int len;

  r = krb5_create_checksum (context,
			    CKSUMTYPE_RSA_MD4,
			    userdata->data,
			    userdata->length,
			    &c);
  if (r)
    return r;

  r = krb5_get_all_client_addrs (&addr);
  if (r)
    return r;

  s.pvno = 5;
  s.msg_type = krb_safe;
  s.safe_body.user_data = *userdata;
  gettimeofday (&tv, NULL);
  usec = tv.tv_usec;
  s.safe_body.timestamp  = &tv.tv_sec;
  s.safe_body.usec       = &usec;
  s.safe_body.seq_number = NULL;
  s.safe_body.s_address.addr_type = addr.addrs[0].type;
  s.safe_body.s_address.address   = addr.addrs[0].address;
  s.safe_body.r_address = NULL;

  len = encode_KRB_SAFE (buf + sizeof(buf) - 1, sizeof(buf), &s);
  if (len < 0)
    return ASN1_PARSE_ERROR;
  outbuf->length = len;
  outbuf->data   = malloc (len);
  if (outbuf->data == NULL)
    return ENOMEM;
  memcpy (outbuf->data, buf + sizeof(buf) - len, len);
  return 0;
}
