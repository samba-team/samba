#include "gssapi_locl.h"

RCSID("$Id$");

static krb5_error_code
encode_om_uint32(OM_uint32 n, u_char *p)
{
  p[0] = (n >> 0)  & 0xFF;
  p[1] = (n >> 8)  & 0xFF;
  p[2] = (n >> 16) & 0xFF;
  p[3] = (n >> 24) & 0xFF;
  return 0;
}

static krb5_error_code
hash_input_chan_bindings (const gss_channel_bindings_t b,
			  u_char *p)
{
  u_char num[4];
  struct md5 md5;

  md5_init(&md5);
  encode_om_uint32 (b->initiator_addrtype, num);
  md5_update (&md5, num, sizeof(num));
  encode_om_uint32 (b->initiator_address.length, num);
  md5_update (&md5, num, sizeof(num));
  if (b->initiator_address.length)
    md5_update (&md5,
		b->initiator_address.value,
		b->initiator_address.length);
  encode_om_uint32 (b->acceptor_addrtype, num);
  md5_update (&md5, num, sizeof(num));
  encode_om_uint32 (b->acceptor_address.length, num);
  md5_update (&md5, num, sizeof(num));
  if (b->acceptor_address.length)
    md5_update (&md5,
		b->acceptor_address.value,
		b->acceptor_address.length);
  encode_om_uint32 (b->application_data.length, num);
  md5_update (&md5, num, sizeof(num));
  if (b->application_data.length)
    md5_update (&md5,
		b->application_data.value,
		b->application_data.length);
  md5_finito (&md5, p);
  return 0;
}

krb5_error_code
gssapi_krb5_create_8003_checksum (
		      const gss_channel_bindings_t input_chan_bindings,
		      OM_uint32 flags,
		      Checksum *result)
{
  u_char *p;
  u_int32_t val;

  result->cksumtype = 0x8003;
  result->checksum.length = 24;
  result->checksum.data   = malloc (result->checksum.length);
  if (result->checksum.data == NULL)
    return ENOMEM;
  
  p = result->checksum.data;
  encode_om_uint32 (16, p);
  p += 4;
  if (input_chan_bindings == GSS_C_NO_CHANNEL_BINDINGS) {
    memset (p, 0, 16);
  } else {
    hash_input_chan_bindings (input_chan_bindings, p);
  }
  p += 16;
  encode_om_uint32 (flags, p);
  p += 4;
  if (p - (u_char *)result->checksum.data != result->checksum.length)
    abort ();
  return 0;
}

