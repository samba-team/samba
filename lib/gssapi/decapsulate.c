#include "gssapi_locl.h"

RCSID("$Id$");

/*
 * Remove the GSS-API wrapping from `in_token' giving `out_data.
 * Does not copy data, so just free `in_token'.
 */

OM_uint32
gssapi_krb5_decapsulate(
			gss_buffer_t input_token_buffer,
			krb5_data *out_data,
			u_char *type
)
{
  u_char *p;
  size_t len;

  p = input_token_buffer->value;
  len = GSS_KRB5_MECHANISM->length + 6;
  if (
      input_token_buffer->length < len
      || memcmp (p, "\x60\x07\x06\x05", 4) != 0
      || memcmp (p + 4, GSS_KRB5_MECHANISM->elements,
		 GSS_KRB5_MECHANISM->length) != 0)
    return GSS_S_BAD_MECH;
  if (memcmp (p + 4 + GSS_KRB5_MECHANISM->length,
	      type, 2) != 0)
    return GSS_S_DEFECTIVE_TOKEN;

  out_data->length = input_token_buffer->length - len;
  out_data->data   = (u_char *)input_token_buffer->value  + len;

  return GSS_S_COMPLETE;
}
