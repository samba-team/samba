#include "gssapi_locl.h"

RCSID("$Id$");

/*
 * Give it a krb5_data and it will encapsulate with extra GSS-API wrappings.
 */

OM_uint32
gssapi_krb5_encapsulate(
			krb5_data *in_data,
			gss_buffer_t output_token,
			u_char *type
)
{
  u_char *p;

  output_token->length = in_data->length + GSS_KRB5_MECHANISM->length + 6;
  output_token->value  = malloc (output_token->length);
  if (output_token->value == NULL)
    return GSS_S_FAILURE;

  p = output_token->value;
  memcpy (p, "\x60\x07\x06\x05", 4);
  p += 4;
  memcpy (p, GSS_KRB5_MECHANISM->elements, GSS_KRB5_MECHANISM->length);
  p += GSS_KRB5_MECHANISM->length;
  memcpy (p, type, 2);
  p += 2;
  memcpy (p, in_data->data, in_data->length);
  krb5_data_free (in_data);
  return GSS_S_COMPLETE;
}
