#include "gssapi_locl.h"

RCSID("$Id$");

OM_uint32 gss_display_name
           (OM_uint32 * minor_status,
            const gss_name_t input_name,
            gss_buffer_t output_name_buffer,
            gss_OID * output_name_type
           )
{
  krb5_error_code kret;
  char *buf;
  size_t len;

  gssapi_krb5_init ();
  kret = krb5_unparse_name (gssapi_krb5_context,
			    input_name,
			    &buf);
  if (kret)
    return GSS_S_FAILURE;
  len = strlen (buf);
  output_name_buffer->length = len;
  output_name_buffer->value  = malloc(len);
  if (output_name_buffer->value == NULL) {
    free (buf);
    return GSS_S_FAILURE;
  }
  memcpy (output_name_buffer->value, buf, len);
  free (buf);
  if (output_name_type)
      *output_name_type = GSS_KRB5_NT_PRINCIPAL_NAME;
  return GSS_S_COMPLETE;
}
