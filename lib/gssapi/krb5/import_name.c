#include "gssapi_locl.h"

RCSID("$Id$");

OM_uint32 gss_import_name
           (OM_uint32 * minor_status,
            const gss_buffer_t input_name_buffer,
            const gss_OID input_name_type,
            gss_name_t * output_name
           )
{
  krb5_error_code kerr;
  char *tmp;

  gssapi_krb5_init ();

  tmp = malloc (input_name_buffer->length + 1);
  if (tmp == NULL) {
    return GSS_S_FAILURE;
  }
  memcpy (tmp,
	  input_name_buffer->value,
	  input_name_buffer->length);
  tmp[input_name_buffer->length] = '\0';

  kerr = krb5_parse_name (gssapi_krb5_context,
			  tmp,
			  output_name);
  free (tmp);
  if (kerr == 0)
    return GSS_S_COMPLETE;
  else if (kerr == KRB5_PARSE_ILLCHAR || kerr == KRB5_PARSE_MALFORMED)
    return GSS_S_BAD_NAME;
  else
    return GSS_S_FAILURE;
}
