#include "gssapi_locl.h"

RCSID("$Id$");

OM_uint32 gss_release_name
           (OM_uint32 * minor_status,
            gss_name_t * input_name
           )
{
  krb5_error_code kret;

  gssapi_krb5_init ();
  krb5_free_principal(gssapi_krb5_context,
		      *input_name);
  return GSS_S_COMPLETE;
}
