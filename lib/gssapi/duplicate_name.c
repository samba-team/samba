#include "gssapi_locl.h"

RCSID("$Id$");

OM_uint32 gss_duplicate_name (
            OM_uint32 * minor_status,
            const gss_name_t src_name,
            gss_name_t * dest_name
           )
{
  krb5_error_code kret;

  gssapi_krb5_init ();

  kret = krb5_copy_principal (gssapi_krb5_context,
			      src_name,
			      dest_name);
  if (kret)
    return GSS_S_FAILURE;
  else
    return GSS_S_COMPLETE;
}
