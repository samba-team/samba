#include "gssapi_locl.h"

RCSID("$Id$");

OM_uint32 gss_delete_sec_context
           (OM_uint32 * minor_status,
            gss_ctx_id_t * context_handle,
            gss_buffer_t output_token
           )
{
  gssapi_krb5_init ();
  krb5_auth_con_free (gssapi_krb5_context,
		      (*context_handle)->auth_context);
  if((*context_handle)->source)
    krb5_free_principal (gssapi_krb5_context,
			 (*context_handle)->source);
  if((*context_handle)->target)
    krb5_free_principal (gssapi_krb5_context,
			 (*context_handle)->target);
  free (*context_handle);
  if (output_token)
    output_token->length = 0;
  return GSS_S_COMPLETE;
}
