#include "gssapi_locl.h"

RCSID("$Id$");

OM_uint32 gss_inquire_context (
            OM_uint32 * minor_status,
            const gss_ctx_id_t context_handle,
            gss_name_t * src_name,
            gss_name_t * targ_name,
            OM_uint32 * lifetime_rec,
            gss_OID * mech_type,
            OM_uint32 * ctx_flags,
            int * locally_initiated,
            int * open
           )
{
  OM_uint32 ret;

  if (src_name) {
    ret = gss_duplicate_name (minor_status,
			      context_handle->source,
			      src_name);
    if (ret)
      return ret;
  }

  if (targ_name) {
    ret = gss_duplicate_name (minor_status,
			      context_handle->target,
			      targ_name);
    if (ret)
      return ret;
  }

  if (lifetime_rec)
    *lifetime_rec = GSS_C_INDEFINITE;

  if (mech_type)
    *mech_type = GSS_KRB5_MECHANISM;

  if (ctx_flags)
    *ctx_flags = context_handle->flags;

  if (locally_initiated)
    *locally_initiated = context_handle->more_flags & LOCAL;

  if (open)
    *open = context_handle->more_flags & OPEN;

  return GSS_S_COMPLETE;
}
