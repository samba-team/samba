#include "gssapi_locl.h"

RCSID("$Id$");

OM_uint32 gss_add_oid_set_member (
            OM_uint32 * minor_status,
            const gss_OID member_oid,
            gss_OID_set * oid_set
           )
{
  size_t n = (*oid_set)->count;

  (*oid_set)->elements = realloc ((*oid_set)->elements,
				  n * sizeof(gss_OID_desc));
  if ((*oid_set)->elements == NULL) {
    return GSS_S_FAILURE;
  }
  (*oid_set)->count = n;
  (*oid_set)->elements[n-1] = *member_oid;
  return GSS_S_COMPLETE;
}
