#include "gssapi_locl.h"

RCSID("$Id$");

OM_uint32 gss_create_empty_oid_set (
            OM_uint32 * minor_status,
            gss_OID_set * oid_set
           )
{
  *oid_set = malloc(sizeof(**oid_set));
  if (*oid_set == NULL) {
    return GSS_S_FAILURE;
  }
  (*oid_set)->count = 0;
  (*oid_set)->elements = NULL;
  return GSS_S_COMPLETE;
}
