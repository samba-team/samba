#include "gssapi_locl.h"

RCSID("$Id$");

OM_uint32 gss_release_oid_set
           (OM_uint32 * minor_status,
            gss_OID_set * set
           )
{
  free ((*set)->elements);
  free (*set);
  return GSS_S_COMPLETE;
}
