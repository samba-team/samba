#include "gssapi_locl.h"

RCSID("$Id$");

OM_uint32 gss_indicate_mechs
           (OM_uint32 * minor_status,
            gss_OID_set * mech_set
           )
{
  *mech_set = malloc(sizeof(**mech_set));
  if (*mech_set == NULL) {
    return GSS_S_FAILURE;
  }
  (*mech_set)->count = 1;
  (*mech_set)->elements = malloc((*mech_set)->count * sizeof(gss_OID_desc));
  if ((*mech_set)->elements == NULL) {
    free (*mech_set);
    return GSS_S_FAILURE;
  }
  (*mech_set)->elements[0] = *GSS_KRB5_MECHANISM;
  return GSS_S_COMPLETE;
}
