#include "gssapi_locl.h"

RCSID("$Id$");

OM_uint32 gss_test_oid_set_member (
            OM_uint32 * minor_status,
            const gss_OID member,
            const gss_OID_set set,
            int * present
           )
{
  size_t i;

  *present = 0;
  for (i = 0; i < set->count; ++i)
    if (member->length = set->elements[i].length
	&& memcmp (member->elements,
		   set->elements[i].elements,
		   member->length) == 0) {
      *present = 1;
      break;
    }
  return GSS_S_COMPLETE;
}
