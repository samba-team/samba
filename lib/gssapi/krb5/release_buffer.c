#include "gssapi_locl.h"

RCSID("$Id$");

OM_uint32 gss_release_buffer
           (OM_uint32 * minor_status,
            gss_buffer_t buffer
           )
{
  free (buffer->value);
  buffer->length = 0;
  return GSS_S_COMPLETE;
}
