#include "gssapi_locl.h"

RCSID("$Id$");

void
gssapi_krb5_init (void)
{
  static int donep = 0;

  if (donep)
    return;

  krb5_init_context (&gssapi_krb5_context);
  donep = 1;
}
