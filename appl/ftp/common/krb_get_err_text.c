#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <krb.h>

RCSID("$Id$");

const char *
krb_get_err_text(int n)
{
  return krb_err_txt[n];
}
