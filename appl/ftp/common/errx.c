#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "err.h"

RCSID("$Id$");

void
errx(int eval, const char *fmt, ...)
{
  va_list ap;
  va_start(ap, fmt);
  verrx(eval, fmt, ap);
  va_end(ap);
}
