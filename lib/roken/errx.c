#ifdef HAVE_CONFIG_H
#include <config.h>
RCSID("$Id$");
#endif

#include "err.h"

void
errx(int eval, const char *fmt, ...)
{
  va_list ap;
  va_start(ap, fmt);
  verrx(eval, fmt, ap);
  va_end(ap);
}
