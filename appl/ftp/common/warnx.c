#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "err.h"

RCSID("$Id$");

void
warnx(const char *fmt, ...)
{
  va_list ap;
  va_start(ap, fmt);
  vwarnx(fmt, ap);
  va_end(ap);
}
