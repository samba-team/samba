#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "err.h"

RCSID("$Id$");

void
warn(const char *fmt, ...)
{
  va_list ap;
  va_start(ap, fmt);
  vwarn(fmt, ap);
  va_end(ap);
}
