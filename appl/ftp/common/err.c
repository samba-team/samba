#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "err.h"

RCSID("$Id$");

void
err(int eval, const char *fmt, ...)
{
  va_list ap;
  va_start(ap, fmt);
  verr(eval, fmt, ap);
  va_end(ap);
}
