#ifdef HAVE_CONFIG_H
#include <config.h>
RCSID("$Id$");
#endif

#include "err.h"

void
err(int eval, const char *fmt, ...)
{
  va_list ap;
  va_start(ap, fmt);
  verr(eval, fmt, ap);
  va_end(ap);
}
