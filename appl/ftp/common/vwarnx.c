#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "err.h"

RCSID("$Id$");

void
vwarnx(const char *fmt, va_list ap)
{
  fprintf(stderr, "%s: ", __progname);
  if (fmt != NULL)
    vfprintf(stderr, fmt, ap);
  fprintf(stderr, "\n");
}
