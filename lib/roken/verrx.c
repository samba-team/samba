#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "err.h"

RCSID("$Id$");

void
verrx(int eval, const char *fmt, va_list ap)
{
#if 0
  fprintf(stderr, "%s: ", __progname);
#endif
  if (fmt != NULL)
    vfprintf(stderr, fmt, ap);
  fprintf(stderr, "\n");
  exit(eval);
}
