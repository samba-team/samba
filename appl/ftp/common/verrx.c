#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "err.h"

RCSID("$Id$");

void
verrx(int eval, const char *fmt, va_list ap)
{
  fprintf(stderr, "%s: ", __progname);
  if (fmt != NULL)
    vfprintf(stderr, fmt, ap);
  fprintf(stderr, "\n");
  exit(eval);
}
