#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

RCSID("$Id$");

#include "roken.h"

#include <stdio.h>
#include <stdarg.h>

int snprintf(char *s, int n, const char *fmt, ...)
{
  int ret;
  va_list ap;
  va_start(ap, fmt);
  ret = vsprintf(s, fmt, ap);
  va_end(ap);
  return ret;
}
