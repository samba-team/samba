#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdarg.h>

RCSID("$Id$");

int snprintf(char *s, int n, const char *fmt, ...)
{
  int ret;
  va_list ap;
  va_start(ap, fmt);
  ret = vsprintf(s, fmt, ap);
  va_end(ap);
  return ret;
}
