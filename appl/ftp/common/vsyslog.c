#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#ifndef HAVE_VSYSLOG

#include <syslog.h>
#include <stdarg.h>

void vsyslog(int pri, const char *fmt, va_list ap)
{
  char buf[10240];
  vsprintf(buf, fmt, ap);
  syslog(pri, buf);
}

#endif
