/* $Id$ */

#ifndef __ERR_H__
#define __ERR_H__

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

extern const char *__progname;

#ifndef __GNUC__
#define __attribute__(x)
#endif

void warnerr(int doexit, int eval, int doerrno, const char *fmt, va_list ap)
     __attribute__ ((noreturn, format (printf, 4, 0)));

void verr(int eval, const char *fmt, va_list ap)
     __attribute__ ((noreturn, format (printf, 2, 0)));
void err(int eval, const char *fmt, ...)
     __attribute__ ((noreturn, format (printf, 2, 3)));
void verrx(int eval, const char *fmt, va_list ap)
     __attribute__ ((noreturn, format (printf, 2, 0)));
void errx(int eval, const char *fmt, ...)
     __attribute__ ((noreturn, format (printf, 2, 3)));
void vwarn(const char *fmt, va_list ap)
     __attribute__ ((format (printf, 1, 0)));
void warn(const char *fmt, ...)
     __attribute__ ((format (printf, 1, 2)));
void vwarnx(const char *fmt, va_list ap)
     __attribute__ ((format (printf, 1, 0)));
void warnx(const char *fmt, ...)
     __attribute__ ((format (printf, 1, 2)));

#endif /* __ERR_H__ */
