#ifndef __ERR_H__
#define __ERR_H__

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

extern char *__progname;

void verr(int eval, const char *fmt, va_list ap);
void err(int eval, const char *fmt, ...);
void verrx(int eval, const char *fmt, va_list ap);
void errx(int eval, const char *fmt, ...);
void vwarn(const char *fmt, va_list ap);
void warn(const char *fmt, ...);
void vwarnx(const char *fmt, va_list ap);
void warnx(const char *fmt, ...);

#endif /* __ERR_H__ */
