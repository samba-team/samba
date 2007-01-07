#ifdef HAVE_ERR_H
#include <err.h>
#else

#ifndef	_ERR_H
#define	_ERR_H	1

void err(int eval, const char *format, ...);
void errx(int eval, const char *format, ...);
void warnx(const char *format, ...);
void warn(const char *format, ...);

#endif	/* err.h */
#endif /* HAVE_ERR_H */
