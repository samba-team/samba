#ifndef	_ERR_H
#define	_ERR_H	1

void err(int eval, const char *format, ...);
void errx(int eval, const char *format, ...);
void warnx(const char *format, ...);

#endif	/* err.h */
