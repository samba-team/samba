/* $Id$ */

#ifndef __ROKEN_H__
#define __ROKEN_H__

#ifndef HAVE_PUTENV
int putenv(const char *string)
#endif

#ifndef HAVE_SETENV
int setenv(const char *var, const char *val, int rewrite);
#endif

#ifndef HAVE_GETUSERSHELL
char *getusershell __P((void));
#endif

#ifndef HAVE_STRDUP
char * strdup(const char *old);
#endif

#ifndef HAVE_GETDTABLESIZE
int getdtablesize(void);
#endif

#ifdef RETSIGTYPE
typedef RETSIGTYPE (*SigAction)(/* int??? */);
SigAction signal(int iSig, SigAction pAction); /* BSD compatible */
#endif

#ifndef HAVE_SNPRINTF
int snprintf(char *s, int n, const char *fmt, ...);
#endif

#ifndef HAVE_STRERROR
char *strerror(int eno);
#endif

#ifndef HAVE_HSTRERROR
char *hstrerror(int herr);
#endif

#ifndef HAVE_INET_ATON
/* Minimal implementation of inet_aton. Doesn't handle hex numbers. */
#ifndef __GNUC__
int inet_aton(char *cp, struct in_addr *adr);
#endif
#endif

#if !defined(HAVE_GETCWD) || defined(BROKEN_GETCWD)
char* getcwd(char *path, int size)
#endif

#endif /*  __ROKEN_H__ */
