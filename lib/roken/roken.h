/* $Id$ */

#ifndef __ROKEN_H__
#define __ROKEN_H__

#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <netinet/in.h>

#include "protos.h"

#ifndef HAVE_PUTENV
int putenv(const char *string);
#endif

#ifndef HAVE_SETENV
int setenv(const char *var, const char *val, int rewrite);
#endif

#ifndef HAVE_UNSETENV
void unsetenv(const char *name);
#endif

#ifndef HAVE_GETUSERSHELL
char *getusershell(void);
#endif

#ifndef HAVE_STRDUP
char * strdup(const char *old);
#endif

#ifndef HAVE_GETDTABLESIZE
int getdtablesize(void);
#endif

#if IRIX != 4 /* fix for compiler bug */
#ifdef RETSIGTYPE
typedef RETSIGTYPE (*SigAction)(/* int??? */);
SigAction signal(int iSig, SigAction pAction); /* BSD compatible */
#endif
#endif

#if !defined(HAVE_STRERROR) && !defined(strerror)
char *strerror(int eno);
#endif

#ifndef HAVE_HSTRERROR
char *hstrerror(int herr);
#endif

#ifndef HAVE_H_ERRNO
extern int h_errno;
#endif

#ifndef HAVE_HERROR
void herror(char *s);
#endif

#ifndef HAVE_INET_ATON
/* Minimal implementation of inet_aton. Doesn't handle hex numbers. */
#ifndef __GNUC__
int inet_aton(const char *cp, struct in_addr *adr);
#endif
#endif

#if !defined(HAVE_GETCWD)
char* getcwd(char *path, int size);
#endif

#ifndef HAVE_GETENT
int getent(char *cp, char *name);
#endif

#ifndef HAVE_GETSTR
char *getstr(char *id, char **cpp);
#endif

#include <pwd.h>
struct passwd *k_getpwnam (char *user);

#include <time.h>
#include <sys/time.h>
time_t tm2time (struct tm tm, int local);

int verify_unix_user(char *user, char *password);

void inaddr2str(struct in_addr addr, char *s, size_t len);

#endif /*  __ROKEN_H__ */
