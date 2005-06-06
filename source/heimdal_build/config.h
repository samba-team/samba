/*
  this is a replacement config.h for building the heimdal parts of the
  Samba source tree
*/

/* bring in the samba4 config.h */
#include "include/config.h"

#define RCSID(msg) \
static /**/const char *const rcsid[] = { (const char *)rcsid, "\100(#)" msg }

#ifdef VOID_RETSIGTYPE
#define SIGRETURN(x) return
#else
#define SIGRETURN(x) return (RETSIGTYPE)(x)
#endif

#ifndef MAXPATHLEN
#define MAXPATHLEN (1024+4)
#endif

/* path to sysconf - should we force this to samba LIBDIR ? */
#define SYSCONFDIR "/etc"

#define KRB5

/* Maximum values on all known systems */
#define MaxHostNameLen (64+4)
#define MaxPathLen (1024+4)

#define HAVE_H_ERRNO

#define HAVE_LONG_LONG 1

#define VERSIONLIST {"Lorikeet-Heimdal, Modified for Samba4 0.7rc1"}


#undef HAVE_DLOPEN
