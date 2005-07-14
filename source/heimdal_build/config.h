/*
  this is a replacement config.h for building the heimdal parts of the
  Samba source tree
*/

#ifndef HAVE_HEIMDAL_CONFIG_H
#define HAVE_HEIMDAL_CONFIG_H 1

/* bring in the samba4 config.h */
#include "include/config.h"

#ifdef HAVE_KRB5

#define RCSID(msg) \
static /**/const char *const rcsid[] = { (const char *)rcsid, "\100(#)" msg }

#ifdef VOID_RETSIGTYPE
#define SIGRETURN(x) return
#else
#define SIGRETURN(x) return (RETSIGTYPE)(x)
#endif

/* path to sysconf - should we force this to samba LIBDIR ? */
#define SYSCONFDIR "/etc"


/* Maximum values on all known systems */
#define MaxHostNameLen (64+4)
#define MaxPathLen (1024+4)

#define VERSIONLIST {"Lorikeet-Heimdal, Modified for Samba4 0.7rc1"}

/* even if we do have dlopen, we don't want heimdal using it */
#undef HAVE_DLOPEN

#define VERSION "Samba"

#define ROKEN_LIB_FUNCTION

/* these should be done with configure tests */
#define KRB5

#include <sys/types.h>
#include <stdarg.h>
#include "lib/replace/replace.h"
#endif

#endif
