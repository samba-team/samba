/*
  this is a replacement config.h for building the heimdal parts of the
  Samba source tree
*/

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

#ifndef MAXPATHLEN
#define MAXPATHLEN (1024+4)
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
#define HAVE_H_ERRNO
#define HAVE_INET_ATON
#define HAVE_LONG_LONG
#define HAVE_GETHOSTNAME
#define HAVE_SOCKLEN_T
#define HAVE_GETNAMEINFO
#define HAVE_STRUCT_WINSIZE
#define HAVE_STRUCT_SOCKADDR_STORAGE
#define HAVE_STRUCT_ADDRINFO
#define HAVE_GAI_STRERROR

/* setup correct defines for capabilities of our version of heimdal */
#define KRB5
#define HAVE_KRB5_SET_REAL_TIME
#define HAVE_KRB5_LOG_CONTROL
#define HAVE_KRB5_INITLOG
#define HAVE_KRB5_ADDLOG_FUNC
#define HAVE_KRB5_FREELOG
#define HAVE_KRB5_SET_WARN_DEST
#define HAVE_KRB5_LOG_FACILITY
#define HAVE_KRB5_AUTH_CON_SETKEY
#define HAVE_ADDR_TYPE_IN_KRB5_ADDRESS
#define HAVE_KRB5_GET_PW_SALT
#define HAVE_KRB5_STRING_TO_KEY_SALT
#define HAVE_KRB5_GET_DEFAULT_IN_TKT_ETYPES
#define HAVE_KRB5_SESSION_IN_CREDS
#define HAVE_KRB5_KEYBLOCK_KEYVALUE
#define HAVE_KRB5_C_ENCTYPE_COMPARE
#define HAVE_KRB5_KT_FREE_ENTRY
#define HAVE_KRB5_PRINCIPAL_GET_COMP_STRING

#include <sys/types.h>
#include "lib/replace/replace.h"
#endif
