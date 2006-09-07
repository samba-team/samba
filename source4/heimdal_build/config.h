/*
  this is a replacement config.h for building the heimdal parts of the
  Samba source tree
*/

#ifndef HAVE_HEIMDAL_CONFIG_H
#define HAVE_HEIMDAL_CONFIG_H 1

#include "include/config.h"
#include "replace.h"

#define RCSID(msg)

#ifdef VOID_RETSIGTYPE
#define SIGRETURN(x) return
#else
#define SIGRETURN(x) return (RETSIGTYPE)(x)
#endif

/* path to sysconf - should we force this to samba LIBDIR ? */
#define SYSCONFDIR "/etc"

/* HDB module dir - set to Samba LIBDIR/hdb ? */
#define HDBDIR "/usr/heimdal/lib"

/* Maximum values on all known systems */
#define MaxHostNameLen (64+4)
#define MaxPathLen (1024+4)

#define VERSIONLIST {"Lorikeet-Heimdal, Modified for Samba4 0.7rc1"}

#define VERSION "Samba"

#define ROKEN_LIB_FUNCTION

/* these should be done with configure tests */
#define KRB5

#define GETHOSTBYADDR_PROTO_COMPATIBLE
#define GETSERVBYNAME_PROTO_COMPATIBLE
#define OPENLOG_PROTO_COMPATIBLE
#define GETSOCKNAME_PROTO_COMPATIBLE

#endif
