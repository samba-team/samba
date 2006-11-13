/*
  a wrapper to override some of the defines that the heimdal roken system looks at
 */
#ifndef _ROKEN_H_
#define _ROKEN_H_

/* path to sysconf - should we force this to samba LIBDIR ? */
#define SYSCONFDIR "/etc"

/* HDB module dir - set to Samba LIBDIR/hdb ? */
#define HDBDIR "/usr/heimdal/lib"
#define LIBDIR "/usr/heimdal/lib"

/* Maximum values on all known systems */
#define MaxHostNameLen (64+4)
#define MaxPathLen (1024+4)

#define VERSIONLIST {"Lorikeet-Heimdal, Modified for Samba4 0.8pre"}

#define VERSION "Samba"

#define ROKEN_LIB_FUNCTION

#define GETHOSTBYADDR_PROTO_COMPATIBLE
#define GETSERVBYNAME_PROTO_COMPATIBLE
#define OPENLOG_PROTO_COMPATIBLE
#define GETSOCKNAME_PROTO_COMPATIBLE

/* even if we do have dlopen, we don't want heimdal using it */
#undef HAVE_DLOPEN

/* we need to tell roken about the functions that Samba replaces in lib/replace */
#ifndef HAVE_SETEUID
#define HAVE_SETEUID 1
#endif

#ifndef HAVE_STRNDUP
#define HAVE_STRNDUP
#endif

#ifndef HAVE_VSYSLOG
#define HAVE_VSYSLOG
#endif

#ifndef HAVE_SOCKLEN_T
#define HAVE_SOCKLEN_T
#endif

#ifndef HAVE_SSIZE_T
#define HAVE_SSIZE_T
#endif

#ifndef HAVE_TIMEGM
#define HAVE_TIMEGM
#endif

#undef SOCKET_WRAPPER_REPLACE

#include "heimdal/lib/roken/roken.h.in"
#endif
