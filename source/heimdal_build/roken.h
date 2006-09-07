/*
  a wrapper to avoid double inclusion of the real roken.h
 */
#ifndef _ROKEN_H_
#define _ROKEN_H_
#include "heimdal_build/config.h"

/* even if we do have dlopen, we don't want heimdal using it */
#undef HAVE_DLOPEN

/* we need to tell roken about the functions that Samba replaces in lib/replace */
#ifndef HAVE_SETEUID
#define HAVE_SETEUID 1
#endif

#ifndef HAVE_SOCKLEN_T
#define HAVE_SOCKLEN_T
#endif

#ifndef HAVE_STRNDUP
#define HAVE_STRNDUP
#endif
#ifndef HAVE_SOCKLEN_T
#define HAVE_SOCKLEN_T
#endif

#ifndef HAVE_SSIZE_T
#define HAVE_SSIZE_T
#endif



#include "heimdal/lib/roken/roken.h"
#endif
