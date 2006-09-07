/* krb5-types.h -- this file was generated for i686-pc-linux-gnu by
                   $Id: bits.c,v 1.23 2005/01/05 15:22:02 lha Exp $ */

#ifndef __krb5_types_h__
#define __krb5_types_h__

#include "replace.h"

#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif


typedef socklen_t krb5_socklen_t;
typedef ssize_t krb5_ssize_t;

#ifdef VOID_RETSIGTYPE
#define SIGRETURN(x) return
#else
#define SIGRETURN(x) return (RETSIGTYPE)(x)
#endif

#endif /* __krb5_types_h__ */
