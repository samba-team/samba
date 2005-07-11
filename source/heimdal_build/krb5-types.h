/* krb5-types.h -- this file was generated for i686-pc-linux-gnu by
                   $Id: bits.c,v 1.23 2005/01/05 15:22:02 lha Exp $ */

#ifndef __krb5_types_h__
#define __krb5_types_h__

#if HAVE_INTTYPES_H
#include <inttypes.h>
#endif
#if HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#if HAVE_SYS_BITYPES_H
#include <sys/bitypes.h>
#endif
#include <sys/socket.h>


typedef socklen_t krb5_socklen_t;
#include <unistd.h>
typedef ssize_t krb5_ssize_t;

#endif /* __krb5_types_h__ */
