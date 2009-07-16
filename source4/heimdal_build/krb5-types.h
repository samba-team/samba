/* krb5-types.h -- this file was generated for i686-pc-linux-gnu by
                   $Id: bits.c,v 1.23 2005/01/05 15:22:02 lha Exp $ */

#ifndef __krb5_types_h__
#define __krb5_types_h__

#include "replace.h"
#include "system/network.h"

typedef socklen_t krb5_socklen_t;
typedef ssize_t krb5_ssize_t;

#ifndef GSSAPI_DEPRECATED
#if (__GNUC__ >= 3) && (__GNUC_MINOR__ >= 1 )
#define GSSAPI_DEPRECATED __attribute__ ((deprecated))
#else
#define GSSAPI_DEPRECATED
#endif
#endif

#endif /* __krb5_types_h__ */
