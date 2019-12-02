/* krb5-types.h -- this file was generated for i686-pc-linux-gnu by
                   $Id: bits.c,v 1.23 2005/01/05 15:22:02 lha Exp $ */

#ifndef __samba_krb5_types_h__
#define __samba_krb5_types_h__

#include "replace.h"
#include "system/network.h"

#if defined USING_SYSTEM_KRB5 && defined HEIMDAL_KRB5_TYPES_PATH
#include HEIMDAL_KRB5_TYPES_PATH
#else
typedef socklen_t krb5_socklen_t;
typedef int krb5_socket_t;
typedef ssize_t krb5_ssize_t;
#endif

#endif /* __samb_krb5_types_h__ */
