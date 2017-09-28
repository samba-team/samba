/* krb5-types.h -- this file was generated for i686-pc-linux-gnu by
                   $Id: bits.c,v 1.23 2005/01/05 15:22:02 lha Exp $ */

#ifndef __samba_krb5_types_h__
#define __samba_krb5_types_h__

#include "replace.h"
#include "system/network.h"
#include "lib/util/attr.h"

#if defined USING_SYSTEM_KRB5 && defined HEIMDAL_KRB5_TYPES_PATH
#include HEIMDAL_KRB5_TYPES_PATH
#else
typedef socklen_t krb5_socklen_t;
typedef int krb5_socket_t;
typedef ssize_t krb5_ssize_t;
#endif


#ifndef HEIMDAL_DEPRECATED
#define HEIMDAL_DEPRECATED _DEPRECATED_
#endif

#ifndef HEIMDAL_PRINTF_ATTRIBUTE
#ifdef HAVE_ATTRIBUTE_PRINTF
#define HEIMDAL_PRINTF_ATTRIBUTE(x) __attribute__((format x))
#else
#define HEIMDAL_PRINTF_ATTRIBUTE(x)
#endif
#endif

#ifndef HEIMDAL_NORETURN_ATTRIBUTE
#ifdef HAVE___ATTRIBUTE__
#define HEIMDAL_NORETURN_ATTRIBUTE __attribute__((noreturn))
#else
#define HEIMDAL_NORETURN_ATTRIBUTE
#endif
#endif

#ifndef HEIMDAL_UNUSED_ATTRIBUTE
#ifdef HAVE___ATTRIBUTE__
#define HEIMDAL_UNUSED_ATTRIBUTE __attribute__((unused))
#else
#define HEIMDAL_UNUSED_ATTRIBUTE
#endif
#endif

#ifndef HEIMDAL_WARN_UNUSED_RESULT_ATTRIBUTE
#ifdef HAVE___ATTRIBUTE__
#define HEIMDAL_WARN_UNUSED_RESULT_ATTRIBUTE _WARN_UNUSED_RESULT_
#else
#define HEIMDAL_WARN_UNUSED_RESULT_ATTRIBUTE
#endif
#endif

#endif /* __samb_krb5_types_h__ */
