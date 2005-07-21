#ifndef _INCLUDES_H
#define _INCLUDES_H
/* 
   Unix SMB/CIFS implementation.
   Machine customisation and include handling
   Copyright (C) Andrew Tridgell 1994-1998
   Copyright (C) 2002 by Martin Pool <mbp@samba.org>
   
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/

#ifndef NO_CONFIG_H /* for some tests */
#include "config.h"
#include "smb_build.h"
#endif

#include "local.h"

#ifdef __GNUC__
/** gcc attribute used on function parameters so that it does not emit
 * warnings about them being unused. **/
#  define UNUSED(param) param __attribute__ ((unused))
#else
#  define UNUSED(param) param
/** Feel free to add definitions for other compilers here. */
#endif

#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <sys/time.h>

#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif

#ifdef HAVE_STRING_H
#include <string.h>
#endif

#include <signal.h>
#include <errno.h>

#ifdef HAVE_STDARG_H
#include <stdarg.h>
#else
#include <varargs.h>
#endif

#ifdef HAVE_WINSOCK2_H
#include <winsock2.h>
#endif

#ifdef HAVE_WS2TCPIP_H
#include <ws2tcpip.h>
#endif

#ifdef HAVE_WINDOWS_H
#include <windows.h>
#endif

#if defined(_MSC_VER) || defined(__MINGW32__)
#include "lib/replace/win32/replace.h"
#endif

/* we support ADS if we want it and have krb5 and ldap libs */
#if defined(WITH_ADS) && defined(HAVE_KRB5) && defined(HAVE_LDAP)
#define HAVE_ADS
#endif

/* tell ldb we have the internal ldap code */
#define HAVE_ILDAP 1

/*
 * Define VOLATILE if needed.
 */

#define False (0)
#define True (1)
#define Auto (2)

typedef int BOOL;

/*
  we use struct ipv4_addr to avoid having to include all the
  system networking headers everywhere
*/
struct ipv4_addr {
	uint32_t addr;
};

#ifndef HAVE_STRERROR
extern char *sys_errlist[];
#define strerror(i) sys_errlist[i]
#endif

#ifndef HAVE_ERRNO_DECL
extern int errno;
#endif

#include "lib/replace/replace.h"

/* Lists, trees, caching, database... */
#include "xfile.h"
#include "lib/talloc/talloc.h"
#include "nt_status.h"
#include "structs.h"
#include "trans2.h"
#include "nterr.h"
#include "charset.h"
#include "debug.h"
#include "doserr.h"
#include "enums.h"
#include "smb_macros.h"
#include "smb.h"
#include "byteorder.h"
#include "module.h"
#include "librpc/ndr/libndr.h"
#include "librpc/gen_ndr/ndr_misc.h"
#include "librpc/gen_ndr/ndr_dcerpc.h"
#include "librpc/ndr/ndr_orpc.h"
#include "librpc/gen_ndr/ndr_orpc.h"
#include "librpc/rpc/dcerpc.h"
#include "smb_interfaces.h"
#include "ntvfs/ntvfs.h"
#include "cli_context.h"
#include "lib/com/com.h"
#include "credentials.h"



#define malloc_p(type) (type *)malloc(sizeof(type))
#define malloc_array_p(type, count) (type *)realloc_array(NULL, sizeof(type), count)
#define realloc_p(p, type, count) (type *)realloc_array(p, sizeof(type), count)

/***** automatically generated prototypes *****/
#define _PRINTF_ATTRIBUTE(a1, a2) PRINTF_ATTRIBUTE(a1, a2)
#include "include/proto.h"
#undef _PRINTF_ATTRIBUTE
#define _PRINTF_ATTRIBUTE(a1, a2)

/* String routines */

#include "safe_string.h"

#ifndef HAVE_PIPE
#define SYNC_DNS 1
#endif

extern int DEBUGLEVEL;

#if defined(VALGRIND)
#define strlen(x) valgrind_strlen(x)
#endif

#if 0
/* darn, we can't do this now that we don't link the ldb tools to all the smb libs */
#define TALLOC_ABORT(reason) smb_panic(reason)
#endif

/*
  this is a warning hack. The idea is to use this everywhere that we
  get the "discarding const" warning from gcc. That doesn't actually
  fix the problem of course, but it means that when we do get to
  cleaning them up we can do it by searching the code for
  discard_const.

  It also means that other error types aren't as swamped by the noise
  of hundreds of const warnings, so we are more likely to notice when
  we get new errors.

  Please only add more uses of this macro when you find it
  _really_ hard to fix const warnings. Our aim is to eventually use
  this function in only a very few places.

  Also, please call this via the discard_const_p() macro interface, as that
  makes the return type safe.
*/
#ifdef HAVE_INTPTR_T
#define discard_const(ptr) ((void *)((intptr_t)(ptr)))
#else
#define discard_const(ptr) ((void *)(ptr))
#endif
#define discard_const_p(type, ptr) ((type *)discard_const(ptr))

#ifndef HAVE_SSIZE_T
#define ssize_t int
#endif

#ifndef UINT16_MAX
#define UINT16_MAX 65535
#endif

/*
  type safe varient of smb_xmalloc()
*/
#define smb_xmalloc_p(type) (type *)smb_xmalloc(sizeof(type))

#endif /* _INCLUDES_H */

