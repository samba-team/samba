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

#if (__GNUC__ >= 3)
/** Use gcc attribute to check printf fns.  a1 is the 1-based index of
 * the parameter containing the format, and a2 the index of the first
 * argument. Note that some gcc 2.x versions don't handle this
 * properly **/
#define PRINTF_ATTRIBUTE(a1, a2) __attribute__ ((format (__printf__, a1, a2)))
#else
#define PRINTF_ATTRIBUTE(a1, a2)
#endif

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

/* we support ADS if we want it and have krb5 and ldap libs */
#if defined(WITH_ADS) && defined(HAVE_KRB5) && defined(HAVE_LDAP)
#define HAVE_ADS
#endif

/*
 * Define VOLATILE if needed.
 */

#if defined(HAVE_VOLATILE)
#define VOLATILE volatile
#else
#define VOLATILE
#endif

/*
   Samba needs type definitions for 
   int8_t,  int16_t,  int32_t, int64_t 
   uint8_t, uint16_t, uint32_t and uint64_t.

   Normally these are signed and unsigned 8, 16, 32 and 64 bit integers, but
   they actually only need to be at least 8, 16, 32 and 64 bits
   respectively. Thus if your word size is 8 bytes just defining them
   as signed and unsigned int will work.
*/

#if !defined(int8)
#define int8 int8_t
#endif

#if !defined(uint8)
#define uint8 uint8_t
#endif

#if !defined(int16)
#define int16 int16_t
#endif

#if !defined(uint16)
#define uint16 uint16_t
#endif

#if !defined(int32)
#define int32 int32_t
#endif

#if !defined(uint32)
#define uint32 uint32_t
#endif

#if !defined(int64)
#define int64 int64_t
#endif

#if !defined(uint64)
#define uint64 uint64_t
#endif

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

/* Lists, trees, caching, database... */
#include "version.h"
#include "xfile.h"
#include "talloc.h"
#include "lib/ldb/include/ldb.h"
#include "lib/tdb/include/tdb.h"
#include "lib/tdb/include/spinlock.h"
#include "lib/tdb/include/tdbutil.h"
#include "db_wrap.h"
#include "nt_status.h"
#include "trans2.h"
#include "nterr.h"
#include "charset.h"
#include "debug.h"
#include "doserr.h"
#include "enums.h"
#include "pstring.h"
#include "smb_macros.h"
#include "rpc_secdes.h"
#include "smb.h"
#include "ads.h"
#include "lib/socket/socket.h"
#include "libcli/ldap/ldap.h"
#include "nameserv.h"
#include "byteorder.h"
#include "module.h"
#include "mutex.h"
#include "librpc/ndr/libndr.h"
#include "librpc/ndr/ndr_sec.h"
#include "librpc/gen_ndr/ndr_misc.h"
#include "librpc/gen_ndr/ndr_dcerpc.h"
#include "librpc/rpc/dcerpc.h"
#include "lib/dcom/common/dcom.h"
#include "librpc/gen_ndr/ndr_dcom.h"
#include "smb_interfaces.h"
#include "smbd/server.h"
#include "smbd/service.h"
#include "structs.h"
#include "ntvfs/ntvfs.h"
#include "cli_context.h"
#include "nsswitch/winbind_client.h"

#define malloc_p(type) (type *)malloc(sizeof(type))
#define malloc_array_p(type, count) (type *)realloc_array(NULL, sizeof(type), count)
#define realloc_p(p, type, count) (type *)realloc_array(p, sizeof(type), count)

#ifndef HAVE_COMPARISON_FN_T
typedef int (*comparison_fn_t)(const void *, const void *);
#endif

/***** automatically generated prototypes *****/
#define _PRINTF_ATTRIBUTE(a1, a2) PRINTF_ATTRIBUTE(a1, a2)
#include "proto.h"
#undef _PRINTF_ATTRIBUTE
#define _PRINTF_ATTRIBUTE(a1, a2)

/* String routines */

#include "safe_string.h"

#ifdef __COMPAR_FN_T
#define QSORT_CAST (__compar_fn_t)
#endif

#ifndef QSORT_CAST
#define QSORT_CAST (int (*)(const void *, const void *))
#endif

#ifndef HAVE_PIPE
#define SYNC_DNS 1
#endif

#ifndef HAVE_STRDUP
char *strdup(const char *s);
#endif

#ifndef HAVE_MEMMOVE
void *memmove(void *dest,const void *src,int size);
#endif

#ifndef HAVE_MKTIME
time_t mktime(struct tm *t);
#endif

#ifndef HAVE_STRLCPY
size_t strlcpy(char *d, const char *s, size_t bufsize);
#endif

#ifndef HAVE_STRLCAT
size_t strlcat(char *d, const char *s, size_t bufsize);
#endif

#ifndef HAVE_STRNDUP
char *strndup(const char *s, size_t n);
#endif

#ifndef HAVE_STRNLEN
size_t strnlen(const char *s, size_t n);
#endif

#ifndef HAVE_STRTOUL
unsigned long strtoul(const char *nptr, char **endptr, int base);
#endif

#ifndef HAVE_SETENV
int setenv(const char *name, const char *value, int overwrite); 
#endif

#ifndef HAVE_VASPRINTF_DECL
int vasprintf(char **ptr, const char *format, va_list ap);
#endif

#if !defined(HAVE_BZERO) && defined(HAVE_MEMSET)
#define bzero(a,b) memset((a),'\0',(b))
#endif

extern int DEBUGLEVEL;

/* add varargs prototypes with printf checking */
#ifndef HAVE_SNPRINTF_DECL
int snprintf(char *,size_t ,const char *, ...) PRINTF_ATTRIBUTE(3,4);
#endif
#ifndef HAVE_ASPRINTF_DECL
int asprintf(char **,const char *, ...) PRINTF_ATTRIBUTE(2,3);
#endif


/* we used to use these fns, but now we have good replacements
   for snprintf and vsnprintf */
#define slprintf snprintf


/* we need to use __va_copy() on some platforms */
#ifdef HAVE_VA_COPY
#define VA_COPY(dest, src) __va_copy(dest, src)
#else
#define VA_COPY(dest, src) (dest) = (src)
#endif

#if defined(VALGRIND)
#define strlen(x) valgrind_strlen(x)
#endif

#define TALLOC_ABORT(reason) smb_panic(reason)


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

#endif /* _INCLUDES_H */

