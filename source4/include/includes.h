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

#ifdef AIX
#define DEFAULT_PRINTING PRINT_AIX
#define PRINTCAP_NAME "/etc/qconfig"
#endif

#ifdef HPUX
#define DEFAULT_PRINTING PRINT_HPUX
#endif

#ifdef QNX
#define DEFAULT_PRINTING PRINT_QNX
#endif

#ifdef SUNOS4
/* on SUNOS4 termios.h conflicts with sys/ioctl.h */
#undef HAVE_TERMIOS_H
#endif

#ifndef DEFAULT_PRINTING
#define DEFAULT_PRINTING PRINT_BSD
#endif
#ifndef PRINTCAP_NAME
#define PRINTCAP_NAME "/etc/printcap"
#endif

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

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <sys/types.h>
#include <stdint.h>

#ifdef HAVE_SYS_RESOURCE_H
#include <sys/resource.h>
#endif

#include <unistd.h>

#include <stdio.h>
#include <stddef.h>

#ifdef HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif

#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif

#ifdef HAVE_STRING_H
#include <string.h>
#endif

#ifdef HAVE_STRINGS_H
#include <strings.h>
#endif

#ifdef HAVE_MEMORY_H
#include <memory.h>
#endif

#ifdef HAVE_MALLOC_H
#include <malloc.h>
#endif

#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#else
#ifdef HAVE_SYS_FCNTL_H
#include <sys/fcntl.h>
#endif
#endif

#include <sys/stat.h>

#ifdef HAVE_LIMITS_H
#include <limits.h>
#endif

#ifdef HAVE_SYS_IOCTL_H
#include <sys/ioctl.h>
#endif

#ifdef HAVE_SYS_FILIO_H
#include <sys/filio.h>
#endif

#include <signal.h>

#ifdef HAVE_CTYPE_H
#include <ctype.h>
#endif

#include <errno.h>

#ifdef HAVE_SYS_MODE_H
/* apparently AIX needs this for S_ISLNK */
#ifndef S_ISLNK
#include <sys/mode.h>
#endif
#endif

#ifdef HAVE_STDARG_H
#include <stdarg.h>
#else
#include <varargs.h>
#endif

#include <sys/file.h>

#ifdef HAVE_STROPTS_H
#include <stropts.h>
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
 * Define additional missing types
 */
#ifndef HAVE_SIG_ATOMIC_T_TYPE
typedef int sig_atomic_t;
#endif

#ifndef HAVE_SOCKLEN_T_TYPE
typedef int socklen_t;
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

/*
  we use struct ipv4_addr to avoid having to include all the
  system networking headers everywhere
*/
struct ipv4_addr {
	uint32_t s_addr;
};

#ifndef UINT8_MAX
#define UINT8_MAX 255
#endif

#ifndef UINT16_MAX
#define UINT16_MAX 65535
#endif

/*
 * Type for stat structure.
 */

#ifndef MIN
#define MIN(a,b) ((a)<(b)?(a):(b))
#endif

#ifndef MAX
#define MAX(a,b) ((a)>(b)?(a):(b))
#endif

#ifndef HAVE_STRERROR
extern char *sys_errlist[];
#define strerror(i) sys_errlist[i]
#endif

#ifndef HAVE_ERRNO_DECL
extern int errno;
#endif

#ifdef HAVE_BROKEN_GETGROUPS
#define GID_T int
#else
#define GID_T gid_t
#endif

#ifndef NGROUPS_MAX
#define NGROUPS_MAX 32 /* Guess... */
#endif

/* Our own pstrings and fstrings */
#include "pstring.h"

/* Lists, trees, caching, database... */
#include "xfile.h"
#include "dlinklist.h"
#include "lib/ldb/include/ldb.h"
#include "lib/tdb/include/tdb.h"
#include "lib/tdb/include/spinlock.h"
#include "lib/tdb/include/tdbutil.h"
#include "talloc.h"
#include "db_wrap.h"
#include "nt_status.h"
#include "trans2.h"
#include "ioctl.h"
#include "nterr.h"
#include "messages.h"
#include "charset.h"
#include "dynconfig.h"

#include "version.h"
#include "rewrite.h"
#include "smb.h"
#include "ads.h"
#include "lib/socket/socket.h"
#include "libcli/ldap/ldap.h"
#include "nameserv.h"
#include "secrets.h"

#include "byteorder.h"

#include "md5.h"
#include "hmacmd5.h"


#include "module.h"

#include "asn_1.h"

#include "mutex.h"

#include "structs.h"
#include "librpc/ndr/libndr.h"
#include "librpc/ndr/ndr_sec.h"
#include "librpc/gen_ndr/ndr_misc.h"
#include "librpc/gen_ndr/ndr_dcerpc.h"
#include "librpc/rpc/dcerpc.h"
#include "librpc/gen_ndr/tables.h"

#include "libcli/auth/ntlmssp.h"
#include "libcli/auth/credentials.h"
#include "libcli/auth/gensec.h"
#include "libcli/auth/spnego.h"
#include "auth/auth.h"

#include "smb_interfaces.h"
#include "smbd/server.h"
#include "smbd/service.h"
#include "rpc_server/dcerpc_server.h"
#include "request.h"
#include "signing.h"
#include "smb_server/smb_server.h"
#include "ntvfs/ntvfs.h"
#include "cli_context.h"
#include "registry.h"
#include "rap.h"
#include "ldap_server/ldap_server.h"

#include "libnet/libnet.h"
#include "utils/net/net.h"

#include "nsswitch/winbind_client.h"

/* hmm, this really is getting ugly isn't it .... we probably need to
   have some way to have subsystem includes without including it
   globally */
#include "ntvfs/posix/vfs_posix.h"

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

#ifndef SIGCLD
#define SIGCLD SIGCHLD
#endif

#ifndef MAP_FILE
#define MAP_FILE 0
#endif

#if defined(HAVE_PUTPRPWNAM) && defined(AUTH_CLEARTEXT_SEG_CHARS)
#define OSF1_ENH_SEC 1
#endif

#ifndef ALLOW_CHANGE_PASSWORD
#if (defined(HAVE_TERMIOS_H) && defined(HAVE_DUP2) && defined(HAVE_SETSID))
#define ALLOW_CHANGE_PASSWORD 1
#endif
#endif

/* what is the longest significant password available on your system? 
 Knowing this speeds up password searches a lot */
#ifndef PASSWORD_LENGTH
#define PASSWORD_LENGTH 8
#endif

#ifdef REPLACE_INET_NTOA
#define inet_ntoa rep_inet_ntoa
#endif

#ifndef HAVE_PIPE
#define SYNC_DNS 1
#endif

#ifndef MAXPATHLEN
#define MAXPATHLEN 256
#endif

#ifndef SEEK_SET
#define SEEK_SET 0
#endif

#ifndef INADDR_LOOPBACK
#define INADDR_LOOPBACK 0x7f000001
#endif

#ifndef INADDR_NONE
#define INADDR_NONE 0xffffffff
#endif

#ifndef HAVE_CRYPT
#define crypt ufc_crypt
#endif

#ifndef O_ACCMODE
#define O_ACCMODE (O_RDONLY | O_WRONLY | O_RDWR)
#endif

#if defined(HAVE_CRYPT16) && defined(HAVE_GETAUTHUID)
#define ULTRIX_AUTH 1
#endif

#ifndef HAVE_STRDUP
char *strdup(const char *s);
#endif

#ifndef HAVE_MEMMOVE
void *memmove(void *dest,const void *src,int size);
#endif

#ifndef HAVE_INITGROUPS
int initgroups(char *name,gid_t id);
#endif

#ifndef HAVE_RENAME
int rename(const char *zfrom, const char *zto);
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

#ifndef HAVE_FTRUNCATE
int ftruncate(int f,long l);
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

#ifdef REPLACE_GETPASS
#define getpass(prompt) getsmbpass((prompt))
#endif

/*
 * Some older systems seem not to have MAXHOSTNAMELEN
 * defined.
 */
#ifndef MAXHOSTNAMELEN
#define MAXHOSTNAMELEN 254
#endif

/* yuck, I'd like a better way of doing this */
#define DIRP_SIZE (256 + 32)

/*
 * glibc on linux doesn't seem to have MSG_WAITALL
 * defined. I think the kernel has it though..
 */

#ifndef MSG_WAITALL
#define MSG_WAITALL 0
#endif

/* default socket options. Dave Miller thinks we should default to TCP_NODELAY
   given the socket IO pattern that Samba uses */
#ifdef TCP_NODELAY
#define DEFAULT_SOCKET_OPTIONS "TCP_NODELAY"
#else
#define DEFAULT_SOCKET_OPTIONS ""
#endif

/* Load header file for dynamic linking stuff */

#ifdef HAVE_DLFCN_H
#include <dlfcn.h>
#endif

/* dmalloc -- free heap debugger (dmalloc.org).  This should be near
 * the *bottom* of include files so as not to conflict. */
#ifdef ENABLE_DMALLOC
#  include <dmalloc.h>
#endif


/* Some POSIX definitions for those without */
 
#ifndef S_IFDIR
#define S_IFDIR         0x4000
#endif
#ifndef S_ISDIR
#define S_ISDIR(mode)   ((mode & 0xF000) == S_IFDIR)
#endif
#ifndef S_IRWXU
#define S_IRWXU 00700           /* read, write, execute: owner */
#endif
#ifndef S_IRUSR
#define S_IRUSR 00400           /* read permission: owner */
#endif
#ifndef S_IWUSR
#define S_IWUSR 00200           /* write permission: owner */
#endif
#ifndef S_IXUSR
#define S_IXUSR 00100           /* execute permission: owner */
#endif
#ifndef S_IRWXG
#define S_IRWXG 00070           /* read, write, execute: group */
#endif
#ifndef S_IRGRP
#define S_IRGRP 00040           /* read permission: group */
#endif
#ifndef S_IWGRP
#define S_IWGRP 00020           /* write permission: group */
#endif
#ifndef S_IXGRP
#define S_IXGRP 00010           /* execute permission: group */
#endif
#ifndef S_IRWXO
#define S_IRWXO 00007           /* read, write, execute: other */
#endif
#ifndef S_IROTH
#define S_IROTH 00004           /* read permission: other */
#endif
#ifndef S_IWOTH
#define S_IWOTH 00002           /* write permission: other */
#endif
#ifndef S_IXOTH
#define S_IXOTH 00001           /* execute permission: other */
#endif

/* For sys_adminlog(). */
#ifndef LOG_EMERG
#define LOG_EMERG       0       /* system is unusable */
#endif

#ifndef LOG_ALERT
#define LOG_ALERT       1       /* action must be taken immediately */
#endif

#ifndef LOG_CRIT
#define LOG_CRIT        2       /* critical conditions */
#endif

#ifndef LOG_ERR
#define LOG_ERR         3       /* error conditions */
#endif

#ifndef LOG_WARNING
#define LOG_WARNING     4       /* warning conditions */
#endif

#ifndef LOG_NOTICE
#define LOG_NOTICE      5       /* normal but significant condition */
#endif

#ifndef LOG_INFO
#define LOG_INFO        6       /* informational */
#endif

#ifndef LOG_DEBUG
#define LOG_DEBUG       7       /* debug-level messages */
#endif

extern int DEBUGLEVEL;

#ifndef RTLD_LAZY
#define RTLD_LAZY 0
#endif

/* needed for some systems without iconv. Doesn't really matter
   what error code we use */
#ifndef EILSEQ
#define EILSEQ EIO
#endif

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

#ifndef HAVE_TIMEGM
time_t timegm(struct tm *tm);
#endif

#if defined(VALGRIND)
#define strlen(x) valgrind_strlen(x)
#endif

/*
 * Veritas File System.  Often in addition to native.
 * Quotas different.
 */
#if defined(HAVE_SYS_FS_VX_QUOTA_H)
#define VXFS_QUOTA
#endif

#if HAVE_SYS_ATTRIBUTES_H
#include <sys/attributes.h>
#endif

/* mutually exclusive (SuSE 8.2) */
#if HAVE_ATTR_XATTR_H
#include <attr/xattr.h>
#elif HAVE_SYS_XATTR_H
#include <sys/xattr.h>
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

