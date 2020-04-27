#ifndef _INCLUDES_H
#define _INCLUDES_H
/* 
   Unix SMB/CIFS implementation.
   Machine customisation and include handling
   Copyright (C) Andrew Tridgell 1994-1998
   Copyright (C) 2002 by Martin Pool <mbp@samba.org>
   
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "../replace/replace.h"

/* make sure we have included the correct config.h */
#ifndef NO_CONFIG_H /* for some tests */
#ifndef CONFIG_H_IS_FROM_SAMBA
#error "make sure you have removed all config.h files from standalone builds!"
#error "the included config.h isn't from samba!"
#endif
#endif /* NO_CONFIG_H */

/* only do the C++ reserved word check when we compile
   to include --with-developer since too many systems
   still have comflicts with their header files (e.g. IRIX 6.4) */

#if !defined(__cplusplus) && defined(DEVELOPER) && defined(__linux__)
#define class #error DONT_USE_CPLUSPLUS_RESERVED_NAMES
#define private #error DONT_USE_CPLUSPLUS_RESERVED_NAMES
#define public #error DONT_USE_CPLUSPLUS_RESERVED_NAMES
#define protected #error DONT_USE_CPLUSPLUS_RESERVED_NAMES
#define template #error DONT_USE_CPLUSPLUS_RESERVED_NAMES
#define this #error DONT_USE_CPLUSPLUS_RESERVED_NAMES
#define new #error DONT_USE_CPLUSPLUS_RESERVED_NAMES
#define delete #error DONT_USE_CPLUSPLUS_RESERVED_NAMES
#define friend #error DONT_USE_CPLUSPLUS_RESERVED_NAMES
#endif

#include "local.h"

#ifdef SUNOS4
/* on SUNOS4 termios.h conflicts with sys/ioctl.h */
#undef HAVE_TERMIOS_H
#endif

#ifdef RELIANTUNIX
/*
 * <unistd.h> has to be included before any other to get
 * large file support on Reliant UNIX. Yes, it's broken :-).
 */
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#endif /* RELIANTUNIX */

#include "system/dir.h"
#include "system/locale.h"
#include "system/time.h"
#include "system/wait.h"

#ifndef HAVE_KRB5_H
#undef HAVE_KRB5
#endif

#ifndef HAVE_LDAP_H
#undef HAVE_LDAP
#endif

#ifdef HAVE_SYS_ATTRIBUTES_H
#include <sys/attributes.h>
#endif

#ifndef ENOATTR
#if defined(ENODATA)
#define ENOATTR ENODATA
#else
#define ENOATTR ENOENT
#endif
#endif

#ifdef HAVE_SYS_UIO_H
#include <sys/uio.h>
#endif

#ifdef HAVE_LANGINFO_H
#include <langinfo.h>
#endif

#ifdef HAVE_NETGROUP_H
#include <netgroup.h>
#endif

/* Special macros that are no-ops except when run under Valgrind on
 * x86.  They've moved a little bit from valgrind 1.0.4 to 1.9.4 */
#ifdef HAVE_VALGRIND_MEMCHECK_H
        /* memcheck.h includes valgrind.h */
#include <valgrind/memcheck.h>
#elif defined(HAVE_VALGRIND_H)
#include <valgrind.h>
#endif

/* we support ADS if we want it and have krb5 and ldap libs */
#if defined(WITH_ADS) && defined(HAVE_KRB5) && defined(HAVE_LDAP)
#define HAVE_ADS
#endif

/*
 * Define additional missing types
 */
#if defined(AIX)
typedef sig_atomic_t SIG_ATOMIC_T;
#else
typedef sig_atomic_t volatile SIG_ATOMIC_T;
#endif

#ifndef uchar
#define uchar unsigned char
#endif

/*
 * Types for devices, inodes and offsets.
 */

#ifndef SMB_DEV_T
# define SMB_DEV_T dev_t
#endif

#ifndef LARGE_SMB_DEV_T
#  if (defined(SIZEOF_DEV_T) && (SIZEOF_DEV_T == 8))
#    define LARGE_SMB_DEV_T 1
#  endif
#endif

#ifdef LARGE_SMB_DEV_T
#define SDEV_T_VAL(p, ofs, v) (SIVAL((p),(ofs),(v)&0xFFFFFFFF), SIVAL((p),(ofs)+4,(v)>>32))
#define DEV_T_VAL(p, ofs) ((SMB_DEV_T)(((uint64_t)(IVAL((p),(ofs))))| (((uint64_t)(IVAL((p),(ofs)+4))) << 32)))
#else 
#define SDEV_T_VAL(p, ofs, v) (SIVAL((p),(ofs),v),SIVAL((p),(ofs)+4,0))
#define DEV_T_VAL(p, ofs) ((SMB_DEV_T)(IVAL((p),(ofs))))
#endif

/*
 * Setup the correctly sized inode type.
 */

#ifndef SMB_INO_T
#    define SMB_INO_T ino_t
#endif

#ifndef LARGE_SMB_INO_T
#  if (defined(SIZEOF_INO_T) && (SIZEOF_INO_T == 8))
#    define LARGE_SMB_INO_T 1
#  endif
#endif

#ifdef LARGE_SMB_INO_T
#define SINO_T_VAL(p, ofs, v) SBVAL(p, ofs, v)
#define INO_T_VAL(p, ofs) ((SMB_INO_T)BVAL(p, ofs))
#else 
#define SINO_T_VAL(p, ofs, v) SBVAL(p, ofs, ((uint64_t)(v)) & UINT32_MAX)
#define INO_T_VAL(p, ofs) ((SMB_INO_T)(IVAL((p),(ofs))))
#endif

/* TODO: remove this macros */
#define SBIG_UINT(p, ofs, v) SBVAL(p, ofs, v)
#define BIG_UINT(p, ofs) BVAL(p, ofs)
#define IVAL2_TO_SMB_BIG_UINT(p, ofs) BVAL(p, ofs)

/*
 * Set the define that tells us if we can do 64 bit
 * NT SMB calls.
 */

#define SOFF_T(p, ofs, v) (SIVAL(p,ofs,(v)&0xFFFFFFFF), SIVAL(p,(ofs)+4,(v)>>32))
#define SOFF_T_R(p, ofs, v) (SIVAL(p,(ofs)+4,(v)&0xFFFFFFFF), SIVAL(p,ofs,(v)>>32))
#define IVAL_TO_SMB_OFF_T(buf,off) ((off_t)(( ((uint64_t)(IVAL((buf),(off)))) & ((uint64_t)0xFFFFFFFF) )))

/* Is birthtime real, or was it calculated ? */
#define ST_EX_IFLAG_CALCULATED_BTIME		(1 << 0)
#define ST_EX_IFLAG_CALCULATED_ITIME		(1 << 1)
#define ST_EX_IFLAG_CALCULATED_FILE_ID		(1 << 2)

/*
 * Type for stat structure.
 */

struct stat_ex {
	dev_t		st_ex_dev;
	ino_t		st_ex_ino;
	uint64_t	st_ex_file_id;
	mode_t		st_ex_mode;
	nlink_t		st_ex_nlink;
	uid_t		st_ex_uid;
	gid_t		st_ex_gid;
	dev_t		st_ex_rdev;
	off_t		st_ex_size;
	struct timespec st_ex_atime;
	struct timespec st_ex_mtime;
	struct timespec st_ex_ctime;
	struct timespec st_ex_btime; /* birthtime */
	/*
	 * Immutable original birth time aka instantiation time. Set when a file
	 * is created, never changes thereafter. May not be set by the client.
	 */
	struct timespec st_ex_itime; /* instantiation time */

	blksize_t	st_ex_blksize;
	blkcnt_t	st_ex_blocks;

	uint32_t	st_ex_flags;
	uint32_t	st_ex_iflags;
};

typedef struct stat_ex SMB_STRUCT_STAT;

enum timestamp_set_resolution {
	TIMESTAMP_SET_SECONDS = 0,
	TIMESTAMP_SET_MSEC,
	TIMESTAMP_SET_NT_OR_BETTER
};

/* Our own fstrings */

/*
                  --------------
                 /              \
                /      REST      \
               /        IN        \
              /       PEACE        \
             /                      \
             | The infamous pstring |
             |                      |
             |                      |
             |      7 December      |
             |                      |
             |         2007         |
            *|     *  *  *          | *
   _________)/\\_//(\/(/\)/\//\/\///|_)_______
*/

#ifndef FSTRING_LEN
#define FSTRING_LEN 256
typedef char fstring[FSTRING_LEN];
#endif

/* debug.h need to be included before samba_util.h for the macro SMB_ASSERT */
#include "../lib/util/debug.h"

/* Lists, trees, caching, database... */
#include "../lib/util/samba_util.h"
#include "../lib/util/util_net.h"
#include "../lib/util/attr.h"
#include "../lib/util/tsort.h"
#include "../lib/util/dlinklist.h"

#include <talloc.h>
#include <tevent.h>

#include "../lib/util/data_blob.h"
#include "../lib/util/time.h"
#include "../lib/util/debug_s3.h"

#include "../libcli/util/ntstatus.h"
#include "../libcli/util/error.h"
#include "../lib/util/charset/charset.h"
#include "dynconfig/dynconfig.h"
#include "locking.h"
#include "smb_perfcount.h"
#include "smb.h"
#include "../lib/util/byteorder.h"

#include "../lib/util/samba_modules.h"
#include "../lib/util/talloc_stack.h"
#include "../lib/util/smb_threads.h"
#include "../lib/util/smb_threads_internal.h"

/* samba_setXXid functions. */
#include "../lib/util/setid.h"

/***** prototypes *****/
#ifndef NO_PROTO_H
#include "proto.h"
#endif

#include "lib/param/loadparm.h"

/* String routines */

#include "srvstr.h"
#include "safe_string.h"

#ifndef SIGCLD
#define SIGCLD SIGCHLD
#endif

#ifndef SIGRTMIN
#define SIGRTMIN NSIG
#endif


#if defined(HAVE_CRYPT16) && defined(HAVE_GETAUTHUID)
#define ULTRIX_AUTH 1
#endif

/* yuck, I'd like a better way of doing this */
#define DIRP_SIZE (256 + 32)

/* default socket options. Dave Miller thinks we should default to TCP_NODELAY
   given the socket IO pattern that Samba uses */
#ifdef TCP_NODELAY
#define DEFAULT_SOCKET_OPTIONS "TCP_NODELAY"
#else
#define DEFAULT_SOCKET_OPTIONS ""
#endif

/* dmalloc -- free heap debugger (dmalloc.org).  This should be near
 * the *bottom* of include files so as not to conflict. */
#ifdef ENABLE_DMALLOC
#  include <dmalloc.h>
#endif


#define MAX_SEC_CTX_DEPTH 8    /* Maximum number of security contexts */


/* add varargs prototypes with printf checking */
/*PRINTFLIKE1 */
int d_printf(const char *, ...) PRINTF_ATTRIBUTE(1,2);
/*PRINTFLIKE2 */
int d_fprintf(FILE *f, const char *, ...) PRINTF_ATTRIBUTE(2,3);

/* PRINTFLIKE2 */
int fstr_sprintf(fstring s, const char *fmt, ...) PRINTF_ATTRIBUTE(2,3);

int asprintf_strupper_m(char **strp, const char *fmt, ...) PRINTF_ATTRIBUTE(2,3);
char *talloc_asprintf_strupper_m(TALLOC_CTX *t, const char *fmt, ...) PRINTF_ATTRIBUTE(2,3);

/*
 * Veritas File System.  Often in addition to native.
 * Quotas different.
 */
#if defined(HAVE_SYS_FS_VX_QUOTA_H)
#define VXFS_QUOTA
#endif

#ifdef TRUE
#undef TRUE
#endif
#define TRUE __ERROR__XX__DONT_USE_TRUE

#ifdef FALSE
#undef FALSE
#endif
#define FALSE __ERROR__XX__DONT_USE_FALSE

void dump_core(void) _NORETURN_;
void exit_server(const char *const reason) _NORETURN_;
void exit_server_cleanly(const char *const reason) _NORETURN_;

#define BASE_RID (0x000003E8L)

#endif /* _INCLUDES_H */
