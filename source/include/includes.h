#ifndef _INCLUDES_H
#define _INCLUDES_H
/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   Machine customisation and include handling
   Copyright (C) Andrew Tridgell 1994-1998
   
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


/* if we have both SYSV IPC and shared mmap then we need to
   choose. For most systems it is much faster to use SYSV IPC. We used
   to make an exception for Linux, but now Linux 2.2 has made it
   better to use sysv if possible */
#if (defined(HAVE_SYSV_IPC) && defined(HAVE_SHARED_MMAP))
#  undef HAVE_SHARED_MMAP
#endif


#include <sys/types.h>

#ifdef TIME_WITH_SYS_TIME
#include <sys/time.h>
#include <time.h>
#ifdef USE_KRB4_DEFINE_WORK_AROUND
#include <krb.h>
#define _KERBEROS_KRB_H
#endif

#else
#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#else
#include <time.h>
#endif
#endif

#ifdef HAVE_SYS_RESOURCE_H
#include <sys/resource.h>
#endif

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <stdio.h>
#include <stddef.h>

#include <netinet/in.h>
#if defined(HAVE_RPC_RPC_H)
#include <rpc/rpc.h>
#endif

#ifdef HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif

#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif

#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif

#ifdef HAVE_SYS_UN_H
#include <sys/un.h>
#endif

#ifdef HAVE_SYS_SYSCALL_H
#include <sys/syscall.h>
#elif HAVE_SYSCALL_H
#include <syscall.h>
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

#ifdef MEM_MAN
#include "../mem_man/mem_man.h"
#else
#ifdef HAVE_MALLOC_H
#include <malloc.h>
#endif
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

#ifdef HAVE_SYS_WAIT_H
#include <sys/wait.h>
#endif
#ifdef HAVE_CTYPE_H
#include <ctype.h>
#endif
#ifdef HAVE_GRP_H
#include <grp.h>
#endif
#ifdef HAVE_SYS_ID_H
#include <sys/id.h>
#endif

#include <errno.h>

#ifdef HAVE_UTIME_H
#include <utime.h>
#endif

#ifdef HAVE_SYS_SELECT_H
#include <sys/select.h>
#endif

#ifdef HAVE_SYS_MODE_H
/* apparently AIX needs this for S_ISLNK */
#ifndef S_ISLNK
#include <sys/mode.h>
#endif
#endif

#ifdef HAVE_GLOB_H
#include <glob.h>
#endif

#include <pwd.h>
#include <grp.h>

#ifdef HAVE_STDARG_H
#include <stdarg.h>
#else
#include <varargs.h>
#endif

#include <arpa/inet.h>
#include <netdb.h>
#include <syslog.h>
#include <sys/file.h>

#ifdef HAVE_NETINET_TCP_H
#include <netinet/tcp.h>
#endif

#ifdef HAVE_TERMIOS_H
#include <termios.h>
#endif

#if HAVE_DIRENT_H
# include <dirent.h>
# define NAMLEN(dirent) strlen((dirent)->d_name)
#else
# define dirent direct
# define NAMLEN(dirent) (dirent)->d_namlen
# if HAVE_SYS_NDIR_H
#  include <sys/ndir.h>
# endif
# if HAVE_SYS_DIR_H
#  include <sys/dir.h>
# endif
# if HAVE_NDIR_H
#  include <ndir.h>
# endif
#endif

#ifdef HAVE_SYS_MMAN_H
#include <sys/mman.h>
#endif

#ifdef HAVE_SYSV_IPC
#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/sem.h>
#endif

#if 0
/*
 *  I have removed this as it prevents compilation under SCO Server
 *  3.2. If you need to add it back in then please add a comment as to
 *  why it's needed and what OS it's needed for so we can work out how
 *  to test for it properly (tridge) */
#ifdef HAVE_NET_ROUTE_H
#include <net/route.h>
#endif
#endif

#ifdef HAVE_NET_IF_H
#include <net/if.h>
#endif


#ifdef HAVE_SYS_MOUNT_H
#include <sys/mount.h>
#endif

#ifdef HAVE_SYS_VFS_H
#include <sys/vfs.h>
#endif

#ifdef HAVE_SYS_ACL_H
#include <sys/acl.h>
#endif

#ifdef HAVE_SYS_FS_S5PARAM_H 
#include <sys/fs/s5param.h>
#endif

#if defined (HAVE_SYS_FILSYS_H) && !defined (_CRAY)
#include <sys/filsys.h> 
#endif

#ifdef HAVE_SYS_STATFS_H
# include <sys/statfs.h>
#endif

#ifdef HAVE_DUSTAT_H              
#include <sys/dustat.h>
#endif

#ifdef HAVE_SYS_STATVFS_H          
#include <sys/statvfs.h>
#endif

#ifdef HAVE_SHADOW_H
#include <shadow.h>
#endif

#ifdef HAVE_GETPWANAM
#include <sys/label.h>
#include <sys/audit.h>
#include <pwdadj.h>
#endif

#ifdef HAVE_SYS_SECURITY_H
#include <sys/security.h>
#include <prot.h>
#define PASSWORD_LENGTH 16
#endif  /* HAVE_SYS_SECURITY_H */

#ifdef HAVE_COMPAT_H
#include <compat.h>
#endif

#ifdef HAVE_STROPTS_H
#include <stropts.h>
#endif

#ifdef HAVE_POLL_H
#include <poll.h>
#endif

#ifdef HAVE_SYS_CAPABILITY_H
#include <sys/capability.h>
#endif

#if defined(HAVE_RPC_RPC_H)
#include <rpc/rpc.h>
#endif

#if defined(HAVE_YP_GET_DEFAULT_DOMAIN) && defined(HAVE_SETNETGRENT) && defined(HAVE_ENDNETGRENT) && defined(HAVE_GETNETGRENT)
#define HAVE_NETGROUP 1
#endif

#if defined (HAVE_NETGROUP)
#if defined(HAVE_RPCSVC_YP_PROT_H)
#include <rpcsvc/yp_prot.h>
#endif
#if defined(HAVE_RPCSVC_YPCLNT_H)
#include <rpcsvc/ypclnt.h>
#endif
#endif /* HAVE_NETGROUP */

#if defined(WITH_LDAP) || defined(WITH_NT5LDAP)
#include <lber.h>
#include <ldap.h>
#else
#define LDAPMod void
#endif

#if defined(HAVE_MYSQL_H)
#include <mysql.h>
#else
/* needed to get make proto to work with no <mysql.h> */
#define MYSQL     void
#define MYSQL_ROW void
#endif

#ifndef uchar
#define uchar unsigned char
#endif

#ifdef HAVE_UNSIGNED_CHAR
#define schar signed char
#else
#define schar char
#endif

/*
   Samba needs type definitions for int16, int32, uint16 and uint32.

   Normally these are signed and unsigned 16 and 32 bit integers, but
   they actually only need to be at least 16 and 32 bits
   respectively. Thus if your word size is 8 bytes just defining them
   as signed and unsigned int will work.
*/

#ifndef uint8
#define uint8 unsigned char
#endif

#if !defined(int16) && !defined(HAVE_INT16_FROM_RPC_RPC_H)
#if (SIZEOF_SHORT == 4)
#define int16 __ERROR___CANNOT_DETERMINE_TYPE_FOR_INT16;
#else /* SIZEOF_SHORT != 4 */
#define int16 short
#endif /* SIZEOF_SHORT != 4 */
#endif

/*
 * Note we duplicate the size tests in the unsigned 
 * case as int16 may be a typedef from rpc/rpc.h
 */

#if !defined(uint16) && !defined(HAVE_UINT16_FROM_RPC_RPC_H)
#if (SIZEOF_SHORT == 4)
#define uint16 __ERROR___CANNOT_DETERMINE_TYPE_FOR_INT16;
#else /* SIZEOF_SHORT != 4 */
#define uint16 unsigned short
#endif /* SIZEOF_SHORT != 4 */
#endif

#if !defined(int32) && !defined(HAVE_INT32_FROM_RPC_RPC_H)
#if (SIZEOF_INT == 4)
#define int32 int
#elif (SIZEOF_LONG == 4)
#define int32 long
#elif (SIZEOF_SHORT == 4)
#define int32 short
#endif
#endif

/*
 * Note we duplicate the size tests in the unsigned 
 * case as int32 may be a typedef from rpc/rpc.h
 */

#if !defined(uint32) && !defined(HAVE_UINT32_FROM_RPC_RPC_H)
#if (SIZEOF_INT == 4)
#define uint32 unsigned int
#elif (SIZEOF_LONG == 4)
#define uint32 unsigned long
#elif (SIZEOF_SHORT == 4)
#define uint32 unsigned short
#endif
#endif

/*
 * Types for devices, inodes and offsets.
 */

#ifndef SMB_DEV_T
#define SMB_DEV_T dev_t
#endif

/*
 * Setup the correctly sized inode type.
 */

#ifndef SMB_INO_T
#  ifdef HAVE_INO64_T
#    define SMB_INO_T ino64_t
#  else
#    define SMB_INO_T ino_t
#  endif
#endif

#ifndef LARGE_SMB_INO_T
#  if defined(HAVE_INO64_T) || (defined(SIZEOF_INO_T) && (SIZEOF_INO_T == 8))
#    define LARGE_SMB_INO_T 1
#  endif
#endif

#ifdef LARGE_SMB_INO_T
#define SINO_T(p, ofs, v) (SIVAL(p,ofs,(v)&0xFFFFFFFF), SIVAL(p,(ofs)+4,(v)>>32))
#else 
#define SINO_T(p, ofs, v) (SIVAL(p,ofs,v),SIVAL(p,(ofs)+4,0))
#endif

#ifndef SMB_OFF_T
#  ifdef HAVE_OFF64_T
#    define SMB_OFF_T off64_t
#  else
#    define SMB_OFF_T off_t
#  endif
#endif

#define SMB_OFF_T_BITS (sizeof(SMB_OFF_T)*8)

/*
 * Set the define that tells us if we can do 64 bit
 * NT SMB calls.
 */

#ifndef LARGE_SMB_OFF_T
#  if defined(HAVE_OFF64_T) || (defined(SIZEOF_OFF_T) && (SIZEOF_OFF_T == 8))
#    define LARGE_SMB_OFF_T 1
#  endif
#endif

#ifdef LARGE_SMB_OFF_T
#define SOFF_T(p, ofs, v) (SIVAL(p,ofs,(v)&0xFFFFFFFF), SIVAL(p,(ofs)+4,(v)>>32))
#else 
#define SOFF_T(p, ofs, v) (SIVAL(p,ofs,v),SIVAL(p,(ofs)+4,0))
#endif

/*
 * Type for stat structure.
 */

#ifndef SMB_STRUCT_STAT
#  if defined(HAVE_STAT64) && defined(HAVE_OFF64_T)
#    define SMB_STRUCT_STAT struct stat64
#  else
#    define SMB_STRUCT_STAT struct stat
#  endif
#endif

/*
 * Defines for 64 bit fcntl locks.
 */

#ifndef SMB_STRUCT_FLOCK
#  if defined(HAVE_STRUCT_FLOCK64) && defined(HAVE_OFF64_T)
#    define SMB_STRUCT_FLOCK struct flock64
#  else
#    define SMB_STRUCT_FLOCK struct flock
#  endif
#endif

#ifndef SMB_F_SETLKW
#  if defined(HAVE_STRUCT_FLOCK64) && defined(HAVE_OFF64_T)
#    define SMB_F_SETLKW F_SETLKW64
#  else
#    define SMB_F_SETLKW F_SETLKW
#  endif
#endif

#ifndef SMB_F_SETLK
#  if defined(HAVE_STRUCT_FLOCK64) && defined(HAVE_OFF64_T)
#    define SMB_F_SETLK F_SETLK64
#  else
#    define SMB_F_SETLK F_SETLK
#  endif
#endif

#ifndef SMB_F_GETLK
#  if defined(HAVE_STRUCT_FLOCK64) && defined(HAVE_OFF64_T)
#    define SMB_F_GETLK F_GETLK64
#  else
#    define SMB_F_GETLK F_GETLK
#  endif
#endif

#if defined(HAVE_LONGLONG)
#define SMB_BIG_UINT unsigned long long
#define SMB_BIG_INT long long
#else
#define SMB_BIG_UINT unsigned long
#define SMB_BIG_INT long
#endif

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

#ifndef HAVE_STRCHR
# define strchr                 index
# define strrchr                rindex
#endif

#ifndef HAVE_ERRNO_DECL
extern int errno;
#endif

#ifdef HAVE_BROKEN_GETGROUPS
#define GID_T int
#else
#define GID_T gid_t
#endif


/* Lists, trees, caching, datbase... */
#include "ubi_sLinkList.h"
#include "ubi_dLinkList.h"
#include "dlinklist.h"
#include "../tdb/tdb.h"

#ifndef UBI_BINTREE_H
#include "ubi_Cache.h"
#endif /* UBI_BINTREE_H */

#include "version.h"
#include "smb.h"
#include "smbw.h"
#include "nameserv.h"

#include "byteorder.h"

#include "kanji.h"
#include "charset.h"

#ifdef WITH_PROFILE
#include "profile.h"
#endif

#ifndef MAXCODEPAGELINES
#define MAXCODEPAGELINES 256
#endif

/***** automatically generated prototypes *****/
#include "ldapdb.h"
#include "proto.h"

/* String routines */

#include "safe_string.h"

#ifdef __COMPAR_FN_T
#define QSORT_CAST (__compar_fn_t)
#endif

#ifndef QSORT_CAST
#define QSORT_CAST (int (*)(const void *, const void *))
#endif

/* this guess needs to be improved (tridge) */
#if defined(STAT_STATVFS) && !defined(SYSV)
#define SYSV 1
#endif

#ifndef DEFAULT_PRINTING
#ifdef SYSV
#define DEFAULT_PRINTING PRINT_SYSV
#define PRINTCAP_NAME "lpstat"
#else
#define DEFAULT_PRINTING PRINT_BSD
#define PRINTCAP_NAME "/etc/printcap"
#endif
#endif

#ifndef PRINTCAP_NAME
#define PRINTCAP_NAME "/etc/printcap"
#endif

#ifndef SIGCLD
#define SIGCLD SIGCHLD
#endif

#if (defined(HAVE_SYSV_IPC) || defined(HAVE_SHARED_MMAP))
#define FAST_SHARE_MODES 1
#endif

#ifndef MAP_FILE
#define MAP_FILE 0
#endif

#ifdef HAVE_SYSV_IPC
#ifndef HAVE_UNION_SEMUN
union semun {
	int val;
	struct semid_ds *buf;
	unsigned short *array;
};
#endif
#endif

#if (!defined(WITH_NISPLUS) && !defined(WITH_LDAP) && !defined(WITH_NT5LDAP))
#define USE_SMBPASS_DB 1
#define USE_SMBUNIX_DB 1
#endif

#if defined(HAVE_PUTPRPWNAM) && defined(AUTH_CLEARTEXT_SEG_CHARS)
#define OSF1_ENH_SEC 1
#endif

#if defined(HAVE_PAM_AUTHENTICATE) && defined(HAVE_SECURITY_PAM_APPL_H)
#define HAVE_PAM 1
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

#ifndef MAX_SERVER_POLICY_HANDLES
#define MAX_SERVER_POLICY_HANDLES 64
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

#ifndef SHM_R
#define SHM_R (0400)
#endif

#ifndef SHM_W
#define SHM_W (0200)
#endif

#if defined(HAVE_CRYPT16) && defined(HAVE_GETAUTHUID)
#define ULTRIX_AUTH 1
#endif

#ifdef HAVE_LIBREADLINE
#  ifdef HAVE_READLINE_READLINE_H
#    include <readline/readline.h>
#    ifdef HAVE_READLINE_HISTORY_H
#      include <readline/history.h>
#    endif
#  else
#    ifdef HAVE_READLINE_H
#      include <readline.h>
#      ifdef HAVE_HISTORY_H
#        include <history.h>
#      endif
#    else
#      undef HAVE_LIBREADLINE
#    endif
#  endif

/* Some old versions of readline don't define a prototype for
   filename_completion_function() */

#  ifndef HAVE_READLINE_FCF_PROTO
char *filename_completion_function(void);
#  endif

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

#ifndef HAVE_FTRUNCATE
int ftruncate(int f,long l);
#endif

#if (defined(USE_SETRESUID) && !defined(HAVE_SETRESUID_DECL))
/* stupid glibc */
int setresuid(uid_t ruid, uid_t euid, uid_t suid);
#endif
#if (defined(USE_SETRESUID) && !defined(HAVE_SETRESGID_DECL))
int setresgid(gid_t rgid, gid_t egid, gid_t sgid);
#endif

#if (defined(HAVE_CRYPT) && !defined(HAVE_CRYPT_DECL) && !defined(KRB4_AUTH))
/* stupid glibc */
int crypt(const char *key, const char *salt);
#endif

#if !defined(HAVE_BZERO) && defined(HAVE_MEMSET)
#define bzero(a,b) memset((a),'\0',(b))
#endif

#ifdef REPLACE_GETPASS
#define getpass(prompt) getsmbpass((prompt))
#endif
 
#ifdef USE_RENEWABLE_AFS_TICKET
#include "afsticket.h"
#endif /* USE_RENEWABLE_AFS_TICKET */

/* yuck, I'd like a better way of doing this */
#define DIRP_SIZE (256 + 32)
/* change initialization ... support for IRIX cc */
#define VUSER_KEY vuser_key key; key.pid=conn->smbd_pid; key.vuid=vuid
#endif /* _INCLUDES_H */
