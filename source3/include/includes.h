#ifndef _INCLUDES_H
#define _INCLUDES_H
/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   Machine customisation and include handling
   Copyright (C) Andrew Tridgell 1994-1997
   
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
/*
   This file does all the #includes's. This makes it easier to
   port to a new unix. Hopefully a port will only have to edit the Makefile
   and add a section for the new unix below.
*/


/* the first OS dependent section is to setup what includes will be used.
   the main OS dependent section comes later on 
*/

#ifdef ALTOS
#define NO_UTIMEH
#endif

#ifdef MIPS
#define POSIX_H
#define NO_UTIMEH
#endif

#ifdef sun386
#define NO_UTIMEH
#endif

#ifdef NEXT2
#define NO_UTIMEH
#endif

#ifdef NEXT3_0
#define NO_UTIMEH
#define NO_UNISTDH
#endif

#ifdef APOLLO
#define NO_UTIMEH
#define NO_SYSMOUNTH
#define NO_UNISTDH
#endif

#ifdef AIX
#define NO_SYSMOUNTH
#endif

#ifdef M88K_R3
#define SVR3H
#define NO_RESOURCEH
#endif

#ifdef DNIX
#define NO_SYSMOUNTH
#define NO_NETIFH
#define NO_RESOURCEH
#define PRIME_NMBD 0
#define NO_SETGROUPS
#endif


#ifdef ISC
#define SYSSTREAMH
#define NO_RESOURCEH
#endif

#ifdef QNX
#define NO_RESOURCEH
#define NO_SYSMOUNTH
#define USE_MMAP 1
#ifdef __386__
   #define __i386__
#endif
#endif

#ifdef NEWS42
#define NO_UTIMEH
#define NO_STRFTIME
#define NO_UTIMBUF
#define REPLACE_MKTIME
#define NO_TM_NAME
#endif

#ifdef OS2
#define NO_SYSMOUNTH
#define NO_NETIFH
#endif

#ifdef LYNX
#define NO_SYSMOUNTH
#endif


#if (defined(SHADOW_PWD)||defined(OSF1_ENH_SEC)||defined(SecureWare)||defined(PWDAUTH))
#define PASSWORD_LENGTH 16
#endif

/* here is the general includes section - with some ifdefs generated 
   by the previous section 
*/
#include "local.h"
#include <stdio.h>
#ifdef POSIX_STDLIBH
#include <posix/stdlib.h>
#else
#include <stdlib.h>
#endif
#include <ctype.h>
#include <time.h>
#ifndef NO_UTIMEH
#include <utime.h>
#endif
#include <sys/types.h>

#ifdef SVR3H
#include <sys/statfs.h>
#include <sys/stream.h>
#include <netinet/types.h>
#include <netinet/ether.h>
#include <netinet/ip_if.h>
#endif

#include <sys/socket.h>
#ifdef AXPROC
#include <termio.h>
#endif
#include <sys/ioctl.h>
#include <stddef.h>
#ifdef POSIX_H
#include <posix/utime.h>
#include <bsd/sys/time.h>
#include <bsd/netinet/in.h>
#else
#include <sys/time.h>
#include <netinet/in.h>
#endif 
#include <netdb.h>
#include <signal.h>
#include <errno.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <grp.h>
#ifndef NO_RESOURCEH
#include <sys/resource.h>
#endif
#ifndef NO_SYSMOUNTH
#include <sys/mount.h>
#endif
#include <pwd.h>
#ifdef __STDC__
#include <stdarg.h>
#else
#include <varargs.h>
#endif
#ifndef NO_UNISTDH
#include <unistd.h>
#endif
#include <sys/wait.h>
#ifdef SYSSTREAMH
#include <sys/stream.h>
#endif
#ifndef NO_NETIFH
#ifdef POSIX_H
#include <bsd/net/if.h>
#else
#include <net/if.h>
#endif
#endif

#if defined(GETPWANAM)
#include <sys/types.h>
#include <sys/label.h>
#include <sys/audit.h>
#include <pwdadj.h>
#endif

#if defined(SHADOW_PWD) && !defined(NETBSD) && !defined(FreeBSD) && !defined(CONVEX)
#include <shadow.h>
#endif

#ifdef SYSLOG
#include <syslog.h>
#endif



/***************************************************************************
Here come some platform specific sections
***************************************************************************/


#ifdef LINUX
#include <arpa/inet.h>
#include <dirent.h>
#include <string.h>
#include <sys/vfs.h>
#include <netinet/in.h>
#ifndef NO_ASMSIGNALH
#include <asm/signal.h>
#endif
#ifdef GLIBC2
#define _LINUX_C_LIB_VERSION_MAJOR     6
#include <termios.h>
#include <rpcsvc/ypclnt.h>
#include <crypt.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#endif
#define SIGNAL_CAST (__sighandler_t)
#define USE_GETCWD
#define USE_SETSID
#define HAVE_BZERO
#define HAVE_MEMMOVE
#define USE_SIGPROCMASK
#define USE_WAITPID
#define USE_SYSV_IPC
#if 0
/* SETFS disabled until we can check on some bug reports */
#if _LINUX_C_LIB_VERSION_MAJOR >= 5
#define USE_SETFS
#endif
#endif
#ifdef SHADOW_PWD
#if _LINUX_C_LIB_VERSION_MAJOR < 5
#ifndef crypt
#define crypt pw_encrypt
#endif
#endif
#endif
#endif

#ifdef SUNOS4
#define SIGNAL_CAST (void (*)(int))
#include <netinet/tcp.h>
#include <dirent.h>
#include <sys/acct.h>
#include <sys/vfs.h>
#include <string.h>
#include <errno.h>
#include <sys/wait.h>
#include <signal.h>
/* #include <termios.h> */
#ifdef sun386
#define NO_STRFTIME
#define NO_UTIMBUF
#define mktime timelocal
typedef unsigned short mode_t;
#else
#include <utime.h>
#define NO_STRERROR
#endif
#ifndef REPLACE_GETPASS
#define REPLACE_GETPASS
#endif
#ifndef BSD_TERMIO
#define BSD_TERMIO
#endif
#ifndef USE_SIGPROCMASK
#define USE_SIGPROCMASK
#endif
#ifndef USE_WAITPID
#define USE_WAITPID
#endif
#define USE_SYSV_IPC
/* SunOS doesn't have POSIX atexit */
#define atexit on_exit
#endif


#ifdef SUNOS5
#include <fcntl.h>
#include <dirent.h>
#include <sys/acct.h>
#include <sys/statfs.h>
#include <sys/statvfs.h>
#include <sys/filio.h>
#include <sys/sockio.h>
#include <netinet/in_systm.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <string.h>
#include <arpa/inet.h>
#include <rpcsvc/ypclnt.h>
#include <termios.h>
#include <sys/stropts.h>
#ifndef USE_LIBDES
#include <crypt.h>
#endif /* USE_LIBDES */
extern int gettimeofday (struct timeval *, void *);
extern int gethostname (char *name, int namelen);
extern int innetgr (const char *, const char *, const char *, const char *);
#define USE_SETVBUF
#define SIGNAL_CAST (void (*)(int))
#ifndef SYSV
#define SYSV
#endif
#define USE_WAITPID
#define REPLACE_STRLEN
#define USE_STATVFS
#define USE_GETCWD
#define USE_SETSID
#define USE_SYSV_IPC

union semun {
	int val;
	struct semid_ds *buf;
	ushort *array;
};


#ifndef REPLACE_GETPASS
#define REPLACE_GETPASS
#endif /* REPLACE_GETPASS */
#define USE_SIGPROCMASK
#endif


#ifdef ULTRIX
#include <strings.h>
#include <nfs/nfs_clnt.h>
#include <nfs/vfs.h>
#include <netinet/tcp.h>
#ifdef ULTRIX_AUTH
#include <auth.h>
#endif
char *getwd(char *);
#define NOSTRDUP
#ifdef __STDC__
#define SIGNAL_CAST (void(*)(int))
#endif
#define USE_DIRECT
#define USE_WAITPID
#endif

#ifdef SGI4
#include <netinet/tcp.h>
#include <sys/statfs.h>
#include <string.h>
#include <signal.h>
#ifndef SYSV
#define SYSV
#endif
#define SIGNAL_CAST (void (*)())
#define STATFS4
#define USE_WAITPID
#define USE_DIRECT
#define USE_SETSID
#define USE_SYSV_IPC
#endif

#if defined(SGI5) || defined(SGI6)
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <sys/statvfs.h>
#include <string.h>
#include <signal.h>
#include <dirent.h>
#define USE_WAITPID
#define NETGROUP 
#ifndef SYSV
#define SYSV
#endif
#define SIGNAL_CAST (void (*)())
#define USE_STATVFS
#define USE_WAITPID
#define USE_SETSID
#define USE_SYSV_IPC
#endif


#ifdef MIPS
#include <bsd/net/soioctl.h>
#include <string.h>
#include <dirent.h>
#include <fcntl.h>
#include <sys/statfs.h>
#include <sys/wait.h>
#include <sys/termio.h>
#define SIGNAL_CAST (void (*)())
typedef int mode_t;
extern struct group *getgrnam();
extern struct passwd *getpwnam();
#define STATFS4
#define NO_STRERROR
#define REPLACE_STRSTR
#endif /* MIPS */



#ifdef DGUX
#include <string.h>
#include <dirent.h>
#include <sys/statfs.h>
#include <sys/statvfs.h>
#include <fcntl.h>
#include <termios.h>
#define SYSV
#define USE_WAITPID
#define SIGNAL_CAST (void (*)(int))
#define STATFS4
#define USE_GETCWD
#endif


#ifdef SVR4
#include <string.h>
#include <sys/dir.h>
#include <dirent.h>
#include <sys/statfs.h>
#include <sys/statvfs.h>
#include <sys/vfs.h>
#include <sys/filio.h>
#include <fcntl.h>
#include <sys/sockio.h>
#include <netinet/tcp.h>
#include <stropts.h>
#include <termios.h>
#define SYSV
#define USE_WAITPID
#define SIGNAL_CAST (void (*)(int))
#define USE_STATVFS
#define USE_GETCWD
#define USE_SETSID
#define USE_SYSV_IPC
#endif


#ifdef OSF1
#include <termios.h>
#include <strings.h>
#include <dirent.h>
char *getwd(char *);
char *mktemp(char *); /* No standard include */
#include <netinet/in.h>
#include <arpa/inet.h> /* both for inet_ntoa */
#define SIGNAL_CAST ( void (*) (int) )
#define STATFS3
#define USE_F_FSIZE
#define USE_SETSID
#include <netinet/tcp.h>
#ifdef OSF1_ENH_SEC
#include <pwd.h>
#include <sys/types.h>
#include <sys/security.h>
#include <prot.h>
#include <unistd.h>
#define PASSWORD_LENGTH 16
#define NEED_AUTH_PARAMETERS
#endif  /* OSF1_ENH_SEC */
#define USE_SYSV_IPC
#endif


#ifdef CLIX
#include <dirent.h>
#define SIGNAL_CAST	(void (*)())
#include <sys/fcntl.h>
#include <sys/statfs.h>
#include <string.h>
#define NO_EID
#define USE_WAITPID
#define STATFS4
#define NO_FSYNC
#define USE_GETCWD
#define USE_SETSID
#ifndef REPLACE_GETPASS
#define REPLACE_GETPASS
#endif /* REPLACE_GETPASS */
#define NO_GETRLIMIT
#endif	/* CLIX */



#ifdef BSDI
#include <string.h>
#include <netinet/tcp.h>
#define SIGNAL_CAST (void (*)())
#define USE_DIRECT
#endif


#ifdef NETBSD
#include <strings.h>
#include <netinet/tcp.h>
/* you may not need this */
#define NO_GETSPNAM
#define SIGNAL_CAST (void (*)())
#define USE_DIRECT
#define REPLACE_INNETGR
#endif 



#ifdef FreeBSD
#include <arpa/inet.h>
#include <strings.h>
#include <netinet/tcp.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#define SIGNAL_CAST (void (*)())
#define USE_SETVBUF
#define USE_SETSID
#define USE_GETCWD
#define USE_WAITPID
#define USE_DIRECT
#define HAVE_MEMMOVE
#define HAVE_BZERO
#define HAVE_GETTIMEOFDAY
#define HAVE_PATHCONF
#define HAVE_GETGRNAM 1
#endif 



#ifdef AIX
#include <strings.h>
#include <sys/dir.h>
#include <sys/select.h>
#include <dirent.h>
#include <sys/statfs.h>
#include <sys/vfs.h>
#include <sys/id.h>
#include <sys/priv.h>
#include <netinet/tcp.h>
#include <locale.h>
#define SYSV
#define USE_WAITPID
#define USE_SIGBLOCK
#define SIGNAL_CAST (void (*)())
#define DEFAULT_PRINTING PRINT_AIX
/* we undef this because sys/param.h is broken in aix. uggh. */
#undef MAXHOSTNAMELEN
#endif


#ifdef HPUX
#include <string.h>
#include <dirent.h>
#include <fcntl.h>
#include <sys/vfs.h>
#include <sys/types.h>
#include <sys/termios.h>
#include <netinet/tcp.h>
#ifdef HPUX_10_TRUSTED
#include <hpsecurity.h>
#include <prot.h>
#define NEED_AUTH_PARAMETERS
#endif
#define SIGNAL_CAST (void (*)(__harg))
#ifndef HPUX10 /* This is only needed for HPUX 9.x */
#define SELECT_CAST (int *)
#endif /* HPUX10 */
#define SYSV
#define USE_WAITPID
#define WAIT3_CAST2 (int *)
#define USE_GETCWD
#define USE_SETSID
#define USE_SETRES
#define USE_SYSV_IPC
#define DEFAULT_PRINTING PRINT_HPUX
/* Ken Weiss <krweiss@ucdavis.edu> tells us that SIGCLD_IGNORE is
   not good for HPUX */
/* #define SIGCLD_IGNORE */
#endif /* HPUX */


#ifdef SEQUENT
#include <signal.h>
#include <string.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/statfs.h>
#include <sys/stat.h>
#include <sys/buf.h>
#include <sys/socket.h>
#include <unistd.h>
#include <fcntl.h>
#define SIGNAL_CAST (void (*)(int))
#define USE_WAITPID
#define USE_GETCWD
#define NO_EID
#define STATFS4
#define USE_DIRECT
#ifdef PTX4
#undef USE_DIRECT
#endif
#endif



#ifdef SEQUENT_PTX4
#include <string.h>
#include <sys/dir.h>
#include <dirent.h>
#include <sys/statfs.h>
#include <sys/statvfs.h>
#include <sys/vfs.h>
#include <fcntl.h>
#include <sys/sockio.h>
#include <netinet/tcp.h>
#include <stropts.h>
#include <termios.h>
#define SYSV
#define USE_WAITPID
#define SIGNAL_CAST (void (*)(int))
#define USE_STATVFS
#define USE_GETCWD
#ifndef seteuid
#define seteuid(uid) setreuid(-1,uid)
#endif
#ifndef setegid
#define setegid(gid) setregid(-1,gid)
#endif
#endif


#ifdef NEXT2
#include <sys/types.h>
#include <strings.h>
#include <dirent.h>
#include <sys/vfs.h>
#define bzero(b,len) memset(b,0,len)
#define mode_t int
#define NO_UTIMBUF
#include <libc.h>
#define NOSTRDUP
#define USE_DIRECT
#define USE_WAITPID
#endif 


#ifdef NEXT3_0
#include <strings.h>
#include <sys/dir.h>
#include <sys/vfs.h>
#define bzero(b,len) memset(b,0,len)
#define NO_UTIMBUF
#include <libc.h>
#define NOSTRDUP
#define USE_DIRECT
#define mode_t int
#define GID_TYPE int
#define gid_t int
#define pid_t int
#define SIGNAL_CAST (void (*)(int))
#define WAIT3_CAST1 (union wait *)
#define HAVE_GMTOFF
#endif



#ifdef APOLLO
#include <string.h>
#include <fcntl.h>
#include <sys/statfs.h>
#define NO_UTIMBUF
#define USE_DIRECT
#define USE_GETCWD
#define SIGNAL_CAST     (void (*)())
#define HAVE_FCNTL_LOCK 0
#define HAVE_GETTIMEOFDAY
#define STATFS4
#endif



#ifdef SCO
#include <sys/netinet/tcp.h>
#include <sys/netinet/in_systm.h>
#include <sys/netinet/ip.h>
#include <dirent.h>
#include <string.h>
#include <termios.h>
#include <fcntl.h>
#include <sys/statfs.h>
#include <sys/stropts.h>
#include <limits.h>
#include <locale.h>
#ifdef EVEREST
#include <unistd.h> 
#endif /* EVEREST */
#ifdef NETGROUP
#include <rpcsvc/ypclnt.h>
#endif /* NETGROUP */
#ifdef SecureWare
#include <sys/security.h>
#include <sys/audit.h>
#include <prot.h>
#define crypt bigcrypt
#endif /* SecureWare */
#define SIGNAL_CAST (void (*)(int))
#define USE_WAITPID
#define USE_GETCWD
#define USE_SETSID
#ifdef SCO3_2_2
#define setuid(u) setreuid(u,-1)
#define seteuid(u) setreuid(-1,u)
#else /* SCO3_2_2 */
#ifndef EVEREST
#define ftruncate(f,l) syscall(0x0a28,f,l)
#define USE_IFREQ
#define NO_INITGROUPS
#endif /* EVEREST */
#endif /* SCO3_2_2 */
#define STATFS4
#define NO_FSYNC
#define HAVE_PATHCONF
#define NO_GETRLIMIT
#endif /* SCO */



/* Definitions for RiscIX */
#ifdef RiscIX
#define SIGNAL_CAST (void (*)(int))
#include <sys/dirent.h>
#include <sys/acct.h>
#include <sys/vfs.h>
#include <string.h>
#include <utime.h>
#include <signal.h>
#define HAVE_GETTIMEOFDAY
#define NOSTRCASECMP
#define NOSTRDUP
#endif



#ifdef ISC
#include <net/errno.h>
#include <string.h>
#include <sys/dir.h>
#include <dirent.h>
#include <sys/statfs.h>
#include <fcntl.h>
#include <sys/sioctl.h>
#include <stropts.h>
#include <limits.h>
#include <netinet/tcp.h>
#define FIONREAD FIORDCHK
#define SYSV
#define USE_WAITPID
#define SIGNAL_CAST (void (*)(int))
#define USE_GETCWD
#define USE_SETSID
#define USE_IFREQ
#define NO_FTRUNCATE
#define STATFS4
#define NO_FSYNC
#endif



#ifdef AUX
#include <fstab.h>
#include <string.h>
#include <dirent.h>
#include <sys/vfs.h>
#include <fcntl.h>
#include <termios.h>
#define SYSV
#define USE_WAITPID
#define SIGNAL_CAST (void (*)(int))
char *strdup (char *);
#define USE_GETCWD
#endif


#ifdef M88K_R3
#include <string.h>
#include <dirent.h>
#include <fcntl.h>
#include <termios.h>
#define STATFS4
#define SYSV
#define USE_WAITPID
#define SIGNAL_CAST (void (*)(int))
char *strdup (char *);
#define USE_GETCWD
#define NO_FSYNC
#define NO_EID
#endif


#ifdef DNIX
#include <dirent.h>
#include <string.h>
#include <fcntl.h>
#include <sys/statfs.h>
#include <sys/stropts.h>
#define NO_GET_BROADCAST
#define USE_WAITPID
#define USE_GETCWD
#define USE_SETSID
#define STATFS4
#define NO_EID
#define PF_INET AF_INET
#define NO_STRERROR
#define ftruncate(f,l) chsize(f,l)
#endif /* DNIX */

#ifdef CONVEX
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <dirent.h>
#include <string.h>
#include <sys/vfs.h>
#include <fcntl.h>
#define DONT_REINSTALL_SIG
#define USE_SIGBLOCK
#define USE_WAITPID
#define SIGNAL_CAST (_SigFunc_Ptr_t)
#define NO_GETSPNAM
#define HAVE_MEMMOVE
extern char *mktemp(char *);
extern int  fsync(int);
extern int  seteuid(uid_t);
extern int  setgroups(int, int *);
extern int  initgroups(char *, int);
extern int  statfs(char *, struct statfs *);
extern int  setegid(gid_t);
extern int  getopt(int, char *const *, const char *);
extern int  chroot(char *);
extern int  gettimeofday(struct timeval *, struct timezone *);
extern int  gethostname(char *, int);
extern char *crypt(char *, char *);
extern char *getpass(char *);
#endif


#ifdef CRAY
#define MAXPATHLEN 1024
#include <dirent.h>
#include <string.h>
#include <fcntl.h>
#include <sys/statfs.h>
#define SIGNAL_CAST (void (*)(int))
#define SIGCLD_IGNORE
#define HAVE_FCNTL_LOCK 1
#define USE_SETSID
#define STATFS4
#endif


#ifdef ALTOS
#include <unistd.h>
#include <string.h>
#include <dirent.h>
#include <sys/fcntl.h>
#include <sys/statfs.h>
#define        const
#define        uid_t           int
#define        gid_t           int
#define        mode_t          int
#define        ptrdiff_t       int
#define HAVE_GETGRNAM  0
#define NO_EID
#define NO_FSYNC
#define        NO_FTRUNCATE
#define        NO_GETRLIMIT
#define        NO_INITGROUPS
#define NO_SELECT
#define NO_SETGROUPS
#define NO_STRERROR
#define NO_STRFTIME
#define        NO_TM_NAME
#define NO_UTIMEH
#define NOSTRCASECMP
#define REPLACE_MKTIME
#define REPLACE_RENAME
#define REPLACE_STRSTR
#define STATFS4
#define        USE_GETCWD
#endif

#ifdef QNX
#define STATFS4
#include <sys/statfs.h>
#include <sys/select.h>
#include <signal.h>
#include <sys/dir.h>
#define SIGNAL_CAST (void (*)())
#define USE_WAITPID
#define NO_INITGROUPS
#define NO_SETGROUPS
#define HAVE_TIMEZONE
#define USE_GETCWD
#define USE_SETSID
#define HAVE_FCNTL_LOCK 1
#define DEFAULT_PRINTING PRINT_QNX
#endif


#ifdef NEWS42
#include <string.h>
#include <dirent.h>
#include <sys/vfs.h>
#include <sys/timeb.h>
typedef int mode_t;
#endif

#ifdef OS2
#include <dirent.h>
#include <sys/statfs.h>
#include <string.h>
#include <limits.h>
#define SIGNAL_CAST (void (*)())
#define HAVE_FCNTL_LOCK 0
#define USE_WAITPID
#define NO_GET_BROADCAST
#define NO_EID
#define NO_SETGROUPS
#define NO_INITGROUPS
#define NO_CRYPT
#define NO_STATFS
#define NO_CHROOT
#define NO_CHOWN
#define strcasecmp stricmp
#define strncasecmp strnicmp
#endif


#ifdef LYNX
#define SIGNAL_CAST (void (*)())
#define WAIT3_CAST1 (union wait *)
#define STATFS4
#include <fcntl.h>
#include <resource.h>
#include <stat.h>
#include <string.h>
#include <dirent.h>
#include <sys/statfs.h>
#define USE_GETCWD
#define USE_GETSID
#endif


#ifdef BOS
#define SIGNAL_CAST (void (*)(int))
#include <string.h>
#include <sys/dir.h>
#include <sys/select.h>
#include <dirent.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/statfs.h>
#include <sys/bsdioctl.h>
#endif

#ifdef AMIGA
#include <arpa/inet.h>
#include <dirent.h>
#include <string.h>
#include <netinet/tcp.h>
#include <sys/acct.h>
#include <sys/fcntl.h>
#include <sys/filio.h>
#include <sys/sockio.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <sys/termios.h>
#include <limits.h>
#include <sys/timeb.h>

#define SIGNAL_CAST (void (*)(int))
#define USE_GETCWD
#define HAVE_BZERO
#define HAVE_MEMMOVE
#define USE_SIGPROCMASK
#define USE_WAITPID
#define USE_DIRECT
#define USE_F_FSIZE
#define HAVE_FCNTL_LOCK 0
#define HAVE_GETTIMEOFDAY
#define HAVE_PATHCONF

#define HAVE_NO_PROC
#define NO_FORK_DEBUG
#define HAVE_FORK 0
#define HAVE_VFORK 1
#endif

/* For UnixWare 2.x's ia_uinfo routines. (tangent@cyberport.com) */
#ifdef IA_UINFO
#include <iaf.h>
#include <ia.h>
#endif


/*******************************************************************
end of the platform specific sections
********************************************************************/

#if defined(USE_MMAP) || defined(FAST_SHARE_MODES)
#include <sys/mman.h>
#endif

#ifdef SecureWare
#define NEED_AUTH_PARAMETERS
#endif

#ifdef REPLACE_GETPASS
extern char    *getsmbpass(char *);
#define getpass(s) getsmbpass(s)
#endif

#ifdef REPLACE_INNETGR
#define innetgr(group,host,user,dom) InNetGr(group,host,user,dom)
#endif

#ifndef FD_SETSIZE
#define FD_SETSIZE 255
#endif

#ifndef __STDC__
#define const
#endif

/* Now for some other grungy stuff */
#ifdef NO_GETSPNAM
struct spwd { /* fake shadow password structure */
       char *sp_pwdp;
};
#endif

#ifndef HAVE_BZERO
#ifndef bzero
#define bzero(p,s) memset(p,0,s)
#endif
#endif

#ifndef HAVE_MEMMOVE
#ifndef memmove
#define memmove(d,s,n) MemMove(d,s,n)
#endif
#endif

#ifdef USE_DIRECT
#include <sys/dir.h>
#endif

/* some unixes have ENOTTY instead of TIOCNOTTY */
#ifndef TIOCNOTTY
#ifdef ENOTTY
#define TIOCNOTTY ENOTTY
#endif
#endif

#ifndef SIGHUP
#define SIGHUP 1
#endif

/* if undefined then use bsd or sysv printing */
#ifndef DEFAULT_PRINTING
#ifdef SYSV
#define DEFAULT_PRINTING PRINT_SYSV
#else
#define DEFAULT_PRINTING PRINT_BSD
#endif
#endif

#ifdef USE_SYSV_IPC
#include <sys/ipc.h>
#include <sys/sem.h>
#include <sys/shm.h>
#endif

#ifdef AFS_AUTH
#include <afs/stds.h>
#include <afs/kautils.h>
#endif

#ifdef DFS_AUTH
#include <dce/dce_error.h>
#include <dce/sec_login.h>
#endif

#ifdef KRB5_AUTH
#include <krb5.h>
#endif

#ifdef NO_UTIMBUF
struct utimbuf {
  time_t actime;
  time_t modtime;
};
#endif

#ifdef NO_STRERROR
#ifndef strerror
extern char *sys_errlist[];
#define strerror(i) sys_errlist[i]
#endif
#endif

#ifndef perror
#define perror(m) printf("%s: %s\n",m,strerror(errno))
#endif

#ifndef MAXHOSTNAMELEN
#define MAXHOSTNAMELEN 255
#endif

#include "version.h"
#include "smb.h"
#include "nameserv.h"
#include "ubiqx/ubi_dLinkList.h"

#include "byteorder.h"

#include "kanji.h"
#include "charset.h"

/***** automatically generated prototypes *****/
#include "rpc_pipes/rpc_proto.h"
#include "proto.h"



#ifndef S_IFREG
#define S_IFREG 0100000
#endif

#ifndef S_ISREG
#define S_ISREG(x) ((S_IFREG & (x))!=0)
#endif

#ifndef S_ISDIR
#define S_ISDIR(x) ((S_IFDIR & (x))!=0)
#endif

#if !defined(S_ISLNK) && defined(S_IFLNK)
#define S_ISLNK(x) ((S_IFLNK & (x))!=0)
#endif

#ifdef UFC_CRYPT
#define crypt ufc_crypt
#endif

#ifdef REPLACE_STRLEN
#define strlen(s) Strlen(s)
#endif

#ifdef REPLACE_STRSTR
#define strstr(s,p) Strstr(s,p)
#endif

#ifdef REPLACE_MKTIME
#define mktime(t) Mktime(t)
#endif

#ifndef NGROUPS_MAX
#define NGROUPS_MAX 128
#endif

#ifndef EDQUOT
#define EDQUOT ENOSPC
#endif

#ifndef HAVE_GETGRNAM
#define HAVE_GETGRNAM 1
#endif

#ifndef SOL_TCP
#define SOL_TCP 6
#endif

/* default to using ftruncate workaround as this is safer than assuming
it works and getting lots of bug reports */
#ifndef FTRUNCATE_CAN_EXTEND
#define FTRUNCATE_CAN_EXTEND 0
#endif

/* maybe this unix doesn't separate RD and WR locks? */
#ifndef F_RDLCK
#define F_RDLCK F_WRLCK
#endif

#ifndef ENOTSOCK
#define ENOTSOCK EINVAL
#endif

#ifndef SIGCLD
#define SIGCLD SIGCHLD
#endif 

#ifndef MAP_FILE
#define MAP_FILE 0
#endif

#ifndef HAVE_FCNTL_LOCK
#define HAVE_FCNTL_LOCK 1
#endif

#ifndef WAIT3_CAST2
#define WAIT3_CAST2 (struct rusage *)
#endif

#ifndef WAIT3_CAST1
#define WAIT3_CAST1 (int *)
#endif

#ifndef QSORT_CAST
#define QSORT_CAST (int (*)())
#endif

#ifndef INADDR_LOOPBACK
#define INADDR_LOOPBACK 0x7f000001
#endif /* INADDR_LOOPBACK */

/* this is a rough check to see if this machine has a lstat() call.
   it is not guaranteed to work */
#if !defined(S_ISLNK)
#define lstat stat
#endif

/* Not all systems declare ERRNO in errno.h... and some systems #define it! */
#ifndef errno
extern int errno;
#endif 


#ifdef NO_EID
#define geteuid() getuid()
#define getegid() getgid()
#define seteuid(x) setuid(x)
#define setegid(x) setgid(x)
#endif


#if (HAVE_FCNTL_LOCK == 0)
/* since there is no locking available, system includes  */
/* for DomainOS 10.4 do not contain any of the following */
/* #define's. So, to satisfy the compiler, add these     */
/* #define's, although they arn't really necessary.      */
#define F_GETLK 0
#define F_SETLK 0
#define F_WRLCK 0
#define F_UNLCK 0
#endif /* HAVE_FCNTL_LOCK == 0 */

#ifdef NOSTRCASECMP
#define strcasecmp(s1,s2) StrCaseCmp(s1,s2)
#define strncasecmp(s1,s2,n) StrnCaseCmp(s1,s2,n)
#endif

#ifndef strcpy
#define strcpy(dest,src) StrCpy(dest,src)
#endif


/* possibly wrap the malloc calls */
#if WRAP_MALLOC

/* undo the old malloc def if necessary */
#ifdef malloc
#define xx_old_malloc malloc
#undef malloc
#endif

#define malloc(size) malloc_wrapped(size,__FILE__,__LINE__)

/* undo the old realloc def if necessary */
#ifdef realloc
#define xx_old_realloc realloc
#undef realloc
#endif

#define realloc(ptr,size) realloc_wrapped(ptr,size,__FILE__,__LINE__)

/* undo the old free def if necessary */
#ifdef free
#define xx_old_free free
#undef free
#endif

#define free(ptr) free_wrapped(ptr,__FILE__,__LINE__)

/* and the malloc prototypes */
void *malloc_wrapped(int,char *,int);
void *realloc_wrapped(void *,int,char *,int);
void free_wrapped(void *,char *,int);

#endif


#if WRAP_MEMCPY
/* undo the old memcpy def if necessary */
#ifdef memcpy
#define xx_old_memcpy memcpy
#undef memcpy
#endif

#define memcpy(d,s,l) memcpy_wrapped(d,s,l,__FILE__,__LINE__)
void *memcpy_wrapped(void *d,void *s,int l,char *fname,int line);
#endif

#endif
