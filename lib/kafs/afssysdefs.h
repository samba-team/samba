/* $Id$ */

/*
 * This section is for machines using single entry point AFS syscalls!
 * and/or
 * This section is for machines using multiple entry point AFS syscalls!
 *
 * SunOS 4 is an example of single entry point and sgi of multiple
 * entry point syscalls.
 */

#if SunOS == 4
#define AFS_SYSCALL	31
#endif

#if SunOS == 5
#define AFS_SYSCALL	105
#endif

#if defined(__hpux)
#define AFS_SYSCALL	50
#define AFS_SYSCALL2	49
#endif

#if defined(_AIX)
/* _AIX is too weird */
#endif

#if defined(__sgi)
#define AFS_PIOCTL      (64+1000)
#define AFS_SETPAG      (65+1000)
#endif

#if defined(__osf__)
#define AFS_SYSCALL	232
#define AFS_SYSCALL2	258
#endif

#if defined(__ultrix)
#define AFS_SYSCALL	31
#endif

#if defined(__NetBSD__)
#define AFS_SYSCALL 210
#endif

#ifdef SYS_afs_syscall
#undef  AFS_SYSCALL
#define AFS_SYSCALL	SYS_afs_syscall
#endif
