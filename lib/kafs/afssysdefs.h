/*
 * This section is for machines using single entry point AFS syscalls!
 * or
 * This section is for machines using multiple entry point AFS syscalls!
 */

#if SunOS == 4
#define AFS_SYSCALL	31
#endif

#if SunOS == 5
#define AFS_SYSCALL	105
#endif

#if defined(hpux)
#define AFS_SYSCALL	50
#define AFS_SYSCALL2	49
#endif

#if defined(_AIX)
/* _AIX is too weird */
#endif

#if defined(sgi)
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

#if defined(__linux)
/* Kent Engström <kent@lysator.liu.se> 1995-08-22
   Linux has no SIGSYS signal. Furthermore, the normal
   kernels have no support for AFS. I'm not sure about
   what to do, but for now I use SIGILL instead of SIGSYS.
*/
#define SIGSYS SIGILL
#endif /* __linux */

#if defined(__NetBSD__)
#define AFS_SYSCALL 210
#endif
