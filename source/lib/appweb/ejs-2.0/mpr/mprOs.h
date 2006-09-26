/*
 *	@file 	mprOs.h
 *	@brief 	Include O/S headers and smooth out per-O/S differences
 *	@copy	default
 *	
 *	Copyright (c) Mbedthis Software LLC, 2003-2006. All Rights Reserved.
 *	
 *	This software is distributed under commercial and open source licenses.
 *	You may use the GPL open source license described below or you may acquire 
 *	a commercial license from Mbedthis Software. You agree to be fully bound 
 *	by the terms of either license. Consult the LICENSE.TXT distributed with 
 *	this software for full details.
 *	
 *	This software is open source; you can redistribute it and/or modify it 
 *	under the terms of the GNU General Public License as published by the 
 *	Free Software Foundation; either version 2 of the License, or (at your 
 *	option) any later version. See the GNU General Public License for more 
 *	details at: http://www.mbedthis.com/downloads/gplLicense.html
 *	
 *	This program is distributed WITHOUT ANY WARRANTY; without even the 
 *	implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. 
 *	
 *	This GPL license does NOT permit incorporating this software into 
 *	proprietary programs. If you are unable to comply with the GPL, you must
 *	acquire a commercial license to use this software. Commercial licenses 
 *	for this software and support services are available from Mbedthis 
 *	Software at http://www.mbedthis.com 
 *	
 *	@end
 */

/******************************* Documentation ********************************/

/*
 *	This header is part of the Mbedthis Portable Runtime and aims to include
 *	all necessary O/S headers and to unify the constants and declarations 
 *	required by Mbedthis products. It can be included by C or C++ programs.
 */

/******************************************************************************/

#ifndef _h_MPR_OS_HDRS
#define _h_MPR_OS_HDRS 1

#include	"buildConfig.h"

/********************************* CPU Families *******************************/
/*
 *	Porters, add your CPU families here and update configure code. 
 */
#define MPR_CPU_UNKNOWN		0
#define MPR_CPU_IX86		1
#define MPR_CPU_PPC 		2
#define MPR_CPU_SPARC 		3
#define MPR_CPU_XSCALE 		4
#define MPR_CPU_ARM 		5
#define MPR_CPU_MIPS 		6
#define MPR_CPU_68K 		7
#define MPR_CPU_SIMNT 		8			/* VxWorks NT simulator */
#define MPR_CPU_SIMSPARC 	9			/* VxWorks sparc simulator */

/********************************* O/S Includes *******************************/

#if LINUX || SOLARIS
	#include	<sys/types.h>
	#include	<time.h>
	#include	<arpa/inet.h>
	#include	<ctype.h>
	#include	<dirent.h>
	#include	<dlfcn.h>
	#include	<fcntl.h>
	#include	<grp.h> 
	#include	<errno.h>
	#include	<libgen.h>
	#include	<limits.h>
	#include	<netdb.h>
	#include	<net/if.h>
	#include	<netinet/in.h>
	#include	<netinet/tcp.h>
	#include	<netinet/ip.h>
	#include	<pthread.h> 
	#include	<pwd.h> 
	#include	<resolv.h>
	#include	<signal.h>
	#include	<stdarg.h>
	#include	<stdio.h>
	#include	<stdlib.h>
	#include	<string.h>
	#include	<syslog.h>
	#include	<sys/ioctl.h>
	#include	<sys/stat.h>
	#include	<sys/param.h>
	#include	<sys/resource.h>
	#include	<sys/sem.h>
	#include	<sys/shm.h>
	#include	<sys/socket.h>
	#include	<sys/select.h>
	#include	<sys/time.h>
	#include	<sys/times.h>
	#include	<sys/utsname.h>
	#include	<sys/wait.h>
	#include	<unistd.h>

#if LINUX
	#include	<stdint.h>
#endif

#if SOLARIS
	#include	<netinet/in_systm.h>
#endif

#if BLD_FEATURE_FLOATING_POINT
	#define __USE_ISOC99 1
	#include	<math.h>
	#include	<values.h>
#endif

#endif /* LINUX || SOLARIS */

#if VXWORKS
	#include	<vxWorks.h>
	#include	<envLib.h>
	#include	<sys/types.h>
	#include	<time.h>
	#include	<arpa/inet.h>
	#include	<ctype.h>
	#include	<dirent.h>
	#include	<fcntl.h>
	#include	<errno.h>
	#include	<limits.h>
	#include	<loadLib.h>
	#include	<netdb.h>
	#include	<net/if.h>
	#include	<netinet/tcp.h>
	#include	<netinet/in.h>
	#include	<netinet/ip.h>
	#include	<signal.h>
	#include	<stdarg.h>
	#include	<stdio.h>
	#include	<stdlib.h>
	#include	<string.h>
	#include	<sysSymTbl.h>
	#include	<sys/fcntlcom.h>
	#include	<sys/ioctl.h>
	#include	<sys/stat.h>
	#include	<sys/socket.h>
	#include	<sys/times.h>
	#include	<sys/wait.h>
	#include	<unistd.h>
	#include	<unldLib.h>

	#if BLD_FEATURE_FLOATING_POINT
	#include	<float.h>
	#define __USE_ISOC99 1
	#include	<math.h>
	#endif

	#include	<sockLib.h>
	#include	<inetLib.h>
	#include	<ioLib.h>
	#include	<pipeDrv.h>
	#include	<hostLib.h>
	#include	<netdb.h>
	#include	<tickLib.h>
	#include	<taskHookLib.h>

#endif /* VXWORKS */

#if MACOSX
	#include	<time.h>
	#include	<arpa/inet.h>
	#include	<ctype.h>
	#include	<fcntl.h>
	#include	<grp.h> 
	#include	<errno.h>
	#include	<libgen.h>
	#include	<limits.h>
	#include	<mach-o/dyld.h>
	#include	<netdb.h>
	#include	<net/if.h>
	#include	<netinet/in_systm.h>
	#include	<netinet/in.h>
	#include	<netinet/tcp.h>
	#include	<netinet/ip.h>
	#include	<pthread.h> 
	#include	<pwd.h> 
	#include	<resolv.h>
	#include	<signal.h>
	#include	<stdarg.h>
	#include	<stdio.h>
	#include	<stdlib.h>
	#include	<stdint.h>
	#include	<string.h>
	#include	<syslog.h>
	#include	<sys/ioctl.h>
	#include	<sys/types.h>
	#include	<sys/stat.h>
	#include	<sys/param.h>
	#include 	<sys/resource.h>
	#include	<sys/sem.h>
	#include	<sys/shm.h>
	#include	<sys/socket.h>
	#include	<sys/select.h>
	#include	<sys/time.h>
	#include	<sys/times.h>
	#include	<sys/types.h>
	#include	<sys/utsname.h>
	#include	<sys/wait.h>
	#include	<unistd.h>
#endif /* MACOSX */

#if WIN
	/*
	 *	We replace insecure functions with Mbedthis replacements
	 */
	#define _CRT_SECURE_NO_DEPRECATE 1

	#include	<ctype.h>
	#include	<conio.h>
	#include	<direct.h>
	#include	<errno.h>
	#include	<fcntl.h>
	#include	<io.h>
	#include	<limits.h>
	#include	<malloc.h>
	#include	<process.h>
	#include	<sys/stat.h>
	#include	<sys/types.h>
	#include	<stddef.h>
	#include	<stdio.h>
	#include	<stdlib.h>
	#include	<string.h>
	#include	<stdarg.h>
	#include	<time.h>
	#define WIN32_LEAN_AND_MEAN
	#include	<winsock2.h>
	#include	<windows.h>
	#include	<winbase.h>
	#if BLD_FEATURE_FLOATING_POINT
	#include	<float.h>
	#endif
	#include	<shlobj.h>
	#include	<shellapi.h>
	#include	<wincrypt.h>

#if BLD_DEBUG
	#include	<crtdbg.h>
#endif
	#include	"mprUnix.h"
#endif /* WIN */

#if BREW
	#if BLD_FEATURE_FLOATING_POINT
	#warning "Floating point is not supported on Brew"
	#endif
	#if BLD_FEATURE_MULTITHREAD
	#warning "Multithreading is not supported on Brew"
	#endif

	#include	"AEEModGen.h"
	#include	"AEEAppGen.h"
	#include	"BREWVersion.h"

	#if BREW_MAJ_VER == 2
		/*
		 *	Fix for BREW 2.X
		 */
		#ifdef __GNUC__
		#define __inline extern __inline__
		#endif
		#include	"AEENet.h"
		#undef __inline
	#endif

	#include	"AEE.h"
	#include	"AEEBitmap.h"
	#include	"AEEDisp.h"
	#include	"AEEFile.h"
	#include	"AEEHeap.h"
	#include	"AEEImageCtl.h"
	#include	"AEEMedia.h"
	#include	"AEEMediaUtil.h"
	#include	"AEEMimeTypes.h"
	#include	"AEEStdLib.h"
	#include	"AEEShell.h"
	#include	"AEESoundPlayer.h"
	#include	"AEEText.h"
	#include	"AEETransform.h"
	#include	"AEEWeb.h"
	#if BREW_MAJ_VER >= 3
	#include	"AEESMS.h"
	#endif
	#include	"AEETAPI.h"

#if 0
	#include	"AEESound.h"
	#include	"AEEDb.h"
	#include	"AEEMenu.h"
#endif

#endif /* BREW */

/******************************************************************************/
/******************************* General Defines ******************************/
/******************************************************************************/

#ifndef MAXINT
#if INT_MAX
	#define	MAXINT	INT_MAX
#else
	#define MAXINT	0x7fffffff
#endif
#endif

#ifndef BITSPERBYTE
#define BITSPERBYTE		(8 * sizeof(char))
#endif

#define BITS(type)		(BITSPERBYTE * (int) sizeof(type))

#ifndef max
#define max(a,b)  (((a) > (b)) ? (a) : (b))
#endif

#ifndef min
#define min(a,b)  (((a) < (b)) ? (a) : (b))
#endif

#define MPR_ARRAY_SIZE(type) 	(sizeof(type) / sizeof(type[0]))

#ifndef PRINTF_ATTRIBUTE
#if (__GNUC__ >= 3) && !DOXYGEN && BLD_FEATURE_ALLOC_LEAK_TRACK
/** Use gcc attribute to check printf fns.  a1 is the 1-based index of
 * the parameter containing the format, and a2 the index of the first
 * argument. Note that some gcc 2.x versions don't handle this
 * properly **/
#define PRINTF_ATTRIBUTE(a1, a2) __attribute__ ((format (__printf__, a1, a2)))
#else
#define PRINTF_ATTRIBUTE(a1, a2)
#endif
#endif

typedef char	*MprStr;					/* Used for dynamic strings */

#ifdef __cplusplus
extern "C" {
#else
typedef int bool;
#endif

/******************************************************************************/
/******************************** Linux Defines *******************************/
/******************************************************************************/

#if LINUX
	typedef unsigned char uchar;

#if BLD_FEATURE_INT64
	__extension__ typedef long long int int64;
	__extension__ typedef unsigned long long int uint64;
	#define INT64(x) (x##LL)
	#define UINT64(x) (x##ULL)
#endif

	#define closesocket(x)	close(x)
	#define MPR_BINARY		""
	#define MPR_TEXT		""
	#define O_BINARY		0
	#define O_TEXT			0
	#define	SOCKET_ERROR	-1
	#define MPR_DLL_EXT		".so"

#if BLD_FEATURE_FLOATING_POINT
	#define MAX_FLOAT		MAXFLOAT
#endif

/*
 *	For some reason it is removed from fedora pthreads.h and only
 *	comes in for UNIX96
 */
extern int pthread_mutexattr_gettype (__const pthread_mutexattr_t *__restrict
				      __attr, int *__restrict __kind) __THROW;
/* Set the mutex kind attribute in *ATTR to KIND (either PTHREAD_MUTEX_NORMAL,
   PTHREAD_MUTEX_RECURSIVE, PTHREAD_MUTEX_ERRORCHECK, or
   PTHREAD_MUTEX_DEFAULT).  */
extern int pthread_mutexattr_settype (pthread_mutexattr_t *__attr, int __kind)
     __THROW;

#endif 	/* LINUX  */

/******************************************************************************/
/******************************* VxWorks Defines ******************************/
/******************************************************************************/

#if VXWORKS

	typedef unsigned char uchar;
	typedef unsigned int uint;
	typedef unsigned long ulong;

	#define HAVE_SOCKLEN_T
	typedef int 	socklen_t;

#if BLD_FEATURE_INT64
	typedef long long int int64;
	typedef unsigned long long int uint64;
	#define INT64(x) (x##LL)
	#define UINT64(x) (x##ULL)
#endif

	#define closesocket(x)	close(x)
	#define getpid() 		taskIdSelf()
	#define MPR_BINARY		""
	#define MPR_TEXT		""
	#define O_BINARY		0
	#define O_TEXT			0
	#define	SOCKET_ERROR	-1
	#define MPR_DLL_EXT		".so"

#if BLD_FEATURE_FLOATING_POINT
	#define MAX_FLOAT 		FLT_MAX
#endif

	#undef R_OK
	#define R_OK	4
	#undef W_OK
	#define W_OK	2
	#undef X_OK
	#define X_OK	1
	#undef F_OK
	#define F_OK	0

	#define MSG_NOSIGNAL 0
	
	extern int access(char *path, int mode);
	extern int sysClkRateGet();

#endif 	/* VXWORKS */

/******************************************************************************/
/******************************** MacOsx Defines ******************************/
/******************************************************************************/
#if MACOSX
	typedef unsigned long ulong;
	typedef unsigned char uchar;

#if BLD_FEATURE_INT64
	__extension__ typedef long long int int64;
	__extension__ typedef unsigned long long int uint64;
	#define INT64(x) (x##LL)
	#define UINT64(x) (x##ULL)
#endif

	#define closesocket(x)	close(x)
	#define MPR_BINARY		""
	#define MPR_TEXT		""
	#define O_BINARY		0
	#define O_TEXT			0
	#define	SOCKET_ERROR	-1
	#define MPR_DLL_EXT		".dylib"
	#define MSG_NOSIGNAL	0
	#define __WALL          0x40000000
	#define PTHREAD_MUTEX_RECURSIVE_NP  PTHREAD_MUTEX_RECURSIVE

#if BLD_FEATURE_FLOATING_POINT
	#define MAX_FLOAT		MAXFLOAT
#endif

#endif /* MACOSX */

/******************************************************************************/
/******************************* Windows Defines ******************************/
/******************************************************************************/

#if WIN
	typedef unsigned char uchar;
	typedef unsigned int uint;
	typedef unsigned long ulong;
	typedef unsigned short ushort;

/*
 *	We always define INT64 types on windows
 */
#if BLD_FEATURE_INT64 || 1
	typedef __int64 int64;
	typedef unsigned __int64 uint64;
	#define INT64(x) (x##i64)
	#define UINT64(x) (x##Ui64)
#endif

	typedef int 	uid_t;
	typedef void 	*handle;
	typedef char 	*caddr_t;
	typedef long 	pid_t;
	typedef int	 	gid_t;
	typedef ushort 	mode_t;
	typedef void 	*siginfo_t;

	#define HAVE_SOCKLEN_T
	typedef int 	socklen_t;

	#undef R_OK
	#define R_OK	4
	#undef W_OK
	#define W_OK	2

	/*
	 *	On windows map X_OK to R_OK
	 */
	#undef X_OK
	#define X_OK	4
	#undef F_OK
	#define F_OK	0
	
	#ifndef EADDRINUSE
	#define EADDRINUSE		46
	#endif
	#ifndef EWOULDBLOCK
	#define EWOULDBLOCK		EAGAIN
	#endif
	#ifndef ENETDOWN
	#define ENETDOWN		43
	#endif
	#ifndef ECONNRESET
	#define ECONNRESET		44
	#endif
	#ifndef ECONNREFUSED
	#define ECONNREFUSED	45
	#endif

	#define MSG_NOSIGNAL	0
	#define MPR_BINARY		"b"
	#define MPR_TEXT		"t"

#if BLD_FEATURE_FLOATING_POINT
	#define MAX_FLOAT		DBL_MAX
#endif

#ifndef FILE_FLAG_FIRST_PIPE_INSTANCE
#define FILE_FLAG_FIRST_PIPE_INSTANCE   0x00080000
#endif

	#define MPR_DLL_EXT		".dll"
#endif /* WIN */

/******************************************************************************/
/****************************** Solaris Defines *******************************/
/******************************************************************************/

#if SOLARIS
	typedef unsigned char uchar;

#if BLD_FEATURE_INT64
	typedef long long int int64;
	typedef unsigned long long int uint64;
	#define INT64(x) (x##LL)
	#define UINT64(x) (x##ULL)
#endif

	#define closesocket(x)	close(x)
	#define MPR_BINARY		""
	#define MPR_TEXT		""
	#define O_BINARY		0
	#define O_TEXT			0
	#define	SOCKET_ERROR	-1
	#define MPR_DLL_EXT		".so"
	#define MSG_NOSIGNAL	0
	#define INADDR_NONE		((in_addr_t) 0xffffffff)
	#define __WALL	0
	#define PTHREAD_MUTEX_RECURSIVE_NP  PTHREAD_MUTEX_RECURSIVE

#if BLD_FEATURE_FLOATING_POINT
	#define MAX_FLOAT		MAXFLOAT
#endif

#endif /* SOLARIS */

/******************************************************************************/
/********************************* BREW Defines *******************************/
/******************************************************************************/

#if BREW
	typedef unsigned char uchar;
	typedef unsigned int uint;
	typedef unsigned long ulong;
	typedef unsigned short ushort;

	typedef uint	off_t;
	typedef long 	pid_t;

#if UNUSED
	typedef int 	uid_t;
	typedef void 	*handle;
	typedef char 	*caddr_t;
	typedef int	 	gid_t;
	typedef ushort 	mode_t;
	typedef void 	*siginfo_t;

	#define HAVE_SOCKLEN_T
	typedef int 	socklen_t;

	#ifndef EADDRINUSE
	#define EADDRINUSE		46
	#endif
	#ifndef EWOULDBLOCK
	#define EWOULDBLOCK		EAGAIN
	#endif
	#ifndef ENETDOWN
	#define ENETDOWN		43
	#endif
	#ifndef ECONNRESET
	#define ECONNRESET		44
	#endif
	#ifndef ECONNREFUSED
	#define ECONNREFUSED	45
	#endif

	#define MSG_NOSIGNAL	0
	#define MPR_BINARY		"b"
	#define MPR_TEXT		"t"

	#define MPR_DLL_EXT		".dll"
#endif

	#define O_RDONLY		0
	#define O_WRONLY		1
	#define O_RDWR			2
	#define O_CREAT			0x200
	#define O_TRUNC			0x400
	#define O_BINARY		0
	#define O_TEXT			0x20000
	#define O_EXCL			0x40000
	#define O_APPEND		0x80000

	#define R_OK	4
	#define W_OK	2
	#define X_OK	1
	#define F_OK	0

	#define SEEK_SET	0
	#define SEEK_CUR	1
	#define SEEK_END	2

#if UNUSED
struct stat {
	uint	st_size;
};
#endif

extern int	getpid();
extern int	isalnum(int c);
extern int	isalpha(int c);
extern int	isdigit(int c);
extern int	islower(int c);
extern int	isupper(int c);
extern int	isspace(int c);
extern int	isxdigit(int c);

extern uint	strlen(const char *str);
extern char	*strstr(const char *string, const char *strSet);
extern void	*memset(const void *dest, int c, uint count);
extern void	exit(int status);
extern char	*strpbrk(const char *str, const char *set);
extern uint	strspn(const char *str, const char *set);
extern int	tolower(int c);
extern int	toupper(int c);
extern void	*memcpy(void *dest, const void *src, uint count);
extern void	*memmove(void *dest, const void *src, uint count);

extern int	atoi(const char *str);
extern void	free(void *ptr);
extern void	*malloc(uint size);
extern void	*realloc(void *ptr, uint size);
extern char	*strcat(char *dest, const char *src);
extern char	*strchr(const char *str, int c);
extern int	strcmp(const char *s1, const char *s2);
extern int	strncmp(const char *s1, const char *s2, uint count);
extern char	*strcpy(char *dest, const char *src);
extern char	*strncpy(char *dest, const char *src, uint count);
extern char	*strrchr(const char *str, int c);

#undef  printf
#define printf DBGPRINTF

#if BREW_SIMULATOR && BLD_DEBUG
extern _CRTIMP int __cdecl _CrtCheckMemory(void);
extern _CRTIMP int __cdecl _CrtSetReportHook();
#endif

#endif /* BREW */

/******************************************************************************/
#ifdef __cplusplus
}
#endif

#endif /* _h_MPR_OS_HDRS */

/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim:tw=78
 * vim600: sw=4 ts=4 fdm=marker
 * vim<600: sw=4 ts=4
 */
