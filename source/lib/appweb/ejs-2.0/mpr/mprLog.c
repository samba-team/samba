/**
 *	@file 		mprLog.c
 *	@brief 		Mbedthis Portable Runtime (MPR) Logging and error reporting.
 *	@remarks 	We always provide these routines.
 */

/*********************************** License **********************************/
/*
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

#include	"mpr.h"

/****************************** Forward Declarations **************************/

static void	defaultLogHandler(MPR_LOC_DEC(ctx, loc), int flags, 
				int level, const char *msg);
static void logOutput(MPR_LOC_DEC(ctx, loc), int flags, int level, 
				const char *msg);

/************************************ Code ************************************/

void mprLog(MprCtx ctx, int level, const char *fmt, ...)
{
	va_list		args;
	char		*buf;

	if (level > mprGetLogLevel(ctx)) {
		return;
	}

	va_start(args, fmt);
	mprAllocVsprintf(MPR_LOC_ARGS(ctx), &buf, 0, fmt, args);
	va_end(args);

	logOutput(MPR_LOC_ARGS(ctx), MPR_LOG_SRC, level, buf);

	va_end(args);
	mprFree(buf);
}

/*****************************************************************************/
/*
 *	Do raw output
 */

void mprRawLog(MprCtx ctx, const char *fmt, ...)
{
	va_list		args;
	char		*buf;
	int			len;

	va_start(args, fmt);
	len = mprAllocVsprintf(MPR_LOC_ARGS(ctx), &buf, 0, fmt, args);
	va_end(args);
	
	logOutput(MPR_LOC_ARGS(ctx), MPR_RAW, 0, buf);
	mprFree(buf);
}

/*****************************************************************************/
/*
 *	Handle an error
 */

void mprError(MPR_LOC_DEC(ctx, loc), const char *fmt, ...)
{
	va_list		args;
	char		*buf;
	int			len;

	va_start(args, fmt);
	len = mprAllocVsprintf(MPR_LOC_ARGS(ctx), &buf, 0, fmt, args);
	va_end(args);
	
	logOutput(MPR_LOC_PASS(ctx, loc), MPR_ERROR_MSG | MPR_ERROR_SRC, 0, buf);

	mprFree(buf);
}

/*****************************************************************************/
/*
 *	Handle an error that should be displayed to the user
 */

void mprUserError(MPR_LOC_DEC(ctx, loc), const char *fmt, ...)
{
	va_list		args;
	char		*buf;
	int			len;

	va_start(args, fmt);
	len = mprAllocVsprintf(MPR_LOC_ARGS(ctx), &buf, 0, fmt, args);
	va_end(args);
	
	logOutput(MPR_LOC_PASS(ctx, loc), MPR_USER_MSG | MPR_ERROR_SRC, 0, buf);

	mprFree(buf);
}

/*****************************************************************************/
/*
 *	Handle a fatal error. Forcibly shutdown the application.
 */

void mprFatalError(MPR_LOC_DEC(ctx, loc), const char *fmt, ...)
{
	va_list		args;
	char		*buf;
	int			len;

	va_start(args, fmt);
	len = mprAllocVsprintf(MPR_LOC_ARGS(ctx), &buf, 0, fmt, args);
	va_end(args);
	
	logOutput(MPR_LOC_PASS(ctx, loc), MPR_USER_MSG | MPR_FATAL_SRC, 0, buf);

	mprFree(buf);

#if BREW
	mprSignalExit(ctx);
#else
	exit(2);
#endif
}

/*****************************************************************************/
/*
 *	Handle a program assertion
 */

void mprAssertError(MPR_LOC_DEC(ctx, loc), const char *msg)
{
	logOutput(MPR_LOC_PASS(ctx, loc), MPR_ASSERT_MSG | MPR_ASSERT_SRC, 0, msg);
}

/*****************************************************************************/
/*
 *	Handle an error
 */

void mprStaticError(MPR_LOC_DEC(ctx, loc), const char *fmt, ...)
{
	va_list		args;
	int			len;
	char		buf[MPR_MAX_STRING];

	va_start(args, fmt);
	len = mprVsprintf(buf, sizeof(buf), fmt, args);
	va_end(args);

	logOutput(MPR_LOC_PASS(ctx, loc), MPR_ERROR_MSG | MPR_ERROR_SRC, 0, buf);
}

/*****************************************************************************/
/*
 *	Direct output to the standard output. Does not hook into the logging 
 *	system and does not allocate memory.
 */

void mprStaticAssert(const char *loc, const char *msg)
{
#if BLD_DEBUG
	char	buf[MPR_MAX_STRING];
	int		len;

	len = mprSprintf(buf, sizeof(buf), "Assertion %s, failed at %s\n", 
		msg, loc);
	mprBreakpoint(loc, buf);
	
#if BLD_HOST_UNIX
	/*
	 *	MOB -- but is stdout always okay to use
	 */
	write(1, buf, len);
#elif BREW || WIN
	/*
	 *	Only time we use printf. We can't get an alloc context so we have
	 *	to use real print
	 */
#if BREW && !BREW_SIMULATOR
	printf(" MP: %s\n", buf);
#else
	printf("%s\n", buf);
#endif

#endif
#endif
}

/*****************************************************************************/

int mprGetLogLevel(MprCtx ctx)
{
	return mprGetApp(ctx)->logLevel;
}

/******************************************************************************/

void mprSetLogLevel(MprCtx ctx, int level)
{
	mprGetApp(ctx)->logLevel = level;
}

/*****************************************************************************/
/*
 *	Output a log message to the log handler
 */

static void logOutput(MPR_LOC_DEC(ctx, loc), int flags, int level, 
	const char *msg)
{
	MprLogHandler 	handler;

	if (flags & (MPR_ERROR_SRC | MPR_FATAL_SRC | MPR_ASSERT_SRC)) {
		mprBreakpoint(MPR_LOC, 0);
	}

	mprAssert(ctx != 0);
	handler = mprGetApp(ctx)->logHandler;
	if (handler != 0) {
		(handler)(MPR_LOC_PASS(ctx, loc), flags, level, msg);
		return;
	}
	defaultLogHandler(MPR_LOC_PASS(ctx, loc), flags, level, msg);
}

/*****************************************************************************/
/*
 *	Default log output is just to the console
 */

static void defaultLogHandler(MPR_LOC_DEC(ctx, loc), int flags, 
	int level, const char *msg)
{
	MprApp	*app;
	char	*prefix;

	app = mprGetApp(ctx);
	prefix = app->name;

	while (*msg == '\n') {
		mprPrintf(ctx, "\n");
		msg++;
	}

	if (flags & MPR_LOG_SRC) {
#if BREW && !BREW_SIMULATOR
		mprPrintf(ctx, "%s\n", msg);
#else
		mprPrintf(ctx, "%s: %d: %s\n", prefix, level, msg);
#endif

	} else if (flags & MPR_ERROR_SRC) {
		/*
		 *	Use static printing to avoid malloc when the messages are small.
		 *	This is important for memory allocation errors.
		 */
		if (strlen(msg) < (MPR_MAX_STRING - 32)) {
			mprStaticPrintf(ctx, "%s: Error: %s\n", prefix, msg);
		} else {
			mprPrintf(ctx, "%s: Error: %s\n", prefix, msg);
		}

	} else if (flags & MPR_FATAL_SRC) {
		mprPrintf(ctx, "%s: Fatal: %s\n", prefix, msg);
		
	} else if (flags & MPR_ASSERT_SRC) {
#if BLD_FEATURE_ALLOC_LEAK_TRACK
		mprPrintf(ctx, "%s: Assertion %s, failed at %s\n", prefix, msg, loc);
#else
		mprPrintf(ctx, "%s: Assertion %s, failed\n", prefix, msg);
#endif

	} else if (flags & MPR_RAW) {
		mprPrintf(ctx, "%s", msg);

	} else {
		return;
	}
}

/*****************************************************************************/
/*
 *	Map the O/S error code to portable error codes.
 */

int mprGetOsError()
{
#if WIN
	int		rc;
	rc = GetLastError();

	/*
	 *	Client has closed the pipe
	 */
	if (rc == ERROR_NO_DATA) {
		return EPIPE;
	}
	return rc;
#endif
#if LINUX || VXWORKS || SOLARIS
	return errno;
#endif
#if BREW
	/*
	 *	No such thing on Brew. Errors are per class
	 */
	return 0;
#endif
}

/******************************************************************************/
#if UNUSED

const char *mprGetErrorMsg(int err)
{
	/*
	 *	MPR error messages. Declare here so we don't have any globals.
	 */
	char *mprErrMessages[] = {
		/*    0 MPR_ERR_OK				*/  "Success", 
		/* -201 MPR_ERR_GENERAL			*/  "General error", 
		/* -202 MPR_ERR_ABORTED			*/  "Aborted", 
		/* -203 MPR_ERR_ALREADY_EXISTS	*/  "Already exists", 
		/* -204 MPR_ERR_BAD_ARGS		*/  "Bad args", 
		/* -205 MPR_ERR_BAD_FORMAT		*/  "Bad format", 
		/* -206 MPR_ERR_BAD_HANDLE		*/  "Bad handle", 
		/* -207 MPR_ERR_BAD_STATE		*/  "Bad state", 
		/* -208 MPR_ERR_BAD_SYNTAX		*/  "Bad syntax", 
		/* -209 MPR_ERR_BAD_TYPE		*/  "Bad type", 
		/* -210 MPR_ERR_BAD_VALUE		*/  "Bad value", 
		/* -211 MPR_ERR_BUSY			*/  "Busy", 
		/* -212 MPR_ERR_CANT_ACCESS		*/  "Can't access", 
		/* -213 MPR_ERR_CANT_COMPLETE	*/  "Can't complete", 
		/* -214 MPR_ERR_CANT_CREATE		*/  "Can't create", 
		/* -215 MPR_ERR_CANT_INITIALIZE	*/  "Can't initialize", 
		/* -216 MPR_ERR_CANT_OPEN		*/  "Can't open", 
		/* -217 MPR_ERR_CANT_READ		*/  "Can't read", 
		/* -218 MPR_ERR_CANT_WRITE		*/  "Can't write", 
		/* -219 MPR_ERR_DELETED			*/  "Already deleted", 
		/* -220 MPR_ERR_NETWORK			*/  "Network error", 
		/* -221 MPR_ERR_NOT_FOUND		*/  "Not found", 
		/* -222 MPR_ERR_NOT_INITIALIZED	*/  "Not initialized", 
		/* -223 MPR_ERR_NOT_READY		*/  "Not ready", 
		/* -224 MPR_ERR_READ_ONLY		*/  "Read only", 
		/* -225 MPR_ERR_TIMEOUT			*/  "Timeout", 
		/* -226 MPR_ERR_TOO_MANY		*/  "Too many", 
		/* -227 MPR_ERR_WONT_FIT		*/  "Won't fit", 
		/* -228 MPR_ERR_WOULD_BLOCK		*/  "Would block", 
		/* -229 MPR_ERR_CANT_ALLOCATE	*/  "Can't allocate", 
	};
	int mprNumErr = sizeof(mprErrMessages) / sizeof(char*);

/*
 *	Operating system error messages
 */
#if WIN
char *osErrMessages[] =
{
    /*  0              */  "No error",
    /*  1 EPERM        */  "Operation not permitted",
    /*  2 ENOENT       */  "No such file or directory",
    /*  3 ESRCH        */  "No such process",
    /*  4 EINTR        */  "Interrupted function call",
    /*  5 EIO          */  "I/O error",
    /*  6 ENXIO        */  "No such device or address",
    /*  7 E2BIG        */  "Arg list too long",
    /*  8 ENOEXEC      */  "Exec format error",
    /*  9 EBADF        */  "Bad file number",
    /* 10 ECHILD       */  "No child processes",
    /* 11 EAGAIN       */  "Try again",
    /* 12 ENOMEM       */  "Out of memory",
    /* 13 EACCES       */  "Permission denied",
    /* 14 EFAULT       */  "Bad address",
    /* 15 ENOTBLK      */  "Unknown error",
    /* 16 EBUSY        */  "Resource busy",
    /* 17 EEXIST       */  "File exists",
    /* 18 EXDEV        */  "Improper link",
    /* 19 ENODEV       */  "No such device",
    /* 20 ENOTDIR      */  "Not a directory",
    /* 21 EISDIR       */  "Is a directory",
    /* 22 EINVAL       */  "Invalid argument",
    /* 23 ENFILE       */  "Too many open files in system",
    /* 24 EMFILE       */  "Too many open files",
    /* 25 ENOTTY       */  "Inappropriate I/O control operation",
    /* 26 ETXTBSY      */  "Unknown error",
    /* 27 EFBIG        */  "File too large",
    /* 28 ENOSPC       */  "No space left on device",
    /* 29 ESPIPE       */  "Invalid seek",
    /* 30 EROFS        */  "Read-only file system",
    /* 31 EMLINK       */  "Too many links",
    /* 32 EPIPE        */  "Broken pipe",
    /* 33 EDOM         */  "Domain error",
    /* 34 ERANGE       */  "Result too large",
    /* 35 EUCLEAN      */  "Unknown error",
    /* 36 EDEADLK      */  "Resource deadlock would occur",
    /* 37 UNKNOWN      */  "Unknown error",
    /* 38 ENAMETOOLONG */  "Filename too long",
    /* 39 ENOLCK       */  "No locks available",
    /* 40 ENOSYS       */  "Function not implemented",
    /* 41 ENOTEMPTY    */  "Directory not empty",
    /* 42 EILSEQ       */  "Illegal byte sequence",
    /* 43 ENETDOWN     */  "Network is down",
    /* 44 ECONNRESET   */  "Connection reset",
    /* 45 ECONNREFUSED */  "Connection refused",
    /* 46 EADDRINUSE   */  "Address already in use"

};

#else /* WIN */

char *osErrMessages[] =
{
	/*   0 		 			*/	"Success"
	/*   1 EPERM 			*/	"Operation not permitted"
	/*   2 ENOENT 			*/	"No such file or directory"
	/*   3 ESRCH 			*/	"No such process"
	/*   4 EINTR 			*/	"Interrupted system call"
	/*   5 EIO 				*/	"I/O error"
	/*   6 ENXIO 			*/	"No such device or address"
	/*   7 E2BIG 			*/	"Arg list too long"
	/*   8 ENOEXEC 			*/	"Exec format error"
	/*   9 EBADF 			*/	"Bad file number"
	/*  10 ECHILD 			*/	"No child processes"
	/*  11 EAGAIN 			*/	"Try again"
	/*  12 ENOMEM 			*/	"Out of memory"
	/*  13 EACCES 			*/	"Permission denied"
	/*  14 EFAULT 			*/	"Bad address"
	/*  15 ENOTBLK 			*/	"Block device required"
	/*  16 EBUSY 			*/	"Device or resource busy"
	/*  17 EEXIST 			*/	"File exists"
	/*  18 EXDEV 			*/	"Cross-device link"
	/*  19 ENODEV 			*/	"No such device"
	/*  20 ENOTDIR 			*/	"Not a directory"
	/*  21 EISDIR 			*/	"Is a directory"
	/*  22 EINVAL 			*/	"Invalid argument"
	/*  23 ENFILE 			*/	"File table overflow"
	/*  24 EMFILE 			*/	"Too many open files"
	/*  25 ENOTTY 			*/	"Not a typewriter"
	/*  26 ETXTBSY 			*/	"Text file busy"
	/*  27 EFBIG 			*/	"File too large"
	/*  28 ENOSPC 			*/	"No space left on device"
	/*  29 ESPIPE 			*/	"Illegal seek"
	/*  30 EROFS 			*/	"Read-only file system"
	/*  31 EMLINK 			*/	"Too many links"
	/*  32 EPIPE 			*/	"Broken pipe"
	/*  33 EDOM 			*/	"Math argument out of domain of func"
	/*  34 ERANGE 			*/	"Math result not representable"
	/*  35 EDEADLK 			*/	"Resource deadlock would occur"
	/*  36 ENAMETOOLONG 	*/	"File name too long"
	/*  37 ENOLCK 			*/	"No record locks available"
	/*  38 ENOSYS 			*/	"Function not implemented"
	/*  39 ENOTEMPTY 		*/	"Directory not empty"
	/*  40 ELOOP 			*/	"Too many symbolic links encountered"
	/*  41 EWOULDBLOCK EAGAIN */"Operation would block"
	/*  42 ENOMSG 			*/	"No message of desired type"
	/*  43 EIDRM 			*/	"Identifier removed"

#if !BLD_FEATURE_SQUEEZE
	/*  44 ECHRNG 			*/	"Channel number out of range"
	/*  45 EL2NSYNC 		*/	"Level 2 not synchronized"
	/*  46 EL3HLT 			*/	"Level 3 halted"
	/*  47 EL3RST 			*/	"Level 3 reset"
	/*  48 ELNRNG 			*/	"Link number out of range"
	/*  49 EUNATCH 			*/	"Protocol driver not attached"
	/*  50 ENOCSI 			*/	"No CSI structure available"
	/*  51 EL2HLT 			*/	"Level 2 halted"
	/*  52 EBADE 			*/	"Invalid exchange"
	/*  53 EBADR 			*/	"Invalid request descriptor"
	/*  54 EXFULL 			*/	"Exchange full"
	/*  55 ENOANO 			*/	"No anode"
	/*  56 EBADRQC 			*/	"Invalid request code"
	/*  57 EBADSLT 			*/	"Invalid slot"
	/*  59 EBFONT 			*/	"Bad font file format"
	/*  60 ENOSTR 			*/	"Device not a stream"
	/*  61 ENODATA 			*/	"No data available"
	/*  62 ETIME 			*/	"Timer expired"
	/*  63 ENOSR 			*/	"Out of streams resources"
	/*  64 ENONET 			*/	"Machine is not on the network"
	/*  65 ENOPKG 			*/	"Package not installed"
	/*  66 EREMOTE 			*/	"Object is remote"
	/*  67 ENOLINK 			*/	"Link has been severed"
	/*  68 EADV 			*/	"Advertise error"
	/*  69 ESRMNT 			*/	"Srmount error"
	/*  70 ECOMM 			*/	"Communication error on send"
	/*  71 EPROTO 			*/	"Protocol error"
	/*  72 EMULTIHOP 		*/	"Multihop attempted"
	/*  73 EDOTDOT 			*/	"RFS specific error"
	/*  74 EBADMSG 			*/	"Not a data message"
	/*  75 EOVERFLOW 		*/	"Value too large for defined data type"
	/*  76 ENOTUNIQ 		*/	"Name not unique on network"
	/*  77 EBADFD 			*/	"File descriptor in bad state"
	/*  78 EREMCHG 			*/	"Remote address changed"
	/*  79 ELIBACC 			*/	"Can not access a needed shared library"
	/*  80 ELIBBAD 			*/	"Accessing a corrupted shared library"
	/*  81 ELIBSCN 			*/	".lib section in a.out corrupted"
	/*  82 ELIBMAX 			*/	"Linking in too many shared libraries"
	/*  83 ELIBEXEC 		*/	"Cannot exec a shared library directly"
	/*  84 EILSEQ 			*/	"Illegal byte sequence"
	/*  85 ERESTART 		*/	"Interrupted system call should be restarted"
	/*  86 ESTRPIPE 		*/	"Streams pipe error"
	/*  87 EUSERS 			*/	"Too many users"
	/*  88 ENOTSOCK 		*/	"Socket operation on non-socket"
	/*  89 EDESTADDRREQ		*/	"Destination address required"
	/*  90 EMSGSIZE 		*/	"Message too long"
	/*  91 EPROTOTYPE 		*/	"Protocol wrong type for socket"
	/*  92 ENOPROTOOPT 		*/	"Protocol not available"
	/*  93 EPROTONOSUPPORT 	*/	"Protocol not supported"
	/*  94 ESOCKTNOSUPPORT 	*/	"Socket type not supported"
	/*  95 EOPNOTSUPP 		*/	"Operation not supported on transport endpoint"
	/*  96 EPFNOSUPPORT 	*/	"Protocol family not supported"
	/*  97 EAFNOSUPPORT 	*/	"Address family not supported by protocol"
	/*  98 EADDRINUSE 		*/	"Address already in use"
	/*  99 EADDRNOTAVAIL 	*/	"Cannot assign requested address"
	/* 100 ENETDOWN 		*/	"Network is down"
	/* 101 ENETUNREACH 		*/	"Network is unreachable"
	/* 102 ENETRESET 		*/	"Network dropped connection because of reset"
	/* 103 ECONNABORTED 	*/	"Software caused connection abort"
	/* 104 ECONNRESET 		*/	"Connection reset by peer"
	/* 105 ENOBUFS 			*/	"No buffer space available"
	/* 106 EISCONN 			*/	"Transport endpoint is already connected"
	/* 107 ENOTCONN 		*/	"Transport endpoint is not connected"
	/* 108 ESHUTDOWN 		*/	"Cannot send after transport endpoint shutdown"
	/* 109 ETOOMANYREFS 	*/	"Too many references: cannot splice"
	/* 110 ETIMEDOUT 		*/	"Connection timed out"
	/* 111 ECONNREFUSED 	*/	"Connection refused"
	/* 112 EHOSTDOWN 		*/	"Host is down"
	/* 113 EHOSTUNREACH 	*/	"No route to host"
	/* 114 EALREADY 		*/	"Operation already in progress"
	/* 115 EINPROGRESS 		*/	"Operation now in progress"
	/* 116 ESTALE 			*/	"Stale NFS file handle"
	/* 117 EUCLEAN 			*/	"Structure needs cleaning"
	/* 118 ENOTNAM 			*/	"Not a XENIX named type file"
	/* 119 ENAVAIL 			*/	"No XENIX semaphores available"
	/* 120 EISNAM 			*/	"Is a named type file"
	/* 121 EREMOTEIO 		*/	"Remote I/O error"
	/* 122 EDQUOT 			*/	"Quota exceeded"
	/* 123 ENOMEDIUM 		*/	"No medium found"
	/* 124 EMEDIUMTYPE 		*/	"Wrong medium type"
};
#endif /* BLD_FEATURE_SQUEEZE */
#endif /* WIN */

	int osNumErr = sizeof(osErrMessages) / sizeof(char*);

	if (err < MPR_ERR_BASE) {
		err = MPR_ERR_BASE - err;
		if (err < 0 || err >= mprNumErr) {
			return "Bad error code";
		}
		return mprErrMessages[err];

	} else {
		/*
		 *	Negative O/S error code. Map to a positive standard Posix error.
		 */
		err = -err;
		if (err < 0 || err >= osNumErr) {
			return "Bad O/S error code";
		}
		return osErrMessages[err];
	}
}

#endif
/*****************************************************************************/

/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim:tw=78
 * vim600: sw=4 ts=4 fdm=marker
 * vim<600: sw=4 ts=4
 */
