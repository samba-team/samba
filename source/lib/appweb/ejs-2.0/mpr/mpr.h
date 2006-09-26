/*
 *	@file 	mpr.h
 *	@brief 	Header for the Mbedthis Portable Runtime (MPR) Base.
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
 *	See mpr.dox for additional documentation.
 */

/******************************************************************************/

#ifndef _h_MPR
#define _h_MPR 1

/***********************************Includes **********************************/

#include "mprOs.h"

/******************************************************************************/

#ifdef __cplusplus
extern "C" {
#endif

/********************************** Constants *********************************/

#if BLD_FEATURE_SQUEEZE
#if BREW || DOXYGEN
/*
 *	Maximum length of a file path name. Reduced from the system maximum to 
 *	save memory space.
 */
#define MPR_MAX_FNAME			64			/**< Reasonable filename size */
#define MPR_MAX_PATH			64			/**< Reasonable path name size */
#define MPR_DEFAULT_STACK		(16 * 1024)	/**< Default stack size */
#else
#define MPR_MAX_FNAME			128			/**< Reasonable filename size */
#define MPR_MAX_PATH			256 		/**< Reasonable path name size */
#define MPR_DEFAULT_STACK		(32 * 1024)	/**< Default stack size */
#endif
/*
 *	Reasonable length of a file name used by the product. Use where you know
 *	the expected file name and it is certain to be less than this limit.
 */
#define MPR_DEFAULT_ALLOC		64			/**< Default small alloc size */
#define MPR_DEFAULT_HASH_SIZE	23			/**< Default size of hash table */ 
#define MPR_MAX_ARGC			32			/**< Reasonable max of args */
#define MPR_MAX_STRING			512			/**< Maximum (stack) string size */
#define MPR_MAX_LOG_STRING		512			/**< Maximum log message */
#define MPR_MAX_URL				256			/**< Reasonable size of a URL */
#define MPR_BUFSIZE				512			/**< Reasonable size for buffers */
#define MPR_SLAB_STR_MAX		32			/**< Size of string slab blocks */
#define MPR_SLAB_STR_INC		32			/**< Pre-allocate increment */
#define MPR_SLAB_DEFAULT_INC	8			/**< Default pre-allocate inc */
#define MPR_ARRAY_INCR			8			/**< Default array growth inc */
#define MPR_BUF_INCR			1024		/**< Default array growth inc */
#define MPR_MAX_BUF				(1024*4096)	/**< Default array growth inc */

#define MPR_BLK_HDR_SIZE 		((sizeof(struct MprBlk) + 3) & ~3)

#else
#define MPR_MAX_FNAME			256
#define MPR_MAX_PATH			1024
#define MPR_DEFAULT_ALLOC		256
#define MPR_DEFAULT_HASH_SIZE	43
#define MPR_DEFAULT_STACK		(64 * 1024)
#define MPR_MAX_ARGC			128
#define MPR_MAX_STRING			4096
#define MPR_MAX_LOG_STRING		8192
#define MPR_MAX_URL				1024
#define MPR_BUFSIZE				1024
#define MPR_SLAB_STR_MAX		32
#define MPR_SLAB_STR_INC		64
#define MPR_SLAB_DEFAULT_INC	16
#define MPR_ARRAY_INCR			16
#define MPR_BUF_INCR			1024
#define MPR_MAX_BUF				(1024*4096)

#define MPR_BLK_HDR_SIZE 		((sizeof(struct MprBlk) + 15) & ~15)
#endif

/**
 *	Maximum size of a host name string
 */
#define MPR_MAX_IP_NAME			64

/**
 *	Maximum size of an IP address
 */
#define MPR_MAX_IP_ADDR			16

/**
 *	Maximum size of an IP address including port number
 */
#define MPR_MAX_IP_ADDR_PORT	32

#define MPR_MAX_SLAB 			16			/* Slabs from 32-512 bytes */

#define MPR_MAX_TIME_SYNC		(10 * 1000)	/* Time sync adjustments */

/**
 *	@overview Memory context type
 * 	@description Blocks of memory are allocated using a memory context 
 * 		as the parent with the \ref MprApp structure being the root of the
 * 		tree. Any allocated memory block may serve as the memory context for
 * 		subsequent memory allocations. Freeing a block via \ref mprFree will
 * 		release the allocated block and all child blocks.
 *  @stability Prototype.
 *  @library libmpr.
 * 	@see mprInit, mprAlloc, mprFree
 */
typedef const void *MprCtx;

/*
 *	Allocated memory destructor type
 */
typedef int (*MprDestructor)(void *);

/******************************** Error Codes *********************************/

/*
 *	Standard MPR return and error codes 
 */

#define MPR_ERR_OK						(0) 				
/**< Success */

#define MPR_ERR_BASE					(-200)
/**< Base error code */

#define MPR_ERR_GENERAL					(MPR_ERR_BASE - 1)	
/**< General error */
#define MPR_ERR_ABORTED					(MPR_ERR_BASE - 2)	
/**< Action aborted */
#define MPR_ERR_ALREADY_EXISTS			(MPR_ERR_BASE - 3)	
/**< Item already exists */
#define MPR_ERR_BAD_ARGS				(MPR_ERR_BASE - 4)	
/**< Bad arguments or paramaeters */
#define MPR_ERR_BAD_FORMAT				(MPR_ERR_BASE - 5)	
/**< Bad input format */
#define MPR_ERR_BAD_HANDLE				(MPR_ERR_BASE - 6)	
#define MPR_ERR_BAD_STATE				(MPR_ERR_BASE - 7)	
/**< Module is in a bad state */
#define MPR_ERR_BAD_SYNTAX				(MPR_ERR_BASE - 8)	
/**< Input has bad syntax */
#define MPR_ERR_BAD_TYPE				(MPR_ERR_BASE - 9)	
#define MPR_ERR_BAD_VALUE				(MPR_ERR_BASE - 10)	
#define MPR_ERR_BUSY					(MPR_ERR_BASE - 11)	
#define MPR_ERR_CANT_ACCESS				(MPR_ERR_BASE - 12)	
/**< Can't access the file or resource */
#define MPR_ERR_CANT_COMPLETE			(MPR_ERR_BASE - 13)	
#define MPR_ERR_CANT_CREATE				(MPR_ERR_BASE - 14)	
/**< Can't create the file or resource */
#define MPR_ERR_CANT_INITIALIZE			(MPR_ERR_BASE - 15)	
#define MPR_ERR_CANT_OPEN				(MPR_ERR_BASE - 16)	
/**< Can't open the file or resource */
#define MPR_ERR_CANT_READ				(MPR_ERR_BASE - 17)	
/**< Can't read from the file or resource */
#define MPR_ERR_CANT_WRITE				(MPR_ERR_BASE - 18)	
/**< Can't write to the file or resource */
#define MPR_ERR_DELETED					(MPR_ERR_BASE - 19)	
#define MPR_ERR_NETWORK					(MPR_ERR_BASE - 20)	
#define MPR_ERR_NOT_FOUND				(MPR_ERR_BASE - 21)	
#define MPR_ERR_NOT_INITIALIZED			(MPR_ERR_BASE - 22)	
/**< Module or resource is not initialized */
#define MPR_ERR_NOT_READY				(MPR_ERR_BASE - 23)	
#define MPR_ERR_READ_ONLY				(MPR_ERR_BASE - 24)	
/**< The operation timed out */
#define MPR_ERR_TIMEOUT					(MPR_ERR_BASE - 25)	
#define MPR_ERR_TOO_MANY				(MPR_ERR_BASE - 26)	
#define MPR_ERR_WONT_FIT				(MPR_ERR_BASE - 27)	
#define MPR_ERR_WOULD_BLOCK				(MPR_ERR_BASE - 28)	
#define MPR_ERR_CANT_ALLOCATE			(MPR_ERR_BASE - 29)	
//	MOB -- rename NO_MEMORY
#define MPR_ERR_MEMORY					(MPR_ERR_BASE - 30)	
#define MPR_ERR_CANT_DELETE				(MPR_ERR_BASE - 31)	
#define MPR_ERR_MAX						(MPR_ERR_BASE - 32)	

/*
 *	Standard logging trace levels are 0 to 9 with 0 being the most verbose. 
 *	the These are ored with the error source and type flags. The MPR_LOG_MASK 
 *	is used to extract the trace level from a flags word. We expect most apps 
 *	to run with level 2 trace enabled.
 */
#define	MPR_ERROR		1		/**< Hard error trace level */
#define MPR_WARN		2		/**< Soft warning trace level */
#define	MPR_CONFIG		2		/**< Configuration settings trace level. */
#define MPR_INFO		3		/**< Informational trace only */
#define MPR_DEBUG		4		/**< Debug information trace level */
#define MPR_VERBOSE		9		/**< Highest level of trace */
#define MPR_LEVEL_MASK	0xf		/**< Level mask */

/*
 *	Error source flags
 */
#define MPR_ERROR_SRC	0x10	/**< Originated from mprError */
#define MPR_LOG_SRC		0x20	/**< Originated from mprLog */
#define MPR_ASSERT_SRC	0x40	/**< Originated from mprAssert */
#define	MPR_FATAL_SRC	0x80	/**< Fatal error. Log and exit */

/*
 *	Log message type flags. Specify what kind of log / error message it is.
 *	Listener handlers examine this flag to determine if they should process
 *	the message.Assert messages are trapped when in DEV mode. Otherwise ignored.
 */
#define	MPR_LOG_MSG		0x100	/**< Log trace message - not an error */
#define	MPR_ERROR_MSG	0x200	/**< General error */
#define	MPR_ASSERT_MSG	0x400	/**< Assert flags -- trap in debugger */
#define	MPR_USER_MSG	0x800	/**< User message */

/*
 *	Log output modifiers
 */
#define MPR_RAW			0x1000	/**< Raw trace output */

/*
 *	Error line number information.
 */
#define MPR_LINE(s)		#s
#define MPR_LINE2(s)	MPR_LINE(s)
#define MPR_LINE3		MPR_LINE2(__LINE__)
#define MPR_LOC 		__FILE__ ":" MPR_LINE3

/*
 *	Macros to pass file and line number information
 *		Use MPR_LOC_ARGS in normal user code.
 *		Use MPR_LOC_DEC  in declarations.
 *		Use MPR_LOC_PASS in layered APIs to pass original line info down.
 */
#if BLD_FEATURE_ALLOC_LEAK_TRACK
#define MPR_LOC_ARGS(ctx)		ctx, MPR_LOC
#define MPR_LOC_DEC(ctx, loc)	MprCtx ctx, const char *loc
#define MPR_LOC_PASS(ctx, loc)	ctx, loc
#else
#define MPR_LOC_ARGS(ctx)		ctx
#define MPR_LOC_DEC(ctx, loc)	MprCtx ctx 
#define MPR_LOC_PASS(ctx, loc)	ctx
#endif

/******************************* Debug and Assert *****************************/

extern void	mprBreakpoint(const char *loc, const char *msg);

#if BLD_FEATURE_ASSERT
	#define mprAssert(C) 	if (C) ; else mprStaticAssert(MPR_LOC, #C)
#else
	#define mprAssert(C)	if (1) ; else
#endif

/********************************* Safe Strings *******************************/
/*
 *	Unsafe functions that should not be used. Define UNSAFE_STRINGS_OK before
 *	including mpr.h if you really want to use these functions. A better approach
 *	is to undefine them just prior to using them in your C/C++ source file.
 */
#if BLD_FEATURE_SAFE_STRINGS

#if BLD_FEATURE_PHP4_MODULE || BLD_FEATURE_PHP5_MODULE
	#ifndef UNSAFE_FUNCTIONS_OK
		#define UNSAFE_FUNCTIONS_OK 1
	#endif
#endif

#ifndef UNSAFE_FUNCTIONS_OK
	#define sprintf			UseMprSprintfInstead
	#define fprintf			UseMprFprintfInstead
	#define vsprintf		UseMprVsprintfInstead
	#define strtok			UseMprStrTokInstead
	#define gethostbyname	UseMprGetHostByNameInstead
	#define ctime			UseMprCtimeInstead
	#define asctime			UseMprAsctimeInstead
	#define localtime		UseMprLocaltimeInstead
	#define gmtime			UseMprGmtimeInstead
	#define malloc			UseMprMallocInstead
	#define free			UseMprFreeInstead
	#define realloc			UseMprReallocInstead
	#define strncpy			UseMprStrcpyInstead
	#define inet_ntoa		UseMprInetToStrInstead

#if !BREW
	#define printf			UseMprPrintfInstead
#endif

	#if FUTURE
	#define strlen			UseMprStrlenInstead
	#define strcpy			UseMprStrcpyInstead
	#endif

#endif	/* UNSAFE_FUNCTIONS_OK */
#endif	/* BLD_FEATURE_SAFE_STRINGS */

/******************************************************************************/

struct MprBuf;
typedef int			(*MprBufProc)(struct MprBuf* bp, void *arg);

/**
 *	@overview Dynamic buffer structure
 *	@description MprBuf is a flexible, dynamic growable buffer structure. It
 *		utilizes a ring buffer mechanism and is suitable for high performance
 *		buffering in a variety of situations.
 *  @stability Prototype.
 *  @library libmpr.
 * 	@see mprCreateBuf, mprFree, MprArray
 */
typedef struct MprBuf {
	uchar			*buf;				/* Actual buffer for data */
	uchar			*endbuf;			/* Pointer one past the end of buffer */
	uchar			*start;				/* Pointer to next data char */
	uchar			*end;				/* Pointer one past the last data chr */
	int				buflen;				/* Current size of buffer */
	int				maxsize;			/* Max size the buffer can ever grow */
	int				growBy;				/* Next growth increment to use */
	MprBufProc		refillProc;			/* Auto-refill procedure */
	void			*refillArg;			/* Refill arg */
} MprBuf;

/**
 *	@overview File structure
 *	@description MprFile is the cross platform File I/O abstraction control
 *		structure.
 *  @stability Prototype.
 *  @library libmpr.
 * 	@see mprOpen, mprClose, mprRead, mprWrite
 */
typedef struct MprFile
{
	MprBuf			*buf;					/* Buffer for I/O */
#if BREW
	IFile			*fd;					/* File handle */
#else
	int				fd;
#endif
} MprFile;

/**
 *	File information structure
 *	@overview File information structure
 *	@description MprFileInfo is the cross platform File information structure.
 *  @stability Prototype.
 * 	@see mprGetFileInfo, mprOpen, mprClose, mprRead, mprWrite
 */
typedef struct MprFileInfo 
{
	uint			size;					/* File length */
	uint			ctime;					/* Create time */ 
	uint			mtime;					/* Modified time */ 
	uint			inode;					/* Inode number */
	int				isDir;					/* Set if directory */
	int				isReg;					/* Set if a regular file */
} MprFileInfo;

/**
 *	@overview Mpr time structure.
 *	@description MprTime is the cross platform time abstraction structure.
 *  @stability Prototype.
 *  @library libmpr.
 * 	@see mprGetTime
 */
typedef struct MprTime 
{
	uint			sec;					/* Seconds */
	uint			msec;					/* Milliseconds */
} MprTime;


/**
 *	@overview Generic array type
 *	@description The MprArray is a dynamic growable array suitable for storing
 *		pointers to arbitrary objects.
 *  @stability Prototype.
 *  @library libmpr.
 * 	@see mprCreateItemArray, mprFree, MprBuf
 */
typedef struct MprArray 
{
	int		capacity;						/* Current capacity of the array */
	int		length;							/* Count of used items */
	int		incr;							/* Growth increment */
	int		maxSize;						/* Maximum capacity */
	void	**items;
} MprArray;


#if BLD_FEATURE_MULTITHREAD
/**
 *	@overview Multithreading lock control structure
 *  @description MprLock is used for multithread locking in multithreaded
 *  	applications.
 *  @library libmpr.
 * 	@see mprCreateLock, mprDestroyLock, mprLock, mprUnlock
 */
typedef struct 
{
	#if WIN
		CRITICAL_SECTION cs;				/* O/S critical section */
	#endif
	#if LINUX || MACOSX || SOLARIS
		pthread_mutex_t	 cs;				/* O/S critical section */
	#endif
	#if VXWORKS
		SEM_ID		cs;						/* Semaphore */
	#endif
} MprLock;
#endif

/*
 *	Error and Logging callback 
 */
typedef void	(*MprLogHandler)(MPR_LOC_DEC(ctx, loc), int flags, 
					int level, const char *msg);

/*
 *	Symbol table
 *	MOB -- rename hash
 */
typedef struct MprSymbol
{
	struct MprSymbol *next;					/* Next symbol in hash chain */
	char 			*key;					/* Symbol key */
	void			*data;					/* Pointer to symbol data */
	int				bucket;					/* Hash bucket index */
} MprSymbol;

typedef struct MprSymbolTable
{
	MprSymbol		**buckets;
	int				hashSize;				/* Size of the buckets array */
	int				count;					/* Number of symbols in the table */
} MprSymbolTable;


/*
 *	Memory allocation error callback
 */
struct MprApp;
typedef int (*MprAllocCback)(struct MprApp *app, uint size, uint total, 
	bool granted);


/*
 *	Slab block pointer links
 */
typedef struct MprSlabBlock {
	struct MprSlabBlock	*next;
} MprSlabBlock;


#if BLD_FEATURE_ALLOC_STATS
/*
 *	Memory Slab Statistics
 */
typedef struct MprSlabStats {
	uint		allocCount;			/* Number of allocated blocks */
	uint		freeCount;			/* Number of blocks on the slab freelist */
	uint		peakAllocCount;		/* Peak allocated */ 
	uint		totalAllocCount;	/* Total count of allocation calls */
	uint		peakFreeCount;		/* Peak on the free list */ 
	MprSlabBlock *next;
} MprSlabStats;
#endif


/*
 *	Slab control structure
 */
typedef struct MprSlab {
	MprSlabBlock *next;
	uint		preAllocateIncr;	/* Pre-allocation increment */
#if BLD_FEATURE_ALLOC_STATS
	MprSlabStats stats;
#endif
} MprSlab;

/*
 *	Allocation stats (kept even in production code so we can detect memory 
 *	allocation failures)
 */
typedef struct MprAllocStats
{
	uint		bytesAllocated;				/* Bytes currently allocated */
	uint		peakAllocated;				/* Peak bytes allocated */
	uint		allocCount;					/* Number of allocated blocks */
	uint		redLine;					/* Warn above this level */
	uint		maxMemory;					/* Max memory to allocate */
	uint		errors;						/* Allocation errors */
} MprAllocStats;

/*
 *	Memory allocation control
 */

typedef struct MprAlloc {
	MprSlab			*slabs;					/* Array[MPR_MAX_SLAB] of MprSlab */
	MprAllocCback	cback;					/* Memory allocation callback */
	MprAllocStats	stats;					/* Keep stats even in release */
	int				inAllocException;		/* Recursive protect */
} MprAlloc;


/*
 *	MprApp State Flags
 */
#define MPR_APP_EXITING			0x1			/* App is exiting */
#define MPR_APP_ALLOC_ERROR		0x2			/* App has allocation error */

/*	MOB -- temporary */
#define MPR_APP_NEED_GC			0x4			/* App needs GC */

/**
 *	@overview Primary MPR application control structure
 *	@description The MprApp structure stores critical application state
 *		information and is the root memory allocation context block. It is
 *		used as the MprCtx context for other memory allocations and is thus
 *		the ultimate parent of all allocated memory.
 *	\n\n
 *	The MprApp structure is allocated by the mprInit API.
 */
typedef struct MprApp 
{
	uint			magic;					/* Corruption protection */
	MprFile			*console;				/* Stdout file */
	bool			debugMode;				/* Run in debug mode (no timers) */
	MprFile			*error;					/* Stderr file */
	int				logLevel;				/* Log trace level */
	MprFile			*logFile;				/* Log file */
	MprLogHandler	logHandler;				/* Current log handler callback */
	MprSymbolTable	*table;
	char			*name;					/* Product name */
	char			*title;					/* Product title */
	char			*version;				/* Product version */

#if BREW
	uint			classId;				/* Brew class ID */
	IShell			*shell;					/* Brew shell object */
	IDisplay		*display;				/* Brew display object */
	IFileMgr		*fileMgr;				/* File manager */
	ITAPI			*tapi;					/* TAPI object */
	int				displayHeight;			/* Display height */
	int				displayWidth;			/* Display width */
	char			*args;					/* Command line args */
#endif

	void			*stackStart;			/* Start of app stack */
	uint			maxStack;				/* Max stack size recorded */

	MprAlloc		alloc;					/* Memory allocation data */
	int				flags;					/* App state flags */

#if BLD_FEATURE_MULTITHREAD
	MprLock			*globalLock;
	MprLock			*allocLock;
#endif
} MprApp;


/*
 *	String type. Minimum size is 8 words (32 bytes).
 */
#define MPR_MAX_INLINE_STR		24


/*
 *	The block header structure for all allocated memory blocks (32 bytes)
 *	WARNING: Don't increase the size of this structure. It just fits into
 *	32 bytes currently. Alignment requirements will double this size if you 
 *	add one byte!
 */
typedef struct MprBlk
{
	MprApp			*app;			/* app is the top level alloc context */
	struct MprBlk	*parent;		/* Parent block */
	struct MprBlk	*children;		/* First child block */
	struct MprBlk	*next;			/* Next sibling */
	struct MprBlk	*prev;			/* Previous sibling */
	MprDestructor	destructor;		/* Destructor function (optional) */
	uint			size;			/* Size of block sans HDR_SIZE */
	uint			flags;			/* Allocation flags and magic number */
#if BLD_FEATURE_ALLOC_LEAK_TRACK
	const char		*location;		/* Allocating code (file + line) */
#endif
} MprBlk;

/******************************************************************************/
/****************************** Internal Prototypes ***************************/
/******************************************************************************/

extern void 	mprSignalAllocError(MprCtx ctx);

/******************************************************************************/
/********************************** Prototypes ********************************/
/******************************************************************************/

extern MprApp 	*mprInit(MprAllocCback cback);
extern MprApp 	*mprInitEx(MprAllocCback cback, void *shell);
extern void 	mprTerm(MprApp *app, bool doStats);
extern void 	mprSignalExit(MprCtx ctx);
extern bool 	mprIsExiting(MprCtx ctx);
extern bool		mprHasAllocError(MprCtx ctx);

#if BLD_DEBUG && UNUSED
extern MprApp	*mprGetApp(MprCtx ctx);
#else
#define mprGetApp(ctx) \
		(((MprBlk*) ((char*) ctx - MPR_BLK_HDR_SIZE))->app)
#endif

/******************************************************************************/

extern int 		mprSetKeyValue(MprCtx ctx, const char *key, void *ptr);
/* MOB -- should this be delete or remove or unset */
extern int 		mprRemoveKeyValue(MprCtx ctx, const char *key);
extern void 	*mprGetKeyValue(MprCtx ctx, const char *key);
/* MOB -- should be setAppName, getAppName */
extern int		mprSetAppName(MprCtx ctx, const char *name, const char *title,
					const char *version);
extern const char *mprGetAppName(MprCtx ctx);
extern const char *mprGetAppTitle(MprCtx ctx);
extern const char *mprGetAppVersion(MprCtx ctx);

/*
 *	File services
 */
extern void 	mprStopFileServices(MprCtx ctx);
extern int 		mprStartFileServices(MprCtx ctx);

/*
 *	Item Array
 */
#define mprCreateItemArray(ctx, initialSize, maxSize) \
				mprCreateItemArrayInternal(MPR_LOC_ARGS(ctx), initialSize, \
				maxSize)

extern MprArray	*mprCreateItemArrayInternal(MPR_LOC_DEC(ctx, loc), 
					int initialSize, int maxSize);
/* MOB -- should be insert not add/delete or insert / remove */
extern int 		mprAddItem(MprArray *array, void *item);
extern void		mprClearItems(MprArray *array);
extern void		mprClearAndFreeItems(MprArray *array);
extern int 		mprFindItem(MprArray *array, void *item);
extern void		*mprGetFirstItem(MprArray *array, int *lastIndex);
extern void		*mprGetItem(MprArray *array, int index);
extern int 		mprGetItemCapacity(MprArray *array);
extern int 		mprGetItemCount(MprArray *array);
extern void		*mprGetNextItem(MprArray *array, int *lastIndex);
extern void		*mprGetPrevItem(MprArray *array, int *lastIndex);
extern int 		mprRemoveItem(MprArray *array, void *item);
extern int 		mprRemoveItemByIndex(MprArray *array, int index);
extern int 		mprRemoveRangeOfItems(MprArray *array, int start, int end);


/*
 *	Printf replacements
 */
extern int		mprSprintf(char *buf, int maxSize, const char *fmt, ...)
					PRINTF_ATTRIBUTE(3,4);
extern int		mprVsprintf(char *buf, int maxSize, const char *fmt, 
					va_list arg) PRINTF_ATTRIBUTE(3,0);
extern char		*mprItoa(char *buf, int size, int value);
extern int 		mprAtoi(const char *str, int radix);

extern int		mprPrintf(MprCtx ctx, const char *fmt, ...)
					PRINTF_ATTRIBUTE(2,3);
/* MOB -- NEED DOC */
extern int		mprErrorPrintf(MprCtx ctx, const char *fmt, ...)
					PRINTF_ATTRIBUTE(2,3);
extern int		mprStaticPrintf(MprCtx ctx, const char *fmt, ...)
					PRINTF_ATTRIBUTE(2,3);
extern int		mprPrintfError(MprCtx ctx, const char *fmt, ...)
					PRINTF_ATTRIBUTE(2,3);
extern int		mprFprintf(MprFile *file, const char *fmt, ...)
					PRINTF_ATTRIBUTE(2,3);

/*
 *	Safe string routines
 */
extern char		*mprGetWordTok(char *buf, int bufsize, const char *str, 
						const char *delim, const char **tok);
extern int		mprMemcpy(char *dest, int destMax, const char *src, 
						int nbytes);
extern int		mprStrcat(char *dest, int max, const char *delim, 
					const char *src, ...);
extern int		mprStrcpy(char *dest, int destMax, const char *src);

extern int		mprStrcmpAnyCase(const char *str1, const char *str2);
extern int		mprStrcmpAnyCaseCount(const char *str1, const char *str2, 
					int len);
extern int		mprStrlen(const char *src, int max);

extern char		*mprStrLower(char *str);
extern char		*mprStrUpper(char *str);
extern char		*mprStrTrim(char *str, const char *set);
extern char		*mprStrTok(char *str, const char *delim, char **last);

/*
 *	Symbol table
 */
extern MprSymbolTable *mprCreateSymbolTable(MprCtx ctx, int hashSize);
extern MprSymbol	*mprGetFirstSymbol(MprSymbolTable *table);
extern MprSymbol	*mprGetNextSymbol(MprSymbolTable *table, MprSymbol *last);
extern int			mprGetSymbolCount(MprSymbolTable *table);
extern MprSymbol	*mprInsertSymbol(MprSymbolTable *table, const char *key, 
						void *ptr);
extern void			*mprLookupSymbol(MprSymbolTable *table, const char *key);
extern int			mprRemoveSymbol(MprSymbolTable *table, const char *key);

/*
 *	File I/O support
 */
extern void		mprClose(MprFile *file);
extern int		mprDelete(MprCtx ctx, const char *path);
extern int		mprDeleteDir(MprCtx ctx, const char *path);
extern int		mprGetFileInfo(MprCtx ctx, const char *path, MprFileInfo *info);
extern char		*mprGets(MprFile *file, char *buf, uint size);
extern int		mprMakeDir(MprCtx ctx, const char *path, int perms);
extern MprFile	*mprOpen(MprCtx ctx, const char *path, int omode, int perms);
extern int		mprPuts(MprFile *file, const char *buf, uint size);
extern int		mprRead(MprFile *file, void *buf, uint size);
extern int		mprSeek(MprFile *file, int seekType, long distance);
extern int		mprWrite(MprFile *file, const void *buf, uint count);

extern int		mprMakeTempFileName(MprCtx ctx, char *buf, int bufsize, 
					const char *tmpDir);


/*
 *	Error handling and logging
 */
extern void 	mprSetLogHandler(MprCtx ctx, MprLogHandler handler);
extern MprLogHandler mprGetLogHandler(MprCtx ctx);

extern void		mprAssertError(MPR_LOC_DEC(ctx, loc), const char *msg);
extern void		mprError(MPR_LOC_DEC(ctx, loc),
					const char *fmt, ...) PRINTF_ATTRIBUTE(3,4);
extern void		mprFatalError(MPR_LOC_DEC(ctx, loc),
					const char *fmt, ...) PRINTF_ATTRIBUTE(3,4);
extern void		mprLog(MprCtx ctx, int level,
					const char *fmt, ...) PRINTF_ATTRIBUTE(3,4);
extern void 	mprRawLog(MprCtx ctx, const char *fmt, ...);
extern void		mprStaticAssert(const char *loc, const char *msg);
extern void		mprStaticError(MPR_LOC_DEC(ctx, loc),
					const char *fmt, ...) PRINTF_ATTRIBUTE(3,4);
extern void		mprUserError(MPR_LOC_DEC(ctx, loc),
					const char *fmt, ...) PRINTF_ATTRIBUTE(3,4);

/*
 *	Dynamic Buffering routines
 */
extern MprBuf	*mprCreateBuf(MprCtx ctx, int initialSize, int maxSize);
extern char		*mprStealBuf(MprCtx ctx, MprBuf *bp);
extern void		mprAddNullToBuf(MprBuf *bp);
extern void		mprAdjustBufStart(MprBuf *bp, int size);
extern void		mprAdjustBufEnd(MprBuf *bp, int size);
extern void 	mprCopyBufDown(MprBuf *bp);
extern void		mprFlushBuf(MprBuf *bp);
extern int		mprGetCharFromBuf(MprBuf *bp);
extern int		mprGetBlockFromBuf(MprBuf *bp, uchar *buf, int len);
extern int		mprGetBufLength(MprBuf *bp);
extern int		mprGetBufLinearSpace(MprBuf *bp);
extern int		mprGetBufLinearData(MprBuf *bp);
extern char		*mprGetBufOrigin(MprBuf *bp);
extern int		mprGetBufSize(MprBuf *bp);
extern int		mprGetBufSpace(MprBuf *bp);
extern char		*mprGetBufStart(MprBuf *bp);
extern char		*mprGetBufEnd(MprBuf *bp);
extern int		mprInsertCharToBuf(MprBuf *bp, int c);
extern int		mprLookAtNextCharInBuf(MprBuf *bp);
extern int		mprLookAtLastCharInBuf(MprBuf *bp);
extern int		mprPutCharToBuf(MprBuf *bp, int c);
extern int 		mprPutBlockToBuf(MprBuf *bp, const char *str, int size);
extern int 		mprPutIntToBuf(MprBuf *bp, int i);
extern int 		mprPutStringToBuf(MprBuf *bp, const char *str);
extern int 		mprPutFmtStringToBuf(MprBuf *bp, const char *fmt, ...);
extern int		mprRefillBuf(MprBuf *bp);
extern void		mprResetBufIfEmpty(MprBuf *bp);
extern void		mprSetBufSize(MprBuf *bp, int initialSize, int maxSize);
extern MprBufProc mprGetBufRefillProc(MprBuf *bp);
extern void		mprSetBufRefillProc(MprBuf *bp, MprBufProc fn, void *arg);

/*
 *	General other xPlatform routines
 */
extern const char *mprGetBaseName(const char *name);
extern bool		mprGetDebugMode(MprCtx ctx);
extern char		*mprGetDirName(char *buf, int bufsize, const char *path);
extern char		*mprGetFullPathName(char *buf, int buflen, const char *path);
extern int 		mprGetLogLevel(MprCtx ctx);
extern int		mprGetOsError();


extern int		mprMakeArgv(MprCtx ctx, const char *prog, const char *cmd, 
					char ***argv, int *argc);
extern int		mprMakeDirPath(MprCtx ctx, const char *path);
extern void		mprSetDebugMode(MprCtx ctx, bool on);
extern void 	mprSetLogLevel(MprCtx ctx, int level);
extern void		mprSleep(MprCtx ctx, int msec);
extern void		mprSetShell(MprCtx ctx, void *shell);
extern void 	*mprGetShell(MprCtx ctx);
extern void		mprSetClassId(MprCtx ctx, uint classId);
extern uint	 	mprGetClassId(MprCtx ctx);

#if BREW
extern void 	mprSetDisplay(MprCtx ctx, void *display);
extern void 	*mprGetDisplay(MprCtx ctx);
extern void 	mprSetFileMgr(MprCtx ctx, void *fileMgr);
extern void 	*mprGetFileMgr(MprCtx ctx);
#else
extern char 	*mprInetToStr(char *buf, int size, const struct in_addr in);
#endif

/*
 *	Memory allocation
 */
extern MprApp	*mprAllocInit(MprAllocCback cback);
extern void		mprAllocTerm(MprApp *app);
extern void 	mprAllocAbort();

extern void		*mprAllocBlock(MPR_LOC_DEC(ctx, loc), uint size);
extern void		*mprAllocZeroedBlock(MPR_LOC_DEC(ctx, loc), uint size);
extern void 	*mprReallocBlock(MPR_LOC_DEC(ctx, loc), void *ptr, uint size);
extern int 		mprFree(void *ptr);
extern int 		mprStealAllocBlock(MPR_LOC_DEC(ctx, loc), const void *ptr);
extern void 	*mprMemdupInternal(MPR_LOC_DEC(ctx, loc), const void *ptr, 
					uint size);
extern char 	*mprStrndupInternal(MPR_LOC_DEC(ctx, loc), const char *str, 
					uint size);
extern char 	*mprStrdupInternal(MPR_LOC_DEC(ctx, loc), const char *str);

extern void 	*mprSlabAllocBlock(MPR_LOC_DEC(ctx, loc), uint size, uint inc);
extern void 	*mprSlabAllocZeroedBlock(MPR_LOC_DEC(ctx, loc), uint size, 
					uint inc);

extern uint 	mprGetAllocBlockSize(MprCtx ctx);
extern uint 	mprGetAllocBlockCount(MprCtx ctx);
extern uint 	mprGetAllocBlockMemory(MprCtx ctx);
extern void 	*mprGetAllocParent(MprCtx ctx);
extern uint 	mprGetAllocatedMemory(MprCtx ctx);
extern uint 	mprGetPeakAllocatedMemory(MprCtx ctx);
extern uint 	mprGetAllocatedSlabMemory(MprCtx ctx);
extern int 		mprIsAllocBlockValid(MprCtx ctx);
extern int		mprStackCheck(MprCtx ctx);
extern int		mprStackSize(MprCtx ctx);
extern int 		mprGetAllocErrors(MprCtx ctx);
extern void 	mprClearAllocErrors(MprCtx ctx);

extern MprDestructor mprSetDestructor(MprCtx ctx, MprDestructor destructor);
extern MprAllocCback mprSetAllocCallback(MprApp *app, MprAllocCback cback);
extern void 	mprSetAllocLimits(MprApp *app, uint redLine, uint maxMemory);

#if BLD_FEATURE_ALLOC_STATS
extern MprSlabStats 	*mprGetSlabAllocStats(MprApp *app, int slabIndex);
extern MprAllocStats 	*mprGetAllocStats(MprApp *app);
extern void 	mprPrintAllocReport(MprApp *app, bool doBlocks, 
					const char *msg);
#endif

#if BLD_DEBUG
extern int	 	mprPrintAllocBlocks(MprCtx ctx, int indent);
extern const char *mprGetAllocLocation(MprCtx ptr);
#endif

extern int	 	mprValidateBlock(MprCtx ctx);
extern int 		mprValidateAllocTree(MprCtx ptr);
extern void 	mprSetRequiredAlloc(MprCtx ptr, bool recurse);

/*
 *	Sprintf style allocators
 */
extern int	mprAllocSprintf(MPR_LOC_DEC(ctx, loc), char **buf, int maxSize, 
				const char *fmt, ...) PRINTF_ATTRIBUTE(5,6);
extern int	mprAllocVsprintf(MPR_LOC_DEC(ctx, loc), char **buf, int maxSize, 
				const char *fmt, va_list arg) PRINTF_ATTRIBUTE(5,0);
extern int	mprAllocMemcpy(MPR_LOC_DEC(ctx, loc), char **dest, int destMax, 
				const void *src, int nbytes);
extern int	mprAllocStrcat(MPR_LOC_DEC(ctx, loc), char **dest, int max, 
				const char *delim, const char *src, ...);
extern int	mprAllocStrcpy(MPR_LOC_DEC(ctx, loc), char **dest, int max, 
				const char *src);
extern int	mprReallocStrcat(MPR_LOC_DEC(ctx, loc), char **dest, int max, 
				int existingLen, const char *delim, const char *src, ...);

/*
 *	MACROS: These are the convenience macros to automatically supply file 
 *	names and line numbers when debugging.
 */ 
#define mprNew(ctx) new(MPR_LOC_ARGS(ctx))

#define mprAlloc(ctx, size) mprAllocBlock(MPR_LOC_ARGS(ctx), size)

#define mprAllocZeroed(ctx, size) mprAllocZeroedBlock(MPR_LOC_ARGS(ctx), size)

#define	mprSlabAlloc(ctx, size, inc) \
			((type*) mprSlabAllocBlock(MPR_LOC_ARGS(ctx), size, inc))

#define	mprSlabAllocZeroed(ctx, size, inc) \
			((type*) mprSlabAllocBlock(MPR_LOC_ARGS(ctx), size, inc))

#define mprRealloc(ctx, ptr, size) mprReallocBlock(MPR_LOC_ARGS(ctx), ptr, size)

#define mprMemdup(ctx, ptr, size) \
			mprMemdupInternal(MPR_LOC_ARGS(ctx), ptr, size)

#define mprStrdup(ctx, str) mprStrdupInternal(MPR_LOC_ARGS(ctx), str)

#define mprStrndup(ctx, str, size) mprStrndupDebug(MPR_LOC_ARGS(ctx), str, size)

/*
 *	Allocate type macros
 */
#define	mprAllocType(ctx, type) \
			((type*) mprAllocBlock(MPR_LOC_ARGS(ctx), sizeof(type)))

#define	mprAllocTypeZeroed(ctx, type) \
			((type*) mprAllocZeroedBlock(MPR_LOC_ARGS(ctx), sizeof(type)))

#define	mprSlabAllocType(ctx, type, inc) \
			((type*) mprSlabAllocBlock(MPR_LOC_ARGS(ctx), sizeof(type), inc))

#define	mprSlabAllocTypeZeroed(ctx, type, inc) \
			((type*) mprSlabAllocZeroedBlock(MPR_LOC_ARGS(ctx), sizeof(type), \
			inc))

/*
 *	Multithread locking
 */
#if BLD_FEATURE_MULTITHREAD
extern void		mprInitThreads(MprApp *app);
extern void		mprTermThreads(MprApp *app);
extern MprLock	*mprCreateLock(MprCtx ctx);
extern void 	mprDestroyLock(MprLock *lock);
extern void 	mprLock(MprLock *lock);
extern int 		mprTryLock(MprLock *lock);
extern void 	mprUnlock(MprLock *lock);
extern void		mprGlobalLock(MprCtx ctx);
extern void		mprGlobalUnlock(MprCtx ctx);
extern int		mprGetCurrentThreadID();
#else
/*
 *	Disable multithreading 
 */
#define mprInitThreads(ctx, app)
#define mprTermThreads(app)
#define mprCreateLock(ctx)
#define mprDestroyLock(lock)
#define mprLock(lock)
#define mprTryLock(lock)
#define mprUnlock(lock)
#define mprGlobalLock(app)
#define mprGlobalUnlock(app)
#define mprGetCurrentThreadID()
#endif

/*
 *	Time
 */
extern MprTime	*mprGetTime(MprCtx ctx, MprTime *tp);
extern int		mprGetTimeRemaining(MprCtx ctx, MprTime mark, uint timeout);
extern int		mprGetElapsedTime(MprCtx ctx, MprTime mark);
extern int 		mprCompareTime(MprTime *t1, MprTime *t2);
extern uint 	mprSubtractTime(MprTime *t1, MprTime *t2);
extern void 	mprAddElapsedToTime(MprTime *time, uint elapsed);

#if !BREW
extern int		mprAsctime(MprCtx ctx, char *buf, int bufsize, 
					const struct tm *timeptr);
extern int		mprCtime(MprCtx ctx, char *buf, int bufsize, 
					const time_t *timer);
extern struct tm *mprLocaltime(MprCtx ctx, struct tm *timep, time_t *now);
extern struct tm *mprGmtime(MprCtx ctx, time_t* now, struct tm *timep);
extern int		mprRfcTime(MprCtx ctx, char *buf, int bufsize, 
					const struct tm *timep);
#endif /* !BREW */

/*
 *	Host name
 */
extern struct hostent* mprGetHostByName(MprCtx ctx, const char *name);

#if WIN
extern int		mprReadRegistry(MprCtx ctx, char **buf, int max, 
					const char *key, const char *val);
extern int 		mprWriteRegistry(MprCtx ctx, const char *key, const char *name, 
					const char *value);
#endif

#ifdef __cplusplus
}
#endif

#endif /* _h_MPR */


/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim:tw=78
 * vim600: sw=4 ts=4 fdm=marker
 * vim<600: sw=4 ts=4
 */
