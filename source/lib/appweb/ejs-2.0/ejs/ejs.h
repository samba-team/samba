/*
 *	ejs.h - EJScript Language (ECMAScript) header.
 */

/********************************* Copyright **********************************/
/*
 *	@copy	default.g
 *	
 *	Copyright (c) Mbedthis Software LLC, 2003-2006. All Rights Reserved.
 *	Copyright (c) Michael O'Brien, 1994-1995. All Rights Reserved.
 *	Portions Copyright (c) GoAhead Software, 1995-2000. All Rights Reserved.
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
/********************************** Includes **********************************/

#ifndef _h_EJS
#define _h_EJS 1

#include	"mpr.h"
#include	"ejsVar.h"

#ifdef __cplusplus
extern "C" {
#endif

/********************************* Prototypes *********************************/
/*
 *	Constants
 */
#if BLD_FEATURE_SQUEEZE
	#define EJS_GC_WORK_QUOTA		160		/* Allocations required before 
											   garbage colllection */

	#define EJS_PARSE_INCR			256		/* Growth factor */
	#define EJS_MAX_RECURSE			25		/* Sanity for maximum recursion */
	#define EJS_SMALL_OBJ_HASH_SIZE	11		/* Small object hash size */
	#define EJS_LIST_INCR			8		/* Growth increment for lists */
	#define EJS_MAX_BACKTRACE		10		/* Recursion limit for assert */

#else
	#define EJS_GC_WORK_QUOTA		500

	#define EJS_PARSE_INCR			1024
	#define EJS_MAX_RECURSE			100
	#define EJS_SMALL_OBJ_HASH_SIZE	11
	#define EJS_LIST_INCR			16
	#define EJS_MAX_BACKTRACE		25

#endif

/*
 *	Allocation increments for the default interpreter
 */
#define EJS_DEFAULT_VAR_INC			8		/* Var allocation increment */
#define EJS_DEFAULT_PROP_INC		96		/* Property allocation increment */
#define EJS_DEFAULT_OBJ_INC			24		/* Object allocation increment */
#define EJS_DEFAULT_STR_INC			64		/* Object allocation increment */

#define EJS_MIN_TIME_FOR_GC			300		/**< Need 1/3 sec for GC */
#define EJS_GC_MIN_WORK_QUOTA		50		/**< Min to stop thrashing */

/*
 *	Allocation increments for all non-default interpreters
 */
#define EJS_VAR_INC					32
#define EJS_PROP_INC				64
#define EJS_OBJ_INC					64
#define EJS_STR_INC					64

#define EJS_INC_FRAMES				8		/* Frame stack increment */
#define EJS_MAX_FRAMES				64		/* Max frame stack */

/*
 *	Lexical analyser tokens
 */
#define EJS_TOK_ERR					-1		/* Any error */
#define EJS_TOK_LPAREN				1		/* ( */
#define EJS_TOK_RPAREN				2		/* ) */
#define EJS_TOK_IF					3		/* if */
#define EJS_TOK_ELSE				4		/* else */
#define EJS_TOK_LBRACE				5		/* { */
#define EJS_TOK_RBRACE				6		/* } */
#define EJS_TOK_LOGICAL				7		/* ||, &&, ! */
#define EJS_TOK_EXPR				8		/* +, -, /, % */
#define EJS_TOK_SEMI				9		/* ; */
#define EJS_TOK_LITERAL				10		/* literal string */
#define EJS_TOK_METHOD_NAME			11		/* methodName( */
#define EJS_TOK_NEWLINE				12		/* newline white space */
#define EJS_TOK_ID					13		/* Identifier */
#define EJS_TOK_EOF					14		/* End of script */
#define EJS_TOK_COMMA				15		/* Comma */
#define EJS_TOK_VAR					16		/* var */
#define EJS_TOK_ASSIGNMENT			17		/* = */
#define EJS_TOK_FOR					18		/* for */
#define EJS_TOK_INC_DEC				19		/* ++, -- */
#define EJS_TOK_RETURN				20		/* return */
#define EJS_TOK_PERIOD				21		/* . */
#define EJS_TOK_LBRACKET			22		/* [ */
#define EJS_TOK_RBRACKET			23		/* ] */
#define EJS_TOK_NEW					24		/* new */
#define EJS_TOK_DELETE				25		/* delete */
#define EJS_TOK_IN					26		/* in */
#define EJS_TOK_FUNCTION			27		/* function */
#define EJS_TOK_NUMBER				28		/* Number */
#define EJS_TOK_CLASS				29		/* class */
#define EJS_TOK_EXTENDS				30		/* extends */
#define EJS_TOK_PUBLIC				31		/* public */
#define EJS_TOK_PRIVATE				32		/* private */
#define EJS_TOK_PROTECTED			33		/* private */
#define EJS_TOK_TRY					34		/* try */
#define EJS_TOK_CATCH				35		/* catch */
#define EJS_TOK_FINALLY				36		/* finally */
#define EJS_TOK_THROW				37		/* throw */
#define EJS_TOK_COLON				38		/* : */
#define EJS_TOK_GET					39		/* get */
#define EJS_TOK_SET					40		/* set */
#define EJS_TOK_MODULE				41		/* module */
#define EJS_TOK_EACH				42		/* each */

/*
 *	Expression operators
 */
#define EJS_EXPR_LESS				1		/* < */
#define EJS_EXPR_LESSEQ				2		/* <= */
#define EJS_EXPR_GREATER			3		/* > */
#define EJS_EXPR_GREATEREQ			4		/* >= */
#define EJS_EXPR_EQ					5		/* == */
#define EJS_EXPR_NOTEQ				6		/* != */
#define EJS_EXPR_PLUS				7		/* + */
#define EJS_EXPR_MINUS				8		/* - */
#define EJS_EXPR_DIV				9		/* / */
#define EJS_EXPR_MOD				10		/* % */
#define EJS_EXPR_LSHIFT				11		/* << */
#define EJS_EXPR_RSHIFT				12		/* >> */
#define EJS_EXPR_MUL				13		/* * */
#define EJS_EXPR_ASSIGNMENT			14		/* = */
#define EJS_EXPR_INC				15		/* ++ */
#define EJS_EXPR_DEC				16		/* -- */
#define EJS_EXPR_BOOL_COMP			17		/* ! */

/*
 *	Conditional operators
 */
#define EJS_COND_AND				1		/* && */
#define EJS_COND_OR					2		/* || */
#define EJS_COND_NOT				3		/* ! */

/**
 *	EJ Parsing States. Error and Return are be negative.
 */
#define EJS_STATE_ERR				-1		/**< Error state */
#define EJS_STATE_RET				-2		/**< Return statement */
#define EJS_STATE_EOF				-3		/**< End of file */
#define EJS_STATE_COND				2		/* Parsing a conditional stmt */
#define EJS_STATE_COND_DONE			3
#define EJS_STATE_RELEXP			4		/* Parsing a relational expr */
#define EJS_STATE_RELEXP_DONE		5
#define EJS_STATE_EXPR				6		/* Parsing an expression */
#define EJS_STATE_EXPR_DONE			7
#define EJS_STATE_STMT				8		/* Parsing General statement */
#define EJS_STATE_STMT_DONE			9
#define EJS_STATE_STMT_BLOCK_DONE	10		/* End of block "}" */
#define EJS_STATE_ARG_LIST			11		/* Method arg list */
#define EJS_STATE_ARG_LIST_DONE		12
#define EJS_STATE_DEC_LIST			16		/* Declaration list */
#define EJS_STATE_DEC_LIST_DONE		17
#define EJS_STATE_DEC				18		/* Declaration statement */
#define EJS_STATE_DEC_DONE			19

#define EJS_STATE_BEGIN				EJS_STATE_STMT

/*
 *	General parsing flags.
 */
#define EJS_FLAGS_EXE				0x1		/* Execute statements */
#define EJS_FLAGS_LOCAL				0x2		/* Get local vars only */
#define EJS_FLAGS_GLOBAL			0x4		/* Get global vars only */
#define EJS_FLAGS_CREATE			0x8		/* Create var */
#define EJS_FLAGS_ASSIGNMENT		0x10	/* In assignment stmt */
#define EJS_FLAGS_DELETE			0x20	/* Deleting a variable */
#define EJS_FLAGS_NEW				0x80	/* In a new stmt() */
#define EJS_FLAGS_EXIT				0x100	/* Must exit */
#define EJS_FLAGS_LHS				0x200	/* Left-hand-side of assignment */
#define EJS_FLAGS_FORIN				0x400	/* In "for (v in ..." */
#define EJS_FLAGS_CLASS_DEC			0x800	/* "class name [extends] name " */
#define EJS_FLAGS_TRY				0x2000	/* In a try {} block */
#define EJS_FLAGS_CATCH				0x4000	/* "catch (variable)" */
#define EJS_FLAGS_DONT_GC			0x8000	/* Don't garbage collect */
#define EJS_FLAGS_NO_ARGS			0x10000	/* Accessors don't use args */
#define EJS_FLAGS_ENUM_HIDDEN		0x20000	/* Enumerate hidden fields */
#define EJS_FLAGS_ENUM_BASE			0x40000	/* Enumerate base classes */
#define EJS_FLAGS_TRACE_ARGS		0x80000	/* Support for printv */
#define EJS_FLAGS_SHARED_SLAB		0x100000/* Using a shared slab */

/*
 *	Exceptions 
 */
#define EJS_ARG_ERROR		"ArgError"		/**< Method argument error */
#define EJS_ASSERT_ERROR	"AssertError"	/**< Assertion error */
#define EJS_EVAL_ERROR		"EvalError"		/**< General evalation error */
#define EJS_INTERNAL_ERROR	"InternalError"	/**< Internal error */
#define EJS_IO_ERROR		"IOError"		/**< IO or data error */
#define EJS_MEMORY_ERROR	"MemoryError"	/**< Memory allocation error */
#define EJS_RANGE_ERROR		"RangeError"	/**< Data out of range (div by 0) */
#define EJS_REFERENCE_ERROR	"ReferenceError"/**< Object or property reference */
#define EJS_SYNTAX_ERROR	"SyntaxError"	/**< Javascript syntax error */
#define EJS_TYPE_ERROR		"TypeError"		/**< Wrong type supplied */

/*
 *	E4X 
 */
#if BLD_FEATURE_EJS_E4X
#if BLD_FEATURE_SQUEEZE
#define E4X_BUF_SIZE				512		/* Initial buffer size for tokens */
#define E4X_BUF_MAX					(32 * 1024) /* Max size for tokens */
#define E4X_MAX_NODE_DEPTH			24		/* Max nesting of tags */
#else
#define E4X_BUF_SIZE				4096
#define E4X_BUF_MAX					(128 * 1024)
#define E4X_MAX_NODE_DEPTH			128
#endif

#define E4X_MAX_ELT_SIZE			(E4X_BUF_MAX-1)
#define E4X_TEXT_PROPERTY 			"-txt"
#define E4X_TAG_NAME_PROPERTY 		"-tag"
#define E4X_COMMENT_PROPERTY 		"-com"
#define E4X_ATTRIBUTES_PROPERTY 	"-att"
#define E4X_PI_PROPERTY				"-pi"
#define E4X_PARENT_PROPERTY			"-parent"
#endif

#if BLD_FEATURE_MULTITHREAD
/**
 *	Multithreaded lock function
 */
typedef void (*EjsLockFn)(void *lockData);
/**
 *	Multithreaded unlock function
 */
typedef void (*EjsUnlockFn)(void *lockData);
#endif

/*
 *	Token limits
 */
#define EJS_MAX_LINE				128		/* Maximum input line buffer */
#define EJS_MAX_TOKEN				640		/* Max input parse token */
#define EJS_TOKEN_STACK				3		/* Put back token stack */

/*
 *	Putback token 
 */

typedef struct EjsToken {
	char		tokbuf[EJS_MAX_TOKEN];
	int			tid;						/* Token ID */
} EjsToken;

/*
 *	EJ evaluation block structure
 */
typedef struct EjsInput {
	EjsToken	putBack[EJS_TOKEN_STACK]; 	/* Put back token stack */
	int			putBackIndex;				/* Top of stack index */
	char		line[EJS_MAX_LINE];			/* Current line */
	char		*fileName;					/* File or script name */
	int			lineLength;					/* Current line length */
	int			lineNumber;					/* Parse line number */
	int			lineColumn;					/* Column in line */
	struct EjsInput *next;					/* Used for backtraces */
	const char  *procName;					/* Gives name in backtrace */
	const char	*script;					/* Input script for parsing */
	char		*scriptServp;				/* Next token in the script */
	int			scriptSize;					/* Length of script */
	char		tokbuf[EJS_MAX_TOKEN];		/* Current token */
	int			tid;						/* Token ID */
	char		*tokEndp;					/* Pointer past end of token */
	char		*tokServp;					/* Pointer to next token char */
	struct EjsInput	*nextInput;				/* Free list of input structs */
} EjsInput;

/*
 *	Method call structure
 */
typedef struct EjsProc {
	MprArray	*args;						/* Args for method */
	EjsVar		*fn;						/* Method definition */
	char		*procName;					/* Method name */
} EjsProc;


/**
 *	@overview EJScript Service structure
 *	@description The EJScript service manages the overall language runtime. It 
 *		is the factory that creates interpreter instances via ejsCreateInterp.
 *		The EJScript service creates a master interpreter that holds the
 *		standard language classes and properties. When user interpreters are
 *		created, they reference (without copying) the master interpreter to
 *		gain access to the standard classes and types.
 *	@stability Prototype.
 *  @library libejs.
 * 	@see ejsOpenService, ejsCloseService, ejsCreateInterp, ejsDestoryInterp
 */
typedef struct EjsService {
	EjsVar		*globalClass;				/* Global class */
	struct Ejs  *master;					/* Master Interp inherited by all */
#if BLD_FEATURE_MULTITHREAD
	EjsLockFn	lock;
	EjsUnlockFn	unlock;
	void		*lockData;
#endif
} EjsService;


/*
 *	Memory statistics
 */
typedef struct EjsMemStats {
	uint		maxMem;
	uint		usedMem;
} EjsMemStats;


/*
 *	Garbage collection block alignment
 */
#define EJS_ALLOC_ALIGN(ptr) \
	(((ptr) + sizeof(void*) - 1) & ~(sizeof(void*) - 1))

/*
 *	Default GC tune factors
 */
#define EJS_GC_START_THRESHOLD	(32 * 1024)

/*
 *	The Garbage collector is a generational collector. It ages blocks and 
 *	optimizes the mark / sweep algorithm to focus on new and recent blocks
 */
typedef enum EjsGeneration {
	EJS_GEN_NEW 			= 0,
	EJS_GEN_RECENT_1 		= 1,
	EJS_GEN_RECENT_2 		= 2,
	EJS_GEN_OLD 			= 3,
	EJS_GEN_PERMANENT 		= 4,
	EJS_GEN_MAX 			= 5,
} EjsGeneration;

/*
 *	Garbage collector control
 */
typedef struct EjsGC {
	bool		enable;
	bool		enableDemandCollect;
	bool		enableIdleCollect;
	/*
 	 *	maxMemory should be set to be 95% of the real max memory limit
	 */
	uint		maxMemory;			/* Above this, Throw Memory exception. */
	int			workQuota;			/* Quota of work before GC */
	int			workDone;			/* Count of allocations */
	int			degraded;			/* Have exceeded maxMemory */

	/*
	 *	Debug Levels 0-N (increases verbosity)
	 *		1 -- Sweep and collection count
	 *		2 -- Trace objects deleted
 	 *		3 -- Trace objects marked
 	 *		4 -- Print alloc report when needing a demand allocation
	 *
	 */
	int			debugLevel;			/* In debug mode */
	int			collecting;			/* Running garbage collection */
	uint		collectionCount;	/* Number of times GC ran */
#if BLD_DEBUG
	int			gcIndent;			/* Indent formatting */
	int			objectsInUse;		/* Objects currently reachable */
	int			propertiesInUse;	/* Properties currently reachable */
#endif
} EjsGC;

/*
 *	Slab memory allocation 
 */
typedef struct EjsSlab {
	uint		allocIncrement;		/* Growth increment in slab */
	uint		size;				/* Size of allocations */
	EjsGCLink	freeList;			/* Free list (only next ptr is used) */
	EjsObj		*lastRecentBlock;	/* Saved for GC age generations phase */
	EjsGCLink	allocList[EJS_GEN_MAX];	/* Allocated block list */

#if BLD_FEATURE_ALLOC_STATS
	uint		totalAlloc;			/* Total count of allocation calls */
	uint		freeCount;			/* Number of blocks on the slab freelist */
	uint		allocCount;			/* Number of allocated blocks */
	uint		peakAllocated;		/* Peak allocated */ 
	uint		peakFree;			/* Peak on the free list */ 
	uint		totalReclaimed;		/* Total blocks reclaimed on sweeps */
	uint		totalSweeps;		/* Total sweeps */
#endif
} EjsSlab;


/**
 *	@overview EJ interpreter control structure.
 *	@description EJ allocates one control structure per active interpreter.
 *		The \ref ejsCreateInterp routine creates the Ejs structure and returns
 *		a reference to be used in subsequent EJ API calls.
 *  @stability Prototype.
 *  @library libejs.
 * 	@see ejsCreateInterp, ejsDestroyInterp, ejsOpenService
 */
struct Ejs {
	void		*altHandle;					/* Alternate callback handle */
	bool		castAlloc;					/* True if castTemp is allocated */
	char		*castTemp;					/* Temporary string for casting */
	char		*currentClass;				/* Current class name */
	EjsVar		*currentObj;				/* Ptr to current object */
	EjsVar		*thisObject;				/* Ptr to current "this" */
	EjsProperty	*currentProperty;			/* Ptr to current property */
	EjsGC		gc;							/* Garbage collector control */
	char		*errorMsg;					/* Error message */
	char		*fileName;					/* File or script name */
	int			lineNumber;					/* File line number */
	int			scriptStatus;				/* Status to exit() */
	int			flags;						/* Flags */
	MprArray	*frames;					/* List of variable frames */
	EjsVar		*global;					/* Global object */
	EjsVar		*objectClass;				/* Object class */
	int			gotException;				/* Exception thrown */
	EjsInput	*input;						/* Input evaluation block */
	int			depth;						/* Recursion depth */
	EjsVar		*local;						/* Local object */
	int			maxDepth;					/* Maximum depth for formatting */
	void		*primaryHandle;				/* primary callback handle */
	EjsProc		*proc;						/* Current method */
	int			recurseCount;				/* Recursion counter */
	EjsVar		*result;					/* Variable result */
	int			tid;						/* Current token id */
	char		*token;						/* Pointer to token string */
	EjsVar		tokenNumber;				/* Parsed number */
	EjsService	*service;					/* Service object */
	void		*userData;					/* Method user data */

	EjsSlab		*slabs;						/* Memory allocation slabs */
	MprCtx		slabAllocContext;			/* Allocation context */
	EjsInput	*inputList;					/* Free list of input structs */

#if BLD_FEATURE_MULTITHREAD
	EjsLockFn	lock;						/* Lock method */
	EjsUnlockFn	unlock;						/* Unlock method */
	void		*lockData;					/* Lock data argument */
#endif
#define EJS_MAX_STACK	(10 * 1024)
	char		stack[EJS_MAX_STACK];		/* Local variable stack */
	char		*stkPtr;					/* Local variable stack ptr */
	void		*inputMarker;				/* Recurse protection */
};


typedef struct EjsModule
{
	int			dummy;
} EjsModule;


/*
 *	Method callback when using Alternate handles. GaCompat uses these and
 *	passes the web server request structure via the altHandle. 
 */
typedef void *EjsHandle;
typedef int (*EjsAltCMethod)(Ejs *ejs, EjsHandle altHandle,
		EjsVar *thisObj, int argc, EjsVar **argv);
typedef int (*EjsAltStringCMethod)(Ejs *ejs, EjsHandle altHandle,
		EjsVar *thisObj, int argc, char **argv);


/*
 *	API Constants
 */
#define EJS_USE_OWN_SLAB	1

/******************************** Internal API ********************************/
/*
 *	Ejs Lex
 */
extern int	 	 ejsLexOpenScript(Ejs *ejs, const char *script);
extern void 	 ejsLexCloseScript(Ejs *ejs);
extern int 		 ejsInitInputState(EjsInput *ip);
extern void 	 ejsLexSaveInputState(Ejs *ejs, EjsInput* state);
extern void 	 ejsLexFreeInputState(Ejs *ejs, EjsInput* state);
extern void 	 ejsLexRestoreInputState(Ejs *ejs, EjsInput* state);
extern int		 ejsLexGetToken(Ejs *ejs, int state);
extern void		 ejsLexPutbackToken(Ejs *ejs, int tid, char *string);

/*
 *	Parsing
 */
extern int		 ejsParse(Ejs *ejs, int state, int flags);
extern int	 	 ejsGetFlags(Ejs *ejs);

/*
 *	Create variable scope blocks
 */
extern int		 ejsOpenBlock(Ejs *ejs);
extern int		 ejsSetBlock(Ejs *ejs, EjsVar *local);
extern int		 ejsCloseBlock(Ejs *ejs, int vid);
extern int		 ejsEvalBlock(Ejs *ejs, char *script, EjsVar *vp);
extern void		 ejsSetFileName(Ejs *ejs, const char *fileName);

/*
 *	Class definitions
 */
extern EjsVar 	*ejsCreateSimpleClass(Ejs *ejs, EjsVar *baseClass, 
					const char *className);
extern int		 ejsDefineObjectClass(Ejs *ejs);
extern int	 	 ejsDefineArrayClass(Ejs *ejs);
extern int 		 ejsDefineBooleanClass(Ejs *ejs);
extern int 		 ejsDefineErrorClasses(Ejs *ejs);
extern int 		 ejsDefineFileClass(Ejs *ejs);
extern int 		 ejsDefineFileSystemClass(Ejs *ejs);
extern int 		 ejsDefineHTTPClass(Ejs *ejs);
extern int 		 ejsDefineFunctionClass(Ejs *ejs);
extern int 		 ejsDefineNumberClass(Ejs *ejs);
extern int 		 ejsDefineStringClass(Ejs *ejs);
extern int 		 ejsDefineDateClass(Ejs *ejs);
extern int 		 ejsDefineStandardClasses(Ejs *ejs);

#if BLD_FEATURE_EJS_E4X
extern int		 ejsDefineXmlClasses(Ejs *ejs);
extern EjsVar 	*ejsCreateXml(Ejs *ejs);
#endif

#if BLD_FEATURE_EJS_DB
extern int		ejsDefineDbClasses(Ejs *ejs);
#endif

/*
 *	System class definitions
 */
extern int 		 ejsDefineSystemClasses(Ejs *ejs);
extern int 		 ejsDefineSystemClass(Ejs *ejs);
extern int 		 ejsDefineAppClass(Ejs *ejs);
extern int 		 ejsDefineDebugClass(Ejs *ejs);
extern int 		 ejsDefineLogClass(Ejs *ejs);
extern int 		 ejsDefineMemoryClass(Ejs *ejs);
extern int 		 ejsDefineGCClass(Ejs *ejs);
extern int 		 ejsDefineGlobalProperties(Ejs *ejs);

extern int 		 ejsTermSystemClasses(Ejs *ejs);
extern void 	 ejsTermHTTPClass(Ejs *ejs);

extern int 		 ejsCreateObjectModel(Ejs *ejs);

/*
 *	Class constructors
 */
extern int 		 ejsArrayConstructor(Ejs *ejs, EjsVar *thisObj, int argc, 
					EjsVar **argv);
extern int 		 ejsXmlConstructor(Ejs *ejs, EjsVar *thisObj, int argc, 
					EjsVar **argv);
extern int 		 ejsXmlListConstructor(Ejs *ejs, EjsVar *thisObj, int argc, 
					EjsVar **argv);
extern int 		 ejsBooleanConstructor(Ejs *ejs, EjsVar *thisObj, int argc, 
					EjsVar **agv);
extern int 		 ejsFunctionConstructor(Ejs *ejs, EjsVar *thisObj, int argc, 
					EjsVar **agv);
extern int 		 ejsNumberConstructor(Ejs *ejs, EjsVar *thisObj, int argc, 
					EjsVar **argv);
extern int 		 ejsStringConstructor(Ejs *ejs, EjsVar *thisObj, int argc, 
					EjsVar **argv);
extern int 		 ejsDateConstructor(Ejs *ejs, EjsVar *thisObj, 
					int argc, EjsVar **argv);

/*
 *	Garbage collection
 */
extern void 	 ejsGCInit(Ejs *ejs, int objInc, int propInc, int varInc, 
					int strInc);
extern int 		 ejsIsTimeForGC(Ejs *ep, int timeTillNextEvent);

extern bool 	 ejsSetGCDebugLevel(Ejs *ep, int debugLevel);
extern void 	 ejsSweepAll(Ejs *ep);

extern EjsObj 	*ejsAllocObj(EJS_LOC_DEC(ejs, loc));
extern EjsProperty *ejsAllocProperty(EJS_LOC_DEC(ejs, loc));
extern EjsVar 	*ejsAllocVar(EJS_LOC_DEC(ejs, loc));
extern void 	 ejsFree(Ejs *ejs, void *ptr, int slabIndex);

extern int 		ejsCollectGarbage(Ejs *ejs, int slabIndex);
extern int 		ejsIncrementalCollectGarbage(Ejs *ejs);

#if BLD_DEBUG
extern void 	ejsDumpObjects(Ejs *ejs);
#endif

#if BLD_FEATURE_ALLOC_STATS
extern void 	 ejsPrintAllocReport(Ejs *ejs, bool printLeakReport);
#endif

extern void		ejsCleanInterp(Ejs *ejs, bool doStats);
extern void 	ejsSetInternalMethods(Ejs *ejs, EjsVar *op);
extern void 	ejsSetPrimaryHandle(Ejs *ep, void *primaryHandle);
extern void 	ejsSetAlternateHandle(Ejs *ep, void *alternateHandle);
extern void 	*ejsGetUserData(Ejs *ejs);

/*
 *	Could possibly make these routines public
  */

extern int 		ejsSetGCMaxMemory(Ejs *ep, uint maxMemory);
extern uint 	ejsGetUsedMemory(Ejs *ejs);
extern uint 	ejsGetAllocatedMemory(Ejs *ejs);
extern uint 	ejsGetAvailableMemory(Ejs *ejs);
extern char 	*ejsFormatStack(Ejs* ep);;

/********************************* Prototypes *********************************/
#if BLD_FEATURE_MULTITHREAD
extern int 		ejsSetServiceLocks(EjsService *sp, EjsLockFn lock, 
					EjsUnlockFn unlock, void *data);
#endif

/*
 *	Ejs service and interpreter management
 */
extern EjsService *ejsOpenService(MprCtx ctx);
extern void 	ejsCloseService(EjsService *sp, bool doStats);

extern Ejs 		*ejsCreateInterp(EjsService *sp, void *primaryHandle, 
					void *altHandle, EjsVar *global, bool useOwnSlab);
extern void		ejsDestroyInterp(Ejs *ejs, bool doStats);

extern Ejs		*ejsGetMasterInterp(EjsService *sp);
extern EjsVar	*ejsGetGlobalClass(Ejs *ejs);

/*
 *	Module support
 */
extern EjsModule *ejsCreateModule(const char *name, const char *version, 
	int (*start)(EjsModule*), int (*stop)(EjsModule*));

/*
 *	Native Objects
 */

void ejsSetNativeData(EjsVar *obj, void *data);
void ejsSetNativeHelpers(Ejs *ejs, EjsVar *nativeClass,
		int	 (*createInstance)(Ejs *ejs, EjsVar *thisObj, int argc, 
			EjsVar **argv), 
		void (*disposeInstance)(Ejs *ejs, EjsVar *thisObj),
		bool (*hasProperty)(Ejs *ejs, EjsVar *thisObj, const char *prop),
		int  (*deleteProperty)(Ejs *ejs, EjsVar *thisObj, const char *prop),
		int	 (*getProperty)(Ejs *ejs, EjsVar *thisObj, const char *prop,
					EjsVar *dest),
		int	 (*setProperty)(Ejs *ejs, EjsVar *thisObj, const char *prop, 
				EjsVar *value),
		int  (*doOperator)(Ejs *ejs, EjsVar *thisObj, EjsOp *op, EjsVar
				*result, EjsVar *lhs, EjsVar *rhs, int *code)
	);

/*
 *	Evaluation methods
 */
extern int		ejsEvalFile(Ejs *ejs, const char *path, EjsVar *result);
extern int		ejsEvalScript(Ejs *ejs, const char *script, EjsVar *result);
extern int 		ejsRunMethod(Ejs *ejs, EjsVar *obj, 
					const char *methodName, MprArray *args);
extern int 		ejsRunMethodCmd(Ejs *ejs, EjsVar *obj, 
					const char *methodName, const char *cmdFmt, ...);
extern EjsVar	*ejsGetReturnValue(Ejs *ejs);

extern EjsVar	*ejsGetLocalObj(Ejs *ejs);
extern EjsVar	*ejsGetGlobalObj(Ejs *ejs);

/*
 *	Define a class in the specified interpreter. If used with the default 
 *	interpeter, then the class is defined for all interpreters.
 */
extern EjsVar	*ejsDefineClass(Ejs *ejs, const char *className, 
					const char *extends, EjsCMethod constructor);
extern EjsVar	*ejsGetClass(Ejs *ejs, EjsVar *parentClass, 
					const char *className);

extern const char *ejsGetClassName(EjsVar *obj);
extern const char *ejsGetBaseClassName(EjsVar *obj);

extern bool 	ejsIsSubClass(EjsVar *target, EjsVar *baseClass);
extern EjsVar	*ejsGetBaseClass(EjsVar *obj);
extern void		ejsSetBaseClass(EjsVar *obj, EjsVar *baseClass);


#define ejsCreateSimpleObj(ejs, className) \
				ejsCreateSimpleObjInternal(EJS_LOC_ARGS(ejs), className)
extern EjsVar	*ejsCreateSimpleObjInternal(EJS_LOC_DEC(ejs, loc), 
					const char *className);

#define ejsCreateSimpleObjUsingClass(ejs, baseClass) \
				ejsCreateSimpleObjUsingClassInt(EJS_LOC_ARGS(ejs), \
					baseClass)
extern EjsVar	*ejsCreateSimpleObjUsingClassInt(EJS_LOC_DEC(ejs, loc), 
					EjsVar *baseClass);

/*
 *	This will create an object and call all required constructors
 */
extern EjsVar 	*ejsCreateObj(Ejs *ejs, EjsVar *obj, 
						const char *className, const char *constructorArgs);

#define ejsCreateObjUsingArgv(ejs, obj, className, args) \
				ejsCreateObjUsingArgvInternal(EJS_LOC_ARGS(ejs), obj, \
					className, args)
extern EjsVar	*ejsCreateObjUsingArgvInternal(EJS_LOC_DEC(ejs, loc), 
					EjsVar *obj, const char *className, MprArray *args);

#define ejsCreateArray(ejs, size) \
				ejsCreateArrayInternal(EJS_LOC_ARGS(ejs), size)
extern EjsVar	*ejsCreateArrayInternal(EJS_LOC_DEC(ejs, loc), 
					int size);

/*
 *	Array methods. MOB -- need other array methods
 */
/* MOB -- spell out  element */
extern EjsVar 	*ejsAddArrayElt(Ejs *ejs, EjsVar *op, EjsVar *element, 
					EjsCopyDepth copyDepth);
/*
 *	Required: Array methods
 *
	array = obj.getMethods();
	array = obj.getProperties();

	array.property.isPublic();
	array.property.isPrivate();
	array.property.isMethod();
	array.property.isEnumerable();
	array.property.isReadOnly();
	array.property.allowsNonUnique();
	array.property.getParent();
*/

/* MOB -- should we have an API that takes a EjsCopyDepth */
extern void		ejsSetReturnValue(Ejs *ejs, EjsVar *vp);
extern void		ejsSetReturnValueAndFree(Ejs *ejs, EjsVar *vp);
extern void		ejsSetReturnValueToBoolean(Ejs *ejs, bool value);
extern void		ejsSetReturnValueToBinaryString(Ejs *ejs, 
					const uchar *value, int len);
extern void		ejsSetReturnValueToInteger(Ejs *ejs, int value);
extern void		ejsSetReturnValueToNumber(Ejs *ejs, EjsNum value);
extern void		ejsSetReturnValueToString(Ejs *ejs, const char *value);
extern void		ejsSetReturnValueToUndefined(Ejs *ejs);

/*
 *	Variable access and control. The fullName arg can contain "[]" and "."
 */
extern bool		ejsGetBool(Ejs *ejs, const char *fullName, bool defaultValue);
extern int 		ejsGetInt(Ejs *ejs, const char *fullName, int defaultValue);
extern const char *ejsGetStr(Ejs *ejs, const char *fullName, 
					const char *defaultValue);
extern EjsVar	*ejsGetVar(Ejs *ejs, const char *fullName);

extern int 		ejsSetBool(Ejs *ejs, const char *fullName, bool value);
extern int 		ejsSetInt(Ejs *ejs, const char *fullName, int value);
extern int 		ejsSetStr(Ejs *ejs, const char *fullName, const char *value);
extern int 		ejsSetVar(Ejs *ejs, const char *fullName, const EjsVar *value);
extern int 		ejsSetVarAndFree(Ejs *ejs, const char *fullName, EjsVar *value);

extern int 		ejsDeleteVar(Ejs *ejs, const char *fullName);

/*
 *	Error handling
 */
extern void		ejsError(Ejs *ejs, const char *errorType, const char *fmt, 
					...) PRINTF_ATTRIBUTE(3,4);
/* MOB -- this should take no arguments */
extern void		ejsArgError(Ejs *ejs, const char *msg);
extern void		ejsInternalError(Ejs *ejs, const char *msg);
extern void		ejsMemoryError(Ejs *ejs);
extern void		ejsSyntaxError(Ejs *ejs, const char *msg);

/*
 * 	Utility methods
 */
extern int 		ejsParseArgs(int argc, char **argv, const char *fmt, ...);

extern void 	ejsExit(Ejs *ejs, int status);
extern bool		ejsIsExiting(Ejs *ejs);
extern void		ejsClearExiting(Ejs *ejs);

extern bool		ejsGotException(Ejs *ejs);

/* MOB -- rename Method to Function */
extern void 	ejsFreeMethodArgs(Ejs *ep, MprArray *args);
extern int	 	ejsStrcat(Ejs *ep, EjsVar *dest, EjsVar *src);

/*
 *	Debugging routines
 */
extern char 	*ejsGetErrorMsg(Ejs *ejs);
extern int		ejsGetLineNumber(Ejs *ejs);
extern void		ejsTrace(Ejs *ejs, const char *fmt, ...);

/*
 *	Multithreaded lock routines
 */
#if BLD_FEATURE_MULTITHREAD
#define ejsLock(sp)	if (sp->lock) { (sp->lock)(sp->lockData); } else
#define ejsUnlock(sp)	if (sp->unlock) { (sp->unlock)(sp->lockData); } else
#else
#define ejsLock(sp)		
#define ejsUnlock(sp)	
#endif

#ifdef __cplusplus
}
#endif
#endif /* _h_EJS */

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
