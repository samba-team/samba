/*
 *	@file 	ejs.c
 *	@brief 	Embedded JavaScript (EJS) 
 *	@overview Main module interface logic.
 *	@remarks The initialization code must be run single-threaded. Includes:
 *		ejsOpen, ejsClose.
 */
/********************************* Copyright **********************************/
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
/********************************** Includes **********************************/

#include	"ejs.h"

#if BLD_FEATURE_EJS

/************************************* Code ***********************************/
/*
 *	Initialize the EJS subsystem
 */

EjsService *ejsOpenService(MprCtx ctx)
{
	EjsService	*service;
	Ejs			*interp;

	service = mprAllocTypeZeroed(ctx, EjsService);
	if (service == 0) {
		mprError(ctx, MPR_LOC, "Can't allocate service memory");
		return 0;
	}

	interp = ejsCreateInterp(service, 0, 0, 0, 1);
	if (interp == 0) {
		mprError(ctx, MPR_LOC, "Can't create master interpreter");
		mprFree(service);
		return 0;
	}
	service->master = interp;

	/*
	 *	Restore the default GC settings for the master interpreter.
	 *	ejsCreateInterp will have initialized them.
	 */
	ejsGCInit(interp, EJS_DEFAULT_OBJ_INC, EJS_DEFAULT_PROP_INC,
		EJS_DEFAULT_VAR_INC, EJS_DEFAULT_STR_INC);

	/*
	 *	Save the default interpreter and global class for all to access
	 *	MOB -- don't store these. Store the service
 	 */
	mprSetKeyValue(interp, "ejsMaster", interp);
	mprSetKeyValue(interp, "ejsGlobalClass", interp->global);

	/*
	 *	Once the Object class is created, this routine will also make the
	 *	Global class a subclass of Object.
	 */
	if (ejsDefineObjectClass(interp) < 0) {
		mprError(ctx, MPR_LOC, "Can't define EJS object class");
		mprFree(service);
		return 0;
	}

	/*
	 *	Create all the standard classes
	 */
	if (ejsDefineStandardClasses(interp) < 0) {
		mprError(ctx, MPR_LOC, "Can't define EJS standard classes");
		mprFree(service);
		return 0;
	}

	if (ejsDefineSystemClasses(interp) < 0) {
		mprError(ctx, MPR_LOC, "Can't define EJS system classes");
		mprFree(service);
		return 0;
	}

	if (ejsCreateObjectModel(interp) < 0) {
		mprError(ctx, MPR_LOC, "Can't create EJS object model");
		mprFree(service);
		return 0;
	}

#if UNUSED && BLD_FEATURE_ALLOC_STATS
{
	EjsVar	v;
	mprLog(ctx, 0, "Obj %d, Var %d, Prop %d\n", sizeof(EjsObj), sizeof(EjsVar),
		sizeof(EjsProperty));
	mprLog(ctx, 0, "GCLink %d\n", sizeof(EjsGCLink));
	mprLog(ctx, 0, "objectState %d\n", (uint) &v.objectState - (uint) &v);
}
#endif

	return service;
}

/******************************************************************************/
/*
 *	Close down the EJS Service
 */

void ejsCloseService(EjsService *sp, bool doStats)
{
	Ejs		*ep;

	mprAssert(sp);

	ep = sp->master;
	mprAssert(ep);

	ejsTermSystemClasses(ep);

	if (ep) {
		ejsFreeVar(ep, sp->globalClass);

#if BLD_FEATURE_ALLOC_STATS
		if (doStats) {
			mprLog(sp, 0, "GC Statistics for the Global Interpreter");
		}
#endif
		ejsDestroyInterp(ep, doStats);
	}

	mprRemoveKeyValue(sp, "ejsMaster");
	mprRemoveKeyValue(sp, "ejsGlobalClass");

	mprFree(sp);
}

/******************************************************************************/

Ejs *ejsGetMasterInterp(EjsService *sp)
{
	return sp->master;
}

/******************************************************************************/
#if BLD_FEATURE_MULTITHREAD

int ejsSetServiceLocks(EjsService *sp, EjsLockFn lock, EjsUnlockFn unlock, 
		void *data)
{
	mprAssert(sp);

	sp->lock = lock;
	sp->unlock = unlock;
	sp->lockData = data;
	return 0;
}

#endif
/******************************************************************************/
/*
 *	Create and initialize an EJS interpreter. Interpreters have a global object
 *	that has the service global class set as a base class. This way, it 
 *	inherits all the desired global properties, methods and classes.
 *
 *	The primary and alternate handles are provided to C methods depending on 
 *	the flags provided when the C methods are defined. The global variable 
 *	(optionally) defines a predefined global variable space.
 */

Ejs *ejsCreateInterp(EjsService *sp, void *primaryHandle, void *altHandle,
	EjsVar *global, bool useOwnSlab)
{
	EjsProperty	*pp;
	EjsVar		*baseClass;
	Ejs			*ep;

	ep = mprAllocTypeZeroed(sp, Ejs);
	if (ep == 0) {
		mprAssert(0);
		return ep;
	}

	ep->stkPtr = &ep->stack[EJS_MAX_STACK];

	ep->service = sp;
	ep->primaryHandle = primaryHandle;
	ep->altHandle = altHandle;

	if (sp->master) {
		ep->objectClass = sp->master->objectClass;
	}

	if (useOwnSlab) {
		ep->slabs = (EjsSlab*) mprAllocZeroed(ep, sizeof(EjsSlab) * 
			EJS_SLAB_MAX);
		 ep->slabAllocContext = ep;

	} else {
		ep->slabs = sp->master->slabs;
		ep->slabAllocContext = sp->master;
		ep->flags |= EJS_FLAGS_SHARED_SLAB;
	}

	ep->frames = mprCreateItemArray(ep, EJS_INC_FRAMES, EJS_MAX_FRAMES);
	if (ep->frames == 0) {
		mprFree(ep);
		return 0;
	}

	ejsGCInit(ep, EJS_OBJ_INC, EJS_PROP_INC, EJS_VAR_INC, EJS_STR_INC);

	if (sp->globalClass == 0) {
		/*
		 *	Only do this for the Global interpreter. Create a global class 
		 *	(prototype) object. This is base class from which all global 
		 *	spaces will inherit. 
		 */
		sp->globalClass = ejsCreateObjVar(ep);
		if (sp->globalClass == 0) {
			mprFree(ep);
			return 0;
		}
		ejsSetClassName(ep, sp->globalClass, "Global");
		global = sp->globalClass;
	}
	
	if (global) {
		/*
		 *	The default interpreter uses the Global class as its global
		 *	space.
		 */
		ep->global = ejsDupVar(ep, global, EJS_SHALLOW_COPY);
		if (ep->global == 0) {
			mprFree(ep);
			return 0;
		}
		if (ep->global->objectState != sp->globalClass->objectState) {
			ejsSetBaseClass(ep->global, sp->globalClass);
		}

	} else {
		/*
		 *	Use the global class as our global so we can find the object class
		 */
		baseClass = ejsGetClass(ep, sp->globalClass, "Object");
		if (baseClass) {
			ep->global = ejsCreateSimpleObjUsingClass(ep, baseClass);
			if (ep->global == 0) {
				mprFree(ep);
				return 0;
			}

			/*
			 *	Override the base class and set to the master Global class
			 */
			ejsSetBaseClass(ep->global, sp->globalClass);

		} else {
			ep->global = ejsCreateObjVar(ep);
		}
	}

	/*
	 *	The "global" variable points to the global space
	 */
	pp = ejsSetProperty(ep, ep->global, "global", ep->global);
	if (pp == 0) {
		mprFree(ep);
		return 0;
	}
	ejsMakePropertyEnumerable(pp, 0);

	/*
	 *	The "Global" variable points to the Global class
	 */
	pp = ejsSetProperty(ep, ep->global, "Global", sp->globalClass);
	if (pp == 0) {
		mprFree(ep);
		return 0;
	}
	ejsMakePropertyEnumerable(pp, 0);

	ep->local = ejsDupVar(ep, ep->global, EJS_SHALLOW_COPY);
	if (ep->frames == 0 || ep->global == 0 || ep->local == 0) {
		mprFree(ep);
		return 0;
	}
	ejsSetVarName(ep, ep->local, "topLevelLocal");

	if (mprAddItem(ep->frames, ep->global) < 0 ||
			mprAddItem(ep->frames, ep->local) < 0) {
		mprFree(ep);
		return 0;
	}

	ep->result = ejsCreateUndefinedVar(ep);
	if (ep->result == 0) {
		mprFree(ep);
		return 0;
	}

	return ep;
}

/******************************************************************************/
/*
 *	Close an EJS interpreter
 */

void ejsDestroyInterp(Ejs *ep, bool doStats)
{
	ejsCleanInterp(ep, doStats);

	mprFree(ep);
}

/******************************************************************************/
/*
 *	Clean an EJS interpreter of all allocated variables, but DONT destroy.
 *	We use this rather than DestroyInterp so we delay freeing the Ejs struct
 *	until after the service is closed.
 */

void ejsCleanInterp(Ejs *ep, bool doStats)
{
	int		i;

	if (ep->global) {
		ejsDeleteProperty(ep, ep->local, "global");
		ejsDeleteProperty(ep, ep->global, "global");
		ep->global = 0;
	}
	if (ep->local) {
		ejsFreeVar(ep, ep->local);
		ep->local = 0;
	}
	if (ep->global) {
		ejsFreeVar(ep, ep->global);
		ep->global = 0;
	}
	if (ep->result) {
		ejsFreeVar(ep, ep->result);
		ep->result = 0;
	}
	if (ep->castAlloc && ep->castTemp) {
		mprFree(ep->castTemp);
		ep->castTemp = 0;
	}
	if (ep->frames) {
		for (i = ep->frames->length - 1; i >= 0; i--) {
			mprRemoveItemByIndex(ep->frames, i);
		}
		mprFree(ep->frames);
		ep->frames = 0;
	}

	if (doStats) {

#if BLD_FEATURE_ALLOC_STATS
		mprLog(ep, 0, " ");
		mprLog(ep, 0, "GC Statistics for Interpreter (0x%X)", (uint) ep);
#endif

		/*
		 *	Cleanup before printing the alloc report
		 */
		ejsSetGCDebugLevel(ep, 3);
		ejsCollectGarbage(ep, -1);

#if BLD_DEBUG
		/*
		 *	If we are the master, dump objects
		 */
		if (ep->service->master == ep) {
			ejsDumpObjects(ep);
		}
#endif

#if BLD_FEATURE_ALLOC_STATS
		/*
		 *	Print an alloc report. 1 == do leak report
		 */
		ejsPrintAllocReport(ep, 1);
#endif

	} else {
		/*
		 *	Must collect garbage here incase sharing interpreters with the
		 *	master. If we don't, the mprFree later in DestroyInterp will free
		 *	all memory and when the master does GC --> crash.
		 */
		ejsCollectGarbage(ep, -1);
	}
}

/******************************************************************************/
/*
 *	Evaluate an EJS script file. This will evaluate the script at the current
 *	context. Ie. if inside a function, declarations will be local.
 */

int ejsEvalFile(Ejs *ep, const char *path, EjsVar *result)
{
	MprFile			*file;
	MprFileInfo		info;
	char			*script;
	char			*saveFileName;
	int				rc;

	mprAssert(path && *path);

	if ((file = mprOpen(ep, path, O_RDONLY | O_BINARY, 0666)) == 0) {
		ejsError(ep, EJS_IO_ERROR, "Can't open %s", path);
		return -1;
	}
	
	if (mprGetFileInfo(ep, path, &info) < 0) {
		ejsError(ep, EJS_IO_ERROR, "Can't get file info for %s", path);
		goto error;
	}
	
	if ((script = (char*) mprAlloc(ep, info.size + 1)) == NULL) {
		ejsError(ep, "MemoryError", "Cant malloc %d", (int) info.size);
		goto error;
	}
	
	if (mprRead(file, script, info.size) != (int) info.size) {
		mprFree(script);
		ejsError(ep, EJS_IO_ERROR, "Error reading %s", path);
		goto error;
	}
	mprClose(file);
	script[info.size] = '\0';

	saveFileName = ep->fileName;
	ep->fileName = mprStrdup(ep, path);

	rc = ejsEvalScript(ep, script, result);
	mprFree(script);

	mprFree(ep->fileName);
	ep->fileName = saveFileName;

	return rc;

/*
 *	Error return
 */
error:
	mprClose(file);
	return -1;
}

/******************************************************************************/
/*
 *	Create a new variable scope block. This pushes the old local frame down
 *	the stack and creates a new local variables frame.
 */

int ejsOpenBlock(Ejs *ep)
{
	EjsProperty		*pp;
	int				fid;

	ep->local = ejsCreateSimpleObj(ep, "Object");
	ejsSetVarName(ep, ep->local, "local");

	if (ep->local == 0) {
		ejsMemoryError(ep);
		return -1;
	}

	if (ep->frames->length > EJS_MAX_FRAMES && !ep->gotException) {
		ejsError(ep, EJS_RANGE_ERROR, "Recursion too deep: Max depth %d", 
			EJS_MAX_FRAMES);
		return -1;
	}

	/*
	 *	Must add to frames before ejsSetProperty which will make the object live
	 */
	fid = mprAddItem(ep->frames, ep->local);
	if (fid < 0) {
		ejsMemoryError(ep);
		return -1;
	}

	/* Self reference */
	pp = ejsSetProperty(ep, ep->local, "local", ep->local);
	ejsMakePropertyEnumerable(pp, 0);

	return fid;
}

/******************************************************************************/
/*
 *	Set a new variable scope block. This pushes the old local frame down
 *	the stack and creates a new local variables frame.
 */

int ejsSetBlock(Ejs *ep, EjsVar *local)
{
	ep->local = ejsDupVar(ep, local, EJS_SHALLOW_COPY);
	ejsMakeObjPermanent(ep->local, 1);
	return mprAddItem(ep->frames, ep->local);
}

/******************************************************************************/
/*
 *	Close a variable scope block opened via ejsOpenBlock. Pop back the old
 *	local variables frame.
 */

int ejsCloseBlock(Ejs *ep, int fid)
{
	mprAssert(ep->local >= 0);
	mprAssert(fid >= 0);

	mprAssert(ep->local == (EjsVar*) mprGetItem(ep->frames, fid));

	if (ep->local) {
		/* Allow GC */
		ejsMakeObjPermanent(ep->local, 0);
		ejsFreeVar(ep, ep->local);
	}

	mprRemoveItemByIndex(ep->frames, fid);

	ep->local = (EjsVar*) mprGetItem(ep->frames, 
		mprGetItemCount(ep->frames) - 1);

	return 0;
}

/******************************************************************************/
/*
 *	Create a new variable scope block and evaluate a script. All frames
 *	created during this context will be automatically deleted when complete.
 *	vp is optional. i.e. created local variables will be discarded
 *	when this routine returns.
 */

int ejsEvalBlock(Ejs *ep, char *script, EjsVar *vp)
{
	int			rc, fid;

	mprAssert(script);

	fid = ejsOpenBlock(ep);
	if (fid < 0) {
		return fid;
	}

	rc = ejsEvalScript(ep, script, vp);

	ejsCloseBlock(ep, fid);

	return rc;
}

/******************************************************************************/
/*
 *	Parse and evaluate a EJS. The script is evaluated at the current context.
 *	Return the result in *vp. The result is "owned" by EJ and the caller 
 *	must not free it. Returns -1 on errors and zero for success. 
 */

int ejsEvalScript(Ejs *ep, const char *script, EjsVar *vp)
{
	int			state;
	
	ejsClearVar(ep, ep->result);
	ep->gotException = 0;

	if (script == 0) {
		return 0;
	}

	/*
	 *	Allocate a new evaluation block, and save the old one
	 */
	if (ejsLexOpenScript(ep, script) < 0) {
		return MPR_ERR_MEMORY;
	}

	/*
	 *	Do the actual parsing and evaluation
	 */
	ep->scriptStatus = 0;

	do {
		state = ejsParse(ep, EJS_STATE_BEGIN, EJS_FLAGS_EXE);

		if (state == EJS_STATE_RET) {
			state = EJS_STATE_EOF;
		}
	} while (state != EJS_STATE_EOF && state != EJS_STATE_ERR);

	ejsLexCloseScript(ep);

	if (state == EJS_STATE_ERR) {
		return -1;
	}

	if (vp) {
		/* Caller must not free. */
		*vp = *ep->result;
	}

	return ep->scriptStatus;
}

/******************************************************************************/

void ejsSetFileName(Ejs *ep, const char *fileName)
{
	mprFree(ep->fileName);
	ep->fileName = mprStrdup(ep, fileName);
}

/******************************************************************************/
/*
 *	Format the stack backtrace
 */

char *ejsFormatStack(Ejs* ep)
{
	EjsInput	*ip;
	char		*errbuf;
	int			frame, len;

	mprAssert(ep);

	ip = ep->input;

	errbuf = 0;

	len = 0;
	frame = 0;
	while (ip && frame < EJS_MAX_BACKTRACE) {
		char *traceLine, *newErrbuf, *line;
		for (line = ip->line; *line && isspace(*line); line++) {
			;
		}
		mprAllocSprintf(MPR_LOC_ARGS(ep), &traceLine, MPR_MAX_STRING,
			" [%02d] %s, %s, line %d -> %s\n",
			frame++, 
			ip->fileName ? ip->fileName : "script",
			ip->procName ? ip->procName: "global", 
			ip->lineNumber, line);
		if (traceLine == 0) {
			break;
		}
		newErrbuf = mprRealloc(ep, errbuf, len + strlen(traceLine) + 1);
		if (newErrbuf == NULL) {
			break;
		}
		errbuf = newErrbuf;
		memcpy(&errbuf[len], traceLine, strlen(traceLine) + 1);
		len += strlen(traceLine);
		mprFree(traceLine);
		ip = ip->next;
	}
	return errbuf;
}

/******************************************************************************/
/*
 *	Internal use method to set the error message
 *
 *	Error, ArgError, AssertError, IOError, MemoryError, RangeError, 
 *		ReferenceError, SyntaxError, TypeError, MemoryError
 */

void ejsError(Ejs* ep, const char *errorType, const char* fmt, ...)
{
	va_list		fmtArgs;
	EjsVar		*error;
	char		*msg, *stack;

	va_start(fmtArgs, fmt);
	mprAllocVsprintf(MPR_LOC_ARGS(ep), &msg, MPR_MAX_STRING, fmt, fmtArgs);
	va_end(fmtArgs);

	/*
	 *	Create a new Error exception object. If bad error type, default to 
	 *	"Error"
	 */
	if (ejsGetClass(ep, 0, errorType) == 0) {
		errorType = "Error";
	}
	ep->gotException = 1;
	
	error = ejsCreateObj(ep, 0, errorType, msg);
	if (error == 0) {
		return;
	}
	mprFree(msg);

	stack = ejsFormatStack(ep);
	ejsSetPropertyToString(ep, error, "stack", stack);
	mprFree(stack);

	ejsWriteVar(ep, ep->result, error, EJS_SHALLOW_COPY);
	ejsFreeVar(ep, error);
}

/******************************************************************************/

void ejsSyntaxError(Ejs *ep, const char *msg)
{
	if (msg == 0) {
		msg = " ";
	}
	ejsError(ep, EJS_SYNTAX_ERROR, msg);
}

/******************************************************************************/

void ejsMemoryError(Ejs *ep)
{
	ejsError(ep, EJS_MEMORY_ERROR, "Memory allocation error");
}

/******************************************************************************/

void ejsArgError(Ejs *ep, const char *msg)
{
	mprAssert(msg && *msg);

	ejsError(ep, EJS_ARG_ERROR, msg);
}

/******************************************************************************/

void ejsInternalError(Ejs *ep, const char *msg)
{
	mprAssert(msg && *msg);

	ejsError(ep, EJS_INTERNAL_ERROR, msg);
}

/******************************************************************************/
/*
 *	Public routine to set the error message. Caller MUST NOT free.
 */

char *ejsGetErrorMsg(Ejs *ep)
{
	EjsVar		*error;
	const char	*message, *stack, *name;
	char		*buf;

	error = ep->result;

	if (! ejsVarIsObject(error)) {
		name = message = stack = 0;
	} else {
		name = ejsGetPropertyAsString(ep, error, "name");
		message = ejsGetPropertyAsString(ep, error, "message");
		stack = ejsGetPropertyAsString(ep, error, "stack");
	}
	if (name == 0 || message == 0) {
		buf = mprStrdup(ep, "Unspecified execution error\n");
	} else {
		mprAllocSprintf(MPR_LOC_ARGS(ep), &buf, 0, 
			"%s Exception: %s\nStack:\n%s\n",
			name, message, stack ? stack : " " );
	}
	mprFree(ep->errorMsg);
	ep->errorMsg = buf;
	return buf;
}

/******************************************************************************/
/*
 *	Get the current line number
 */

int ejsGetLineNumber(Ejs *ep)
{
	if (ep->input == 0) {
		return -1;
	}
	return ep->input->lineNumber;
}

/******************************************************************************/
/*
 *	Return the local object
 */

EjsVar *ejsGetLocalObj(Ejs *ep)
{
	return ep->local;
}

/******************************************************************************/
/*
 *	Return the global object
 */

EjsVar *ejsGetGlobalObj(Ejs *ep)
{
	return ep->global;
}

/******************************************************************************/
/*
 *	Set the expression return value
 */

void ejsSetReturnValue(Ejs *ep, EjsVar *vp)
{
	mprAssert(ep);
	mprAssert(vp);

	if (vp == 0) {
		return;
	}
	ejsWriteVar(ep, ep->result, vp, EJS_SHALLOW_COPY);
}

/******************************************************************************/
/*
 *	Set the expression return value and free the arg.
 */

void ejsSetReturnValueAndFree(Ejs *ep, EjsVar *vp)
{
	mprAssert(ep);
	mprAssert(vp);

	ejsWriteVar(ep, ep->result, vp, EJS_SHALLOW_COPY);
	ejsFreeVar(ep, vp);
}

/******************************************************************************/
/*
 *	Set the expression return value to a string value.
 */

void ejsSetReturnValueToString(Ejs *ep, const char *value)
{
	mprAssert(ep);
	mprAssert(value);

	ejsWriteVarAsString(ep, ep->result, value);
}

/******************************************************************************/
/*
 *	Set the expression return value to a binary string value.
 */

void ejsSetReturnValueToBinaryString(Ejs *ep, const uchar *value, int len)
{
	mprAssert(ep);
	mprAssert(value);

	ejsWriteVarAsBinaryString(ep, ep->result, value, len);
}

/******************************************************************************/
/*
 *	Set the expression return value to a integer value.
 */

void ejsSetReturnValueToInteger(Ejs *ep, int value)
{
	mprAssert(ep);

	ejsWriteVarAsInteger(ep, ep->result, value);
}

/******************************************************************************/
/*
 *	Set the expression return value to an EjsNum value.
 */

void ejsSetReturnValueToNumber(Ejs *ep, EjsNum value)
{
	mprAssert(ep);

	ejsWriteVarAsNumber(ep, ep->result, value);
}

/******************************************************************************/
/*
 *	Set the expression return value to a boolean value.
 */

void ejsSetReturnValueToBoolean(Ejs *ep, int value)
{
	mprAssert(ep);

	ejsWriteVarAsBoolean(ep, ep->result, value);
}

/******************************************************************************/
/*
 *	Set the expression return value to a boolean value.
 */

void ejsSetReturnValueToUndefined(Ejs *ep)
{
	mprAssert(ep);

	ejsWriteVarAsUndefined(ep, ep->result);
}

/******************************************************************************/
/*
 *	Get the expression return value
 */

EjsVar *ejsGetReturnValue(Ejs *ep)
{
	mprAssert(ep);

	return ep->result;
}

/******************************************************************************/

void *ejsGetUserData(Ejs *ep)
{
	mprAssert(ep);

	return ep->userData;
}

/******************************************************************************/
/*
 *	Get a variable given a full variable spec possibly containing "." or "[]".
 */

EjsVar *ejsGetVar(Ejs *ep, const char *fullName)
{
	mprAssert(ep);
	mprAssert(fullName && *fullName);

	return ejsFindProperty(ep, 0, 0, ep->global, ep->local, fullName, 0);
}

/******************************************************************************/
/*
 *	Get a string var given a full variable spec possibly containing "." or "[]".
 */

const char *ejsGetStr(Ejs *ep, const char *fullName, const char *defaultValue)
{
	EjsVar	*vp;

	mprAssert(fullName && *fullName);

	vp = ejsFindProperty(ep, 0, 0, ep->global, ep->local, fullName, 0);
	if (vp == 0 || !ejsVarIsString(vp)) {
		return defaultValue;
	}
	/* MOB -- what about VarToStr */
	return vp->string;
}

/******************************************************************************/
/*
 *	Get an int var given a full variable spec possibly containing "." or "[]".
 */

int ejsGetInt(Ejs *ep, const char *fullName, int defaultValue)
{
	EjsVar	*vp;

	mprAssert(ep);
	mprAssert(fullName && *fullName);

	vp = ejsFindProperty(ep, 0, 0, ep->global, ep->local, fullName, 0);
	if (vp == 0 || !ejsVarIsInteger(vp)) {
		return defaultValue;
	}
	/* MOB -- should use VarToInt */
	return vp->integer;
}

/******************************************************************************/
/*
 *	Get an bool var given a full variable spec possibly containing "." or "[]".
 */

int ejsGetBool(Ejs *ep, const char *fullName, int defaultValue)
{
	EjsVar	*vp;

	mprAssert(ep);
	mprAssert(fullName && *fullName);

	vp = ejsFindProperty(ep, 0, 0, ep->global, ep->local, fullName, 0);
	if (vp == 0 || !ejsVarIsBoolean(vp)) {
		return defaultValue;
	}
	/* MOB -- should use VarToBool */
	return vp->boolean;
}

/******************************************************************************/
/*
 *	Set a variable that may be an arbitrarily complex object or array reference.
 *	Will always define in the top most variable frame.
 */

int ejsSetVar(Ejs *ep, const char *fullName, const EjsVar *value)
{
	EjsVar		*vp;

	mprAssert(fullName && *fullName);

	vp = ejsFindProperty(ep, 0, 0, ep->global, ep->local, fullName, 1);
	if (vp == 0) {
		return MPR_ERR_CANT_CREATE;
	}

	if (ejsWriteVar(ep, vp, value, EJS_SHALLOW_COPY) == 0) {
		return MPR_ERR_CANT_WRITE;
	}

	return 0;
}

/******************************************************************************/
/*
 *	Set a variable that may be an arbitrarily complex object or array reference.
 *	Will always define in the top most variable frame.
 */

int ejsSetStr(Ejs *ep, const char *fullName, const char *value)
{
	EjsVar		*vp;

	mprAssert(fullName && *fullName);

	vp = ejsFindProperty(ep, 0, 0, ep->global, ep->local, fullName, 1);
	if (vp == 0) {
		return MPR_ERR_CANT_CREATE;
	}

	if (ejsWriteVarAsString(ep, vp, value) == 0) {
		return MPR_ERR_CANT_WRITE;
	}

	return 0;
}

/******************************************************************************/
/*
 *	Set a variable that may be an arbitrarily complex object or array reference.
 *	Will always define in the top most variable frame.
 */

int ejsSetInt(Ejs *ep, const char *fullName, int value)
{
	EjsVar		*vp;

	mprAssert(fullName && *fullName);

	vp = ejsFindProperty(ep, 0, 0, ep->global, ep->local, fullName, 1);
	if (vp == 0) {
		return MPR_ERR_CANT_CREATE;
	}

	/*	Can't fail */
	ejsWriteVarAsInteger(ep, vp, value);

	return 0;
}

/******************************************************************************/
/*
 *	Set a variable that may be an arbitrarily complex object or array reference.
 *	Will always define in the top most variable frame.
 */

int ejsSetBool(Ejs *ep, const char *fullName, bool value)
{
	EjsVar		*vp;

	mprAssert(fullName && *fullName);

	vp = ejsFindProperty(ep, 0, 0, ep->global, ep->local, fullName, 1);
	if (vp == 0) {
		return MPR_ERR_CANT_CREATE;
	}

	/* Can't fail */
	ejsWriteVarAsBoolean(ep, vp, value);

	return 0;
}

/******************************************************************************/
/*
 *	Set a variable that may be an arbitrarily complex object or array reference.
 *	Will always define in the top most variable frame. Free the value passed in.
 */

int ejsSetVarAndFree(Ejs *ep, const char *fullName, EjsVar *value)
{
	EjsVar		*vp;

	mprAssert(fullName && *fullName);

	vp = ejsFindProperty(ep, 0, 0, ep->global, ep->local, fullName, 1);
	if (vp == 0) {
		return MPR_ERR_CANT_CREATE;
	}

	if (ejsWriteVar(ep, vp, value, EJS_SHALLOW_COPY) == 0) {
		ejsFreeVar(ep, value);
		return MPR_ERR_CANT_WRITE;
	}

	ejsFreeVar(ep, value);
	return 0;
}

/******************************************************************************/
/*
 *	Delete a variable
 */

int ejsDeleteVar(Ejs *ep, const char *fullName)
{
	EjsVar		*vp;
	EjsVar		*obj;
	char		*propertyName;

	vp = ejsFindProperty(ep, &obj, &propertyName, ep->global, ep->local, 
		fullName, 0);
	if (vp == 0) {
		return -1;
	}

	mprAssert(propertyName);
	mprAssert(propertyName);

	return ejsDeleteProperty(ep, obj, propertyName);
}

/******************************************************************************/
/*
 *	Utility routine to crack JavaScript arguments. Return the number of args
 *	seen. This routine only supports %s and %d type args.
 *
 *	Typical usage:
 *
 *		if (ejsParseArgs(argc, argv, "%s %d", &name, &age) < 2) {
 *			// Insufficient args
 *			return -1;
 *		}
 */ 

int ejsParseArgs(int argc, char **argv, const char *fmt, ...)
{
	va_list		vargs;
	const char	*cp;
	char		**sp, *s;
	int			*bp, *ip, argn;

	va_start(vargs, fmt);

	if (argv == 0) {
		return 0;
	}

	for (argn = 0, cp = fmt; cp && *cp && argn < argc && argv[argn]; ) {
		if (*cp++ != '%') {
			continue;
		}

		s = argv[argn];
		switch (*cp) {
		case 'b':
			bp = va_arg(vargs, int*);
			if (bp) {
				if (strcmp(s, "true") == 0 || s[0] == '1') {
					*bp = 1;
				} else {
					*bp = 0;
				}
			} else {
				*bp = 0;
			}
			break;

		case 'd':
			ip = va_arg(vargs, int*);
			*ip = atoi(s);
			break;

		case 's':
			sp = va_arg(vargs, char**);
			*sp = s;
			break;

		default:
			mprAssert(0);
		}
		argn++;
	}

	va_end(vargs);
	return argn;
}

/******************************************************************************/
/*
 *	Define the standard classes
 */

int ejsDefineStandardClasses(Ejs *master)
{
	if (ejsDefineArrayClass(master) != 0 ||
			ejsDefineBooleanClass(master) != 0 || 
			ejsDefineErrorClasses(master) != 0 || 
			ejsDefineFunctionClass(master) != 0 || 
			ejsDefineNumberClass(master) != 0 ||
#if FUTURE
			ejsDefineDateClass(master) != 0 ||
#endif
#if BLD_FEATURE_EJS_E4X
			ejsDefineXmlClasses(master) != 0 ||
#endif
#if BLD_FEATURE_EJS_DB && NOT_HERE
			ejsDefineDbClasses(master) != 0 ||
#endif
			ejsDefineStringClass(master) != 0) {
		return MPR_ERR_MEMORY;
	}
	return 0;
}

/******************************************************************************/
/*
 *	Define the EJS System Object Model
 */

int ejsDefineSystemClasses(Ejs *master)
{
	if (ejsDefineSystemClass(master) != 0 ||
			ejsDefineAppClass(master) != 0 ||
			ejsDefineMemoryClass(master) != 0 ||
			ejsDefineLogClass(master) != 0 ||
			ejsDefineDebugClass(master) != 0 ||
			ejsDefineGCClass(master) != 0 ||
			ejsDefineFileSystemClass(master) != 0 ||
#if BREW
			ejsDefineFileClass(master) != 0 ||
			ejsDefineHTTPClass(master) != 0 ||
#endif
			ejsDefineGlobalProperties(master) != 0) {
		return MPR_ERR_MEMORY;
	}
	return 0;
}

/******************************************************************************/
/*
 *	Terminate the system object model and classes
 */

int ejsTermSystemClasses(Ejs *master)
{
#if BREW
	ejsTermHTTPClass(master);
#endif
	return 0;
}

/******************************************************************************/
/*
 *	Define the EJS object model
 */

int ejsCreateObjectModel(Ejs *ejs)
{
	EjsProperty		*pp;

	pp = ejsSetPropertyToNewObj(ejs, ejs->global, "system", "System", 0);
	if (pp == 0) {
		return MPR_ERR_MEMORY;
	}

	if (ejsSetPropertyToNewObj(ejs, ejsGetVarPtr(pp), "app", "System.App", 
			0) == 0) {
		return MPR_ERR_MEMORY;
	}
	return 0;
}

/******************************************************************************/

void ejsTrace(Ejs *ep, const char *fmt, ...)
{
	va_list		args;
	char		buf[MPR_MAX_LOG_STRING];
	int			len;

	va_start(args, fmt);
	len = mprVsprintf(buf, sizeof(buf) - 1, fmt, args);
	va_end(args);

	mprLog(ep, 0, buf, len);

	va_end(args);
}

/******************************************************************************/

bool ejsGotException(Ejs *ep)
{
	return (bool) ep->gotException;
}

/******************************************************************************/

void ejsSetPrimaryHandle(Ejs *ep, void *primaryHandle)
{
	mprAssert(ep);

	ep->primaryHandle = primaryHandle;
}

/******************************************************************************/

void ejsSetAlternateHandle(Ejs *ep, void *alternateHandle)
{
	mprAssert(ep);

	ep->altHandle = alternateHandle;
}

/******************************************************************************/

#else
void ejsDummy() {}

#endif /* BLD_FEATURE_EJS */

/******************************************************************************/
/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim:tw=78
 * vim600: sw=4 ts=4 fdm=marker
 * vim<600: sw=4 ts=4
 */
