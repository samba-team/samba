/*
 *	@file 	ejsGlobal.c
 *	@brief 	EJS support methods
 */
/********************************* Copyright **********************************/
/*
 *	@copy	default
 *	
 *	Copyright (c) Mbedthis Software LLC, 2003-2006. All Rights Reserved.
 *	Copyright (c) Michael O'Brien, 1994-1995. All Rights Reserved.
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

/******************************************************************************/
/************************************* Code ***********************************/
/******************************************************************************/
/*
 *	assert(condition)
 */

static int assertProc(Ejs *ep, EjsVar *thisObj, int argc, EjsVar **argv)
{
	int		b;

	if (argc < 1) {
		ejsError(ep, EJS_ARG_ERROR, "usage: assert(condition)");
		return -1;
	}
	b = ejsVarToBoolean(argv[0]);
	if (b == 0) {
		ejsError(ep, EJS_ASSERT_ERROR, "Assertion failure at line %d",
			ejsGetLineNumber(ep));
		return -1;
	}
	ejsWriteVarAsBoolean(ep, ep->result, b);
	return 0;
}

/******************************************************************************/
/*
 *	breakpoint(msg) 
 */

static int breakpointProc(Ejs *ep, EjsVar *thisObj, int argc, EjsVar **argv)
{
	char 	*buf;

	if (argc < 1) {
		return 0;
	}
	buf = ejsVarToString(ep, argv[0]);
	if (buf) {
		mprBreakpoint(0, buf);
	}
	return 0;
}

/******************************************************************************/
/*
 *	basename(path) 
 */

static int basenameProc(Ejs *ep, EjsVar *thisObj, int argc, EjsVar **argv)
{
	char 	*path;

	if (argc != 1) {
		ejsError(ep, EJS_ARG_ERROR, "usage: basename(path)");
		return -1;
	}
	
	path = ejsVarToString(ep, argv[0]);
	if (path == 0) {
		return MPR_ERR_MEMORY;
	}
	ejsSetReturnValueToString(ep, mprGetBaseName(path));

	return 0;
}

/******************************************************************************/
/*
 *	stripext(path) 
 */

static int stripextProc(Ejs *ep, EjsVar *thisObj, int argc, EjsVar **argv)
{
	char 	*cp, *path, *stripPath;

	if (argc != 1) {
		ejsError(ep, EJS_ARG_ERROR, "usage: stripext(path)");
		return -1;
	}
	
	path = ejsVarToString(ep, argv[0]);
	if (path == 0) {
		return MPR_ERR_MEMORY;
	}
	stripPath = mprStrdup(ep, path);

	if ((cp = strrchr(stripPath, '.')) != 0) {
		*cp = '\0';
	}

	ejsSetReturnValueToString(ep, stripPath);

	mprFree(stripPath);

	return 0;
}

/******************************************************************************/
/*
 *	dirname(path) 
 */

static int dirnameProc(Ejs *ep, EjsVar *thisObj, int argc, EjsVar **argv)
{
	char 	*path;
	char	dirname[MPR_MAX_FNAME];

	if (argc != 1) {
		ejsError(ep, EJS_ARG_ERROR, "usage: dirname(path)");
		return -1;
	}
	
	path = ejsVarToString(ep, argv[0]);
	if (path == 0) {
		return MPR_ERR_MEMORY;
	}

	ejsSetReturnValueToString(ep, 
		mprGetDirName(dirname, sizeof(dirname), path));

	return 0;
}

/******************************************************************************/
/*
 *	trim(string) -- trim white space
 */

static int trimProc(Ejs *ep, EjsVar *thisObj, int argc, EjsVar **argv)
{
	char 	*str, *buf, *cp;

	if (argc != 1) {
		ejsError(ep, EJS_ARG_ERROR, "usage: trim(string)");
		return -1;
	}

	str = ejsVarToString(ep, argv[0]);
	if (str == 0) {
		return MPR_ERR_MEMORY;
	}
	str = buf = mprStrdup(ep, str);

	while (isspace(*str)) {
		str++;
	}
	cp = &str[strlen(str) - 1];
	while (cp >= str) {
		if (isspace(*cp)) {
			*cp = '\0';
		} else {
			break;
		}
		cp--;
	}

	ejsSetReturnValueToString(ep, str);

	mprFree(buf);

	return 0;
}

/******************************************************************************/
/*
 *	Terminate the script
 */

static int exitScript(Ejs *ep, EjsVar *thisObj, int argc, EjsVar **argv)
{
	int			status;

	if (argc != 1) {
		ejsError(ep, EJS_ARG_ERROR, "usage: exit(status)");
		return -1;
	}
	status = (int) ejsVarToInteger(argv[0]);
	ejsExit(ep, status);

	ejsWriteVarAsString(ep, ep->result, "");
	return 0;
}

/******************************************************************************/
/*
 *	include javascript libraries.
 */ 

static int includeProc(Ejs *ep, EjsVar *thisObj, int argc, char **argv)
{
	int			i;

	mprAssert(argv);

	for (i = 0; i < argc; i++) {
		if (ejsEvalFile(ep, argv[i], 0) < 0) {
			return -1;
		}
	} 
	return 0;
}

/******************************************************************************/
/*
 *	include javascript libraries at the global level
 */ 

static int includeGlobalProc(Ejs *ep, EjsVar *thisObj, int argc, char **argv)
{
	int			fid, i;

	mprAssert(argv);

	/*
	 *	Create a new block and set the context to be the global scope
	 */
	fid = ejsSetBlock(ep, ep->global);

	for (i = 0; i < argc; i++) {
		if (ejsEvalFile(ep, argv[i], 0) < 0) {
			ejsCloseBlock(ep, fid);
			return -1;
		}
	} 
	ejsCloseBlock(ep, fid);
	return 0;
}

/******************************************************************************/
#if BLD_DEBUG
/*
 *	Print variables to stdout
 */

static int printvProc(Ejs *ep, EjsVar *thisObj, int argc, EjsVar **argv)
{
	EjsVar			*vp;
	char			*buf;
	int				i;

	for (i = 0; i < argc; ) {
		vp = argv[i++];

		/* mprPrintf(ep, "arg[%d] = ", i); */

		buf = ejsVarToString(ep, vp);

		if (vp->propertyName == 0 || *vp->propertyName == '\0') {
			mprPrintf(ep, "%s: ", buf);
			
		} else if (i < argc) {
			mprPrintf(ep, "%s = %s, ", vp->propertyName, buf);
		} else {
			mprPrintf(ep, "%s = %s\n", vp->propertyName, buf);
		}
	}
	return 0;
}

#endif
/******************************************************************************/
/*
 *	Print the args to stdout
 */

static int printProc(Ejs *ep, EjsVar *thisObj, int argc, EjsVar **argv)
{
	char	*buf;
	int		i;

	for (i = 0; i < argc; i++) {
		buf = ejsVarToString(ep, argv[i]);
		mprPrintf(ep, "%s", buf);
	}
	return 0;
}

/******************************************************************************/
/*
 *	println
 */

static int printlnProc(Ejs *ep, EjsVar *thisObj, int argc, EjsVar **argv)
{
	printProc(ep, thisObj, argc, argv);
	mprPrintf(ep, "\n");
	return 0;
}

/******************************************************************************/
#if FUTURE
/*
 *	sprintf
 */

static int sprintfProc(Ejs *ep, EjsVar *thisObj, int argc, EjsVar **argv)
{
	va_list		ap;
	char		*buf;
	void		**args;
	int			result;

	if (argc <= 1) {
		ejsError(ep, EJS_ARG_ERROR, "Usage: sprintf(fmt, [args ...])");
		return -1;
	}

	args = mprAlloc(ep, sizeof(void*) * (argc - 1));
	if (args == 0) {
		mprAssert(args);
		return -1;
	}

	for (i = 1; i < argc; i++) {
		args[i - 1] = argv[i]);
	}

	va_start(ap, fmt);
	*buf = 0;
	result = inner(0, &buf, MPR_MAX_STRING, fmt, args);
	va_end(ap);

	ejsSetReturnValueToString(ep, buf);

	mprFree(buf);
	return 0;
}

/******************************************************************************/

inner(const char *fmt, void **args)
{
	va_list		ap;

	va_start(ap, fmt);
	*buf = 0;
	mprSprintfCore(ctx, &buf, maxSize, fmt, ap, MPR_PRINTF_ARGV);
	va_end(ap);
}

#endif
/******************************************************************************/
/*
 *	sleep 
 */

static int sleepProc(Ejs *ep, EjsVar *thisObj, int argc, EjsVar **argv)
{
	if (argc != 1) {
		ejsError(ep, EJS_ARG_ERROR, "Usage: sleep(milliseconds)");
		return -1;
	}
	mprSleep(ep, ejsVarToInteger(argv[0]));
	return 0;
}

/******************************************************************************/
/*
 *	sort properties 
 *	FUTURE -- should have option to sort object based on a given property value
 *	ascending or descending
 *	Usage: sort(object, order = ascending, property = 0);
 */

static int sortProc(Ejs *ep, EjsVar *thisObj, int argc, EjsVar **argv)
{
	const char	*property;
	int			error, order;

	error = 0;
	property = 0;

	/*
	 *	Default order is increasing
	 */
	order = 1;

	if (argc < 1 || argc > 3 || !ejsVarIsObject(argv[0])) {
		error++;
	}

	if (argc >= 2) {
		order = ejsVarToInteger(argv[1]);
	}

	/*
	 *	If property is not defined, it sorts the properties in the object
	 */
	if (argc == 3) {
		if (! ejsVarIsString(argv[2])) {
			error++;
		} else {
			property = argv[2]->string;
		}
	}

	if (error) {
		ejsError(ep, EJS_ARG_ERROR, "Usage: sort(object, [order], [property])");
		return -1;
	}
	ejsSortProperties(ep, argv[0], 0, property, order);
	return 0;
}

/******************************************************************************/
/*
 *	Get a time mark
 *	MOB -- WARNING: this can overflow. OK on BREW, but other O/Ss it may have
 *	overflowed on the first call. It should be renamed.
 *	MOB -- replace with proper Date.
 */

static int timeProc(Ejs *ep, EjsVar *thisObj, int argc, EjsVar **argv)
{
	MprTime		now;

	mprGetTime(ep, &now);
#if WIN || LINUX || SOLARIS
{
	/*	MOB -- poor hack */
	static MprTime	initial;
	if (initial.sec == 0) {
		initial = now;
	}
	now.sec -= initial.sec;

	if (initial.msec > now.msec) {
		now.msec = now.msec + 1000 - initial.msec;
		now.sec--;
	} else {
		now.msec -= initial.msec;
	}
}
#endif
	/* MOB -- this can overflow */
	ejsSetReturnValueToInteger(ep, now.sec * 1000 + now.msec);
	return 0;
}

/******************************************************************************/
/*
 *	MOB -- Temporary Get the date (time since Jan 6, 1980 GMT
 */

static int dateProc(Ejs *ep, EjsVar *thisObj, int argc, EjsVar **argv)
{
#if BREW
	uint		now;

	now = GETTIMESECONDS();
	ejsSetReturnValueToInteger(ep, now);
#endif
	return 0;
}

/******************************************************************************/
/*
 *	strlen(string) 
 */

static int strlenProc(Ejs *ep, EjsVar *thisObj, int argc, EjsVar **argv)
{
	char	*buf;
	int		len;

	if (argc != 1) {
		ejsError(ep, EJS_ARG_ERROR, "Usage: strlen(var)");
		return -1;
	}

	len = 0;
	if (! ejsVarIsString(argv[0])) {
		buf = ejsVarToString(ep, argv[0]);
		if (buf) {
			len = strlen(buf);
		}

	} else {
		len = argv[0]->length;
	}
	
	ejsSetReturnValueToInteger(ep, len);
	return 0;
}

/******************************************************************************/
/*
 *	toint(num) 
 */

static int tointProc(Ejs *ep, EjsVar *thisObj, int argc, EjsVar **argv)
{
	int		i;

	if (argc != 1) {
		ejsError(ep, EJS_ARG_ERROR, "Usage: toint(number)");
		return -1;
	}

	i = ejsVarToInteger(argv[0]);
	
	ejsSetReturnValueToInteger(ep, i);
	return 0;
}

/******************************************************************************/
/*
 *	string strstr(string, pat) 
 */

static int strstrProc(Ejs *ep, EjsVar *thisObj, int argc, EjsVar **argv)
{
	char	*str, *pat;
	char	*s;
	int		strAlloc;

	if (argc != 2) {
		ejsError(ep, EJS_ARG_ERROR, "Usage: strstr(string, pat)");
		return -1;
	}

	str = ejsVarToString(ep, argv[0]);

	strAlloc = ep->castAlloc;
	ep->castTemp = 0;

	pat = ejsVarToString(ep, argv[1]);

	s = strstr(str, pat);
	
	if (s == 0) {
		ejsSetReturnValueToUndefined(ep);
	} else {
		ejsSetReturnValueToString(ep, s);
	}

	if (strAlloc) {
		mprFree(str);
	}

	return 0;
}

/******************************************************************************/
/*
 *	Trace 
 */

static int traceProc(Ejs *ep, EjsVar *thisObj, int argc, char **argv)
{
	if (argc == 1) {
		mprLog(ep, 0, "%s", argv[0]);

	} else if (argc == 2) {
		mprLog(ep, atoi(argv[0]), "%s", argv[1]);

	} else {
		ejsError(ep, EJS_ARG_ERROR, "Usage: trace([level], message)");
		return -1;
	}
	ejsWriteVarAsString(ep, ep->result, "");
	return 0;
}

/******************************************************************************/
/*
 *	Evaluate a sub-script. It is evaluated in the same variable scope as
 *	the calling script / method.
 */

static int evalScriptProc(Ejs *ep, EjsVar *thisObj, int argc, EjsVar **argv)
{
	EjsVar		*arg;
	int			i;

	ejsWriteVarAsUndefined(ep, ep->result);

	for (i = 0; i < argc; i++) {
		arg = argv[i];
		if (arg->type != EJS_TYPE_STRING) {
			continue;
		}
		if (ejsEvalScript(ep, arg->string, 0) < 0) {
			return -1;
		}
	}
	/*
	 *	Return with the value of the last expression
 	 */
	return 0;
}

/******************************************************************************/

/* MOB -- need a real datatype returning int, int64, etc */

static int typeofProc(Ejs *ep, EjsVar *thisObj, int argc, EjsVar **argv)
{
	const struct {
		EjsType		type;
		const char 	*name;
	} types[] = {
		{	EJS_TYPE_UNDEFINED,			"undefined"	},
#if EJS_ECMA_STND
		{	EJS_TYPE_NULL,				"object"	},
#else
		{	EJS_TYPE_NULL,				"null"		},
#endif
		{	EJS_TYPE_BOOL,				"boolean"	},
		{	EJS_TYPE_CMETHOD,			"function"	},
		{	EJS_TYPE_FLOAT,				"number"	},
		{	EJS_TYPE_INT,				"number"	},
		{	EJS_TYPE_INT64,				"number"	},
		{	EJS_TYPE_OBJECT,			"object"	},
		{	EJS_TYPE_METHOD,			"function"	},
		{	EJS_TYPE_STRING,			"string"	},
		{	EJS_TYPE_STRING_CMETHOD,	"function"	},
		{	EJS_TYPE_PTR,				"pointer"	}
	};
	const char 	*type;
	int 		i;

 	type = NULL;
	if (argc != 1) {
		ejsError(ep, EJS_ARG_ERROR, "Bad args: typeof(var)");
		return -1;
	}
	
	for (i = 0; i < MPR_ARRAY_SIZE(types); i++) {
		if (argv[0]->type == types[i].type) {
			type = types[i].name;
			break;
		}
	}
	if (type == NULL) {
		mprAssert(type);
		return -1;
	}

	ejsSetReturnValueToString(ep, type);
	return 0;
}

/******************************************************************************/
/*
 *	Define the standard properties and methods inherited by all interpreters
 *	Obj is set to the global class in the default interpreter. When an
 *	interpreter attempts to write to any property, a copy will be written 
 *	into the interpeters own global space. This is like a "copy-on-write".
 */

int ejsDefineGlobalProperties(Ejs *ep)
{
	EjsVar	*obj;

	obj = ep->service->globalClass;
	mprAssert(obj);

	ejsSetPropertyToNull(ep, obj, "null");
	ejsSetPropertyToUndefined(ep, obj, "undefined");
	ejsSetPropertyToBoolean(ep, obj, "true", 1);
	ejsSetPropertyToBoolean(ep, obj, "false", 0);

#if BLD_FEATURE_FLOATING_POINT
	{
		/*	MOB. Fix. This generates warnings on some systems. 
			This is intended. */
		double	d = 0.0;
		double	e = 0.0;
		ejsSetPropertyToFloat(ep, obj, "NaN", e / d);

		d = MAX_FLOAT;
		ejsSetPropertyToFloat(ep, obj, "Infinity", d * d);
	}
#endif

#if BLD_FEATURE_LEGACY_API
	/*
 	 *	DEPRECATED: 2.0.
 	 *	So that ESP/ASP can ignore "language=javascript" statements
	 */
	ejsSetPropertyToInteger(ep, obj, "javascript", 0);
#endif

	/*
 	 *	Extension methods. We go directly to the mpr property APIs for speed.
 	 *	Flags will cause the callbacks to be supplied the Ejs handle.
 	 */
	ejsDefineCMethod(ep, obj, "assert", assertProc, EJS_NO_LOCAL);
	ejsDefineCMethod(ep, obj, "breakpoint", breakpointProc, EJS_NO_LOCAL);
	ejsDefineCMethod(ep, obj, "basename", basenameProc, EJS_NO_LOCAL);
	ejsDefineCMethod(ep, obj, "dirname", dirnameProc, EJS_NO_LOCAL);
	ejsDefineCMethod(ep, obj, "stripext", stripextProc, EJS_NO_LOCAL);
	ejsDefineCMethod(ep, obj, "trim", trimProc, EJS_NO_LOCAL);
	ejsDefineCMethod(ep, obj, "eval", evalScriptProc, EJS_NO_LOCAL);
	ejsDefineCMethod(ep, obj, "exit", exitScript, EJS_NO_LOCAL);
	ejsDefineCMethod(ep, obj, "print", printProc, EJS_NO_LOCAL);
	ejsDefineCMethod(ep, obj, "println", printlnProc, EJS_NO_LOCAL);
	ejsDefineCMethod(ep, obj, "sleep", sleepProc, EJS_NO_LOCAL);
	ejsDefineCMethod(ep, obj, "sort", sortProc, EJS_NO_LOCAL);
	ejsDefineCMethod(ep, obj, "time", timeProc, EJS_NO_LOCAL);
	ejsDefineCMethod(ep, obj, "date", dateProc, EJS_NO_LOCAL);
	ejsDefineCMethod(ep, obj, "strlen", strlenProc, EJS_NO_LOCAL);
	ejsDefineCMethod(ep, obj, "strstr", strstrProc, EJS_NO_LOCAL);
	ejsDefineCMethod(ep, obj, "typeof", typeofProc, EJS_NO_LOCAL);
	ejsDefineCMethod(ep, obj, "toint", tointProc, EJS_NO_LOCAL);

	ejsDefineStringCMethod(ep, obj, "include", includeProc, EJS_NO_LOCAL);
	ejsDefineStringCMethod(ep, obj, "includeGlobal", includeGlobalProc, 
		EJS_NO_LOCAL);
	ejsDefineStringCMethod(ep, obj, "trace", traceProc, EJS_NO_LOCAL);

#if BLD_DEBUG
	ejsDefineCMethod(ep, obj, "printv", printvProc, EJS_NO_LOCAL);
#endif

#if FUTURE
	ejsDefineCMethod(ep, obj, "printf", printfProc, EJS_NO_LOCAL);
	ejsDefineCMethod(ep, obj, "sprintf", sprintfProc, EJS_NO_LOCAL);
#endif

	if (ejsObjHasErrors(obj)) {
		return MPR_ERR_CANT_INITIALIZE;
	}
	return 0;
}

/******************************************************************************/

#else
void ejsProcsDummy() {}

/******************************************************************************/
#endif /* BLD_FEATURE_EJS */

/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim:tw=78
 * vim600: sw=4 ts=4 fdm=marker
 * vim<600: sw=4 ts=4
 */
