/*
 *	@file 	ejsSystemLog.c
 *	@brief 	System.Log class for the EJS Object Model
 */
/********************************** Copyright *********************************/
/*
 *	Copyright (c) Mbedthis Software LLC, 2005-2006. All Rights Reserved.
 */
/********************************** Includes **********************************/

#include	"ejs.h"

/*********************************** Usage ************************************/
/*
 * 	System.Log.setLog(path);
 *	System.Log.enable;
 */
/******************************************************************************/

static void logHandler(MPR_LOC_DEC(ctx, loc), int flags, int level, 
	const char *msg)
{
	MprApp	*app;
	char	*buf;
	int		len;

	app = mprGetApp(ctx);
	if (app->logFile == 0) {
		return;
	}

	if (flags & MPR_LOG_SRC) {
		len = mprAllocSprintf(MPR_LOC_PASS(ctx, loc), &buf, 0, 
			"Log %d: %s\n", level, msg);

	} else if (flags & MPR_ERROR_SRC) {
		len = mprAllocSprintf(MPR_LOC_PASS(ctx, loc), &buf, 0, 
			"Error: %s\n", msg);

	} else if (flags & MPR_FATAL_SRC) {
		len = mprAllocSprintf(MPR_LOC_PASS(ctx, loc), &buf, 0, 
			"Fatal: %s\n", msg);
		
	} else if (flags & MPR_ASSERT_SRC) {
#if BLD_FEATURE_ALLOC_LEAK_TRACK
		len = mprAllocSprintf(MPR_LOC_PASS(ctx, loc), &buf, 0, 
			"Assertion %s, failed at %s\n",
			msg, loc);
#else
		len = mprAllocSprintf(MPR_LOC_PASS(ctx, loc), &buf, 0, 
			"Assertion %s, failed\n", msg);
#endif

	} else if (flags & MPR_RAW) {
		/* OPT */
		len = mprAllocSprintf(MPR_LOC_PASS(ctx, loc), &buf, 0, 
			"%s", msg);

	} else {
		return;
	}

	mprPuts(app->logFile, buf, len);

	mprFree(buf);
}

/******************************************************************************/
/************************************ Methods *********************************/
/******************************************************************************/
/*
 *	function int setLog(string path)
 */

static int setLog(Ejs *ejs, EjsVar *thisObj, int argc, EjsVar **argv)
{
	const char	*path;
	MprFile		*file;
	MprApp		*app;

	if (argc != 1 || !ejsVarIsString(argv[0])) {
		ejsArgError(ejs, "Usage: setLog(path)");
		return -1;
	}

	app = mprGetApp(ejs);

	/*
	 *	Ignore errors if we can't create the log file.
	 *	Use the app context so this will live longer than the interpreter
	 *	MOB -- this leaks files.
	 */
	path = argv[0]->string;
	file = mprOpen(app, path, O_CREAT | O_TRUNC | O_WRONLY, 0664);
	if (file) {
		app->logFile = file;
		mprSetLogHandler(ejs, logHandler);
	}
	mprLog(ejs, 0, "Test log");

	return 0;
}

/******************************************************************************/
#if UNUSED

static int enableSetAccessor(Ejs *ejs, EjsVar *thisObj, int argc, EjsVar **argv)
{
	if (argc != 1) {
		ejsArgError(ejs, "Usage: set(value)");
		return -1;
	}
	ejsSetProperty(ejs, thisObj, "_enabled", argv[0]);
	return 0;
}

/******************************************************************************/

static int enableGetAccessor(Ejs *ejs, EjsVar *thisObj, int argc, EjsVar **argv)
{
	ejsSetReturnValue(ejs, ejsGetPropertyAsVar(ejs, thisObj, "_enabled"));
	return 0;
}

#endif
/******************************************************************************/
/******************************** Initialization ******************************/
/******************************************************************************/

int ejsDefineLogClass(Ejs *ejs)
{
	EjsVar			*logClass;

	logClass =  ejsDefineClass(ejs, "System.Log", "Object", 0);
	if (logClass == 0) {
		return MPR_ERR_CANT_INITIALIZE;
	}

	ejsDefineCMethod(ejs, logClass, "setLog", setLog, EJS_NO_LOCAL);

#if UNUSED
	EjsProperty		*pp;
	ejsDefineCAccessors(ejs, logClass, "enable", enableSetAccessor, 
		enableGetAccessor, EJS_NO_LOCAL);

	pp = ejsSetPropertyToBoolean(ejs, logClass, "_enabled", 0);
	ejsMakePropertyEnumerable(pp, 0);
#endif

	return ejsObjHasErrors(logClass) ? MPR_ERR_CANT_INITIALIZE : 0;
}

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
