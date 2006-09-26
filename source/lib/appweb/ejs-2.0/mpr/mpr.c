/**
 *	@file 	mpr.c
 *	@brief	Mpr initialization 
 *	@overview 
 *	@remarks Most routines in this file are not thread-safe. It is the callers 
 *		responsibility to perform all thread synchronization.
 */

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
/*
 *	We need to use the underlying str(cpy) routines to implement our safe
 *	alternatives
 */
#if !DOXYGEN
#define 	UNSAFE_FUNCTIONS_OK 1
#endif

#include	"mpr.h"

/******************************************************************************/
/*
 *	Initialize the MPR. Create the top level memory context. This routine is 
 *	the first call an MPR application must do. If using MprServices, the 
 *	creation of an Mpr object will call this routine.
 */

MprApp *mprInit(MprAllocCback cback)
{
	return mprInitEx(cback, 0);
}

/******************************************************************************/
/*
 *	Add a shell parameter then do the regular init
 */

MprApp *mprInitEx(MprAllocCback cback, void *shell)
{
	MprApp	*app;

	app = (MprApp*) mprAllocInit(cback);

	mprAssert(app);
	if (app == 0) {
		return 0;
	}

	app->name = mprStrdup(app, BLD_PRODUCT);
	app->title = mprStrdup(app, BLD_NAME);
	app->version = mprStrdup(app, BLD_VERSION);

	mprSetShell(app, shell);

	app->table = mprCreateSymbolTable(app, 0);

	if (mprStartFileServices(app) < 0) {
		mprAllocTerm(app);
		return 0;
	}

#if BLD_FEATURE_MULTITHREAD
	mprInitThreads(app);
#endif

	/*
	 *	See if any of the preceeding allocations failed
	 */
	if (mprGetAllocErrors(app) > 0) {
		mprAllocTerm(app);
		return 0;
	}

	/*
 	 *	Mark all blocks allocated so far as required. They will then be 
	 *	omitted from leak reports.
	 */
	mprSetRequiredAlloc(app, 1);

	return app;
}

/******************************************************************************/
/*
 *	Terminate the MPR. If doStats is true, then output a memory allocation
 *	report.
 */

void mprTerm(MprApp *app, bool doStats)
{
#if BLD_FEATURE_ALLOC_STATS
	if (doStats) {
		mprPrintAllocReport(app, 1, "MPR Memory Allocation Report");
	}
#endif

#if BLD_FEATURE_MULTITHREAD
	mprTermThreads(app);
#endif

	mprStopFileServices(app);

#if BLD_DEBUG
	mprValidateAllocTree(app);
#endif
	mprAllocTerm(app);
}

/******************************************************************************/

bool mprIsExiting(MprCtx ctx)
{
	MprApp	*app;

	app = mprGetApp(ctx);
	if (app == 0) {
		return 1;
	}
	return app->flags & MPR_APP_EXITING;
}

/******************************************************************************/

int mprHasAllocError(MprCtx ctx)
{
	MprApp	*app;

	app = mprGetApp(ctx);
	if (app == 0) {
		return 1;
	}

	return app->flags & MPR_APP_ALLOC_ERROR;
}

/******************************************************************************/

void mprSignalExit(MprCtx ctx)
{
	MprApp	*app;

	app = mprGetApp(ctx);
	app->flags |= MPR_APP_EXITING;
}

/******************************************************************************/

void mprSignalAllocError(MprCtx ctx)
{
	MprApp	*app;

	app = mprGetApp(ctx);
	app->flags |= MPR_APP_ALLOC_ERROR;
}

/******************************************************************************/

int mprSetAppName(MprCtx ctx, const char *name, const char *title, 
	const char *version)
{
	MprApp	*app;

	app = mprGetApp(ctx);

	if (name) {
		mprFree(app->name);
		if ((app->name = mprStrdup(ctx, name)) == 0) {
			return MPR_ERR_CANT_ALLOCATE;
		}
	}

	if (title) {
		mprFree(app->title);
		if ((app->title = mprStrdup(ctx, title)) == 0) {
			return MPR_ERR_CANT_ALLOCATE;
		}
	}

	if (version) {
		mprFree(app->version);
		if ((app->version = mprStrdup(ctx, version)) == 0) {
			return MPR_ERR_CANT_ALLOCATE;
		}
	}
	return 0;
}

/******************************************************************************/

const char *mprGetAppName(MprCtx ctx)
{
	MprApp	*app;

	app = mprGetApp(ctx);
	return app->name;
}

/******************************************************************************/

const char *mprGetAppTitle(MprCtx ctx)
{
	MprApp	*app;

	app = mprGetApp(ctx);
	return app->title;
}

/******************************************************************************/

const char *mprGetAppVersion(MprCtx ctx)
{
	MprApp	*app;

	app = mprGetApp(ctx);
	return app->version;
}

/******************************************************************************/

int mprSetKeyValue(MprCtx ctx, const char *key, void *ptr)
{
	MprApp	*app;

	app = mprGetApp(ctx);
	if (mprInsertSymbol(app->table, key, ptr) == 0) {
		return MPR_ERR_CANT_WRITE;
	}
	return 0;
}

/******************************************************************************/

int mprRemoveKeyValue(MprCtx ctx, const char *key)
{
	MprApp	*app;

	app = mprGetApp(ctx);
	return mprRemoveSymbol(app->table, key);
}

/******************************************************************************/

void *mprGetKeyValue(MprCtx ctx, const char *key)
{
	MprApp	*app;

	app = mprGetApp(ctx);
	return mprLookupSymbol(app->table, key);
}

/******************************************************************************/

bool mprGetDebugMode(MprCtx ctx)
{
	return mprGetApp(ctx)->debugMode;
}

/******************************************************************************/

void mprSetDebugMode(MprCtx ctx, bool on)
{
	mprGetApp(ctx)->debugMode = on;
}

/******************************************************************************/

void mprSetLogHandler(MprCtx ctx, MprLogHandler handler)
{
	mprGetApp(ctx)->logHandler = handler;
}

/******************************************************************************/

MprLogHandler mprGetLogHandler(MprCtx ctx)
{
	return mprGetApp(ctx)->logHandler;
}

#if UNUSED
/******************************************************************************/

void mprSetMprInstance(MprCtx ctx, void *mprInstance)
{
	mprGetApp(ctx)->mprInstance = mprInstance;
}

/******************************************************************************/

void *mprGetMprInstance(MprCtx ctx)
{
	return mprGetApp(ctx)->mprInstance;
}

#endif
/******************************************************************************/

const char *mprCopyright()
{
	return "Copyright (c) Mbedthis Software LLC, 2003-2006. All Rights Reserved.";
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
