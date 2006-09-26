/*
 *	@file 	ejsGC.c
 *	@brief 	Garbage collector class for the EJS Object Model
 */
/********************************** Copyright *********************************/
/*
 *	Copyright (c) Mbedthis Software LLC, 2005-2006. All Rights Reserved.
 */
/********************************** Includes **********************************/

#include	"ejs.h"

/******************************************************************************/
/************************************ Methods *********************************/
/******************************************************************************/
#if (WIN || BREW_SIMULATOR) && BLD_DEBUG

static int checkProc(Ejs *ep, EjsVar *thisObj, int argc, EjsVar **argv)
{
	_CrtCheckMemory();
	return 0;
}

#endif
/******************************************************************************/

static int debugProc(Ejs *ep, EjsVar *thisObj, int argc, EjsVar **argv)
{
	if (argc != 1) {
		ejsError(ep, EJS_ARG_ERROR, "Bad args: debug(debugLevel)");
		return -1;
	}

	ejsSetGCDebugLevel(ep, ejsVarToInteger(argv[0]));
	return 0;
}

/******************************************************************************/
/*
 *	Print stats and dump objects
 */

static int printStatsProc(Ejs *ep, EjsVar *thisObj, int argc, EjsVar **argv)
{
	bool	leakStats;

	if (argc > 1) {
		leakStats = ejsVarToInteger(argv[0]);
	} else {
		leakStats = 0;
	}

#if BLD_FEATURE_ALLOC_STATS
	ejsPrintAllocReport(ep, 0);

	mprPrintAllocReport(mprGetApp(ep), leakStats, 0);
#endif

#if BLD_DEBUG
	ejsDumpObjects(ep);
#endif

	return 0;
}

/******************************************************************************/

static int runProc(Ejs *ep, EjsVar *thisObj, int argc, EjsVar **argv)
{
	if (argc > 1) {
		ejsError(ep, EJS_ARG_ERROR, "Bad args: run([quick])");
		return -1;
	}

	if (argc == 1) {
		ejsIncrementalCollectGarbage(ep);
	} else {
		ejsCollectGarbage(ep, -1);
	}
	return 0;
}

/******************************************************************************/

static int usedMemoryProc(Ejs *ep, EjsVar *thisObj, int argc, EjsVar **argv)
{
	ejsSetReturnValueToInteger(ep, ejsGetUsedMemory(ep));
	return 0;
}

/******************************************************************************/

static int allocatedMemoryProc(Ejs *ep, EjsVar *thisObj, int argc, 
	EjsVar **argv)
{
#if BLD_FEATURE_ALLOC_STATS
	ejsSetReturnValueToInteger(ep, ejsGetAllocatedMemory(ep));
#endif
	return 0;
}

/******************************************************************************/

static int mprMemoryProc(Ejs *ep, EjsVar *thisObj, int argc, EjsVar **argv)
{
#if BLD_FEATURE_ALLOC_STATS
	ejsSetReturnValueToInteger(ep, mprGetAllocatedMemory(ep));
#endif
	return 0;
}

/******************************************************************************/

static int peakMprMemoryProc(Ejs *ep, EjsVar *thisObj, int argc, EjsVar **argv)
{
#if BLD_FEATURE_ALLOC_STATS
	ejsSetReturnValueToInteger(ep, mprGetPeakAllocatedMemory(ep));
#endif
	return 0;
}

/******************************************************************************/

static int getDebugLevel(Ejs *ep, EjsVar *thisObj, int argc, EjsVar **argv)
{
	ejsSetReturnValueToInteger(ep, ep->gc.debugLevel);
	return 0;
}

/******************************************************************************/

static int setDebugLevel(Ejs *ep, EjsVar *thisObj, int argc, EjsVar **argv)
{
	if (argc != 1) {
		ejsArgError(ep, "Bad arguments");
		return -1;
	}
	ep->gc.debugLevel= ejsVarToInteger(argv[0]);
	return 0;
}

/******************************************************************************/

static int getEnable(Ejs *ep, EjsVar *thisObj, int argc, EjsVar **argv)
{
	ejsSetReturnValueToBoolean(ep, ep->gc.enable);
	return 0;
}

/******************************************************************************/

static int setEnable(Ejs *ep, EjsVar *thisObj, int argc, EjsVar **argv)
{
	if (argc != 1) {
		ejsArgError(ep, "Bad arguments");
		return -1;
	}
	ep->gc.enable= ejsVarToBoolean(argv[0]);
	return 0;
}

/******************************************************************************/

static int getDemandCollect(Ejs *ep, EjsVar *thisObj, int argc, EjsVar **argv)
{
	ejsSetReturnValueToBoolean(ep, ep->gc.enableDemandCollect);
	return 0;
}

/******************************************************************************/

static int setDemandCollect(Ejs *ep, EjsVar *thisObj, int argc, EjsVar **argv)
{
	if (argc != 1) {
		ejsArgError(ep, "Bad arguments");
		return -1;
	}
	ep->gc.enableDemandCollect = ejsVarToBoolean(argv[0]);
	return 0;
}

/******************************************************************************/

static int getIdleCollect(Ejs *ep, EjsVar *thisObj, int argc, EjsVar **argv)
{
	ejsSetReturnValueToBoolean(ep, ep->gc.enableIdleCollect);
	return 0;
}

/******************************************************************************/

static int setIdleCollect(Ejs *ep, EjsVar *thisObj, int argc, EjsVar **argv)
{
	if (argc != 1) {
		ejsArgError(ep, "Bad arguments");
		return -1;
	}
	ep->gc.enableIdleCollect = ejsVarToBoolean(argv[0]);
	return 0;
}

/******************************************************************************/

static int getWorkQuota(Ejs *ep, EjsVar *thisObj, int argc, EjsVar **argv)
{
	ejsSetReturnValueToInteger(ep, ep->gc.workQuota);
	return 0;
}

/******************************************************************************/

static int setWorkQuota(Ejs *ep, EjsVar *thisObj, int argc, EjsVar **argv)
{
	int		quota;

	if (argc != 1) {
		ejsArgError(ep, "Bad arguments");
		return -1;
	}
	quota = ejsVarToInteger(argv[0]);
	if (quota < EJS_GC_MIN_WORK_QUOTA && quota != 0) {
		ejsArgError(ep, "Bad work quota");
		return -1;
	}

	ep->gc.workQuota = quota;
	return 0;
}

/******************************************************************************/

static int getMaxMemory(Ejs *ep, EjsVar *thisObj, int argc, EjsVar **argv)
{
	ejsSetReturnValueToInteger(ep, ep->gc.maxMemory);
	return 0;
}

/******************************************************************************/

static int setMaxMemory(Ejs *ep, EjsVar *thisObj, int argc, EjsVar **argv)
{
	int		maxMemory;

	if (argc != 1) {
		ejsArgError(ep, "Bad arguments");
		return -1;
	}
	maxMemory = ejsVarToInteger(argv[0]);
	if (maxMemory < 0) {
		ejsArgError(ep, "Bad maxMemory");
		return -1;
	}

	ep->gc.maxMemory = maxMemory;
	return 0;
}

/******************************************************************************/
/******************************** Initialization ******************************/
/******************************************************************************/

int ejsDefineGCClass(Ejs *ep)
{
	EjsVar	*gcClass;
	int		flags;

	flags = EJS_NO_LOCAL;

	/*
 	 *	NOTE: We create the GC class and define static methods on it. There 
	 *	is no object instance
	 */
	gcClass =  ejsDefineClass(ep, "System.GC", "Object", 0);
	if (gcClass == 0) {
		return MPR_ERR_CANT_INITIALIZE;
	}

	/*
	 *	MOB -- convert these to properties with accessors when available
	 */
	ejsDefineCMethod(ep, gcClass, "printStats", printStatsProc, flags);
	ejsDefineCMethod(ep, gcClass, "run", runProc, flags);

	ejsDefineCMethod(ep, gcClass, "getUsedMemory", usedMemoryProc, flags);
	ejsDefineCMethod(ep, gcClass, "getAllocatedMemory", allocatedMemoryProc,
		flags);
	ejsDefineCMethod(ep, gcClass, "getMprMemory", mprMemoryProc, flags);
	ejsDefineCMethod(ep, gcClass, "getPeakMprMemory", peakMprMemoryProc, flags);
	ejsDefineCMethod(ep, gcClass, "debug", debugProc, flags);

#if (WIN || BREW_SIMULATOR) && BLD_DEBUG
	ejsDefineCMethod(ep, gcClass, "check", checkProc, flags);
#endif

	ejsDefineCAccessors(ep, gcClass, "debugLevel", 
		getDebugLevel, setDebugLevel, flags);

	ejsDefineCAccessors(ep, gcClass, "enable", 
		getEnable, setEnable, flags);

	ejsDefineCAccessors(ep, gcClass, "demandCollect", 
		getDemandCollect, setDemandCollect, flags);

	ejsDefineCAccessors(ep, gcClass, "idleCollect", 
		getIdleCollect, setIdleCollect, flags);

	ejsDefineCAccessors(ep, gcClass, "workQuota", 
		getWorkQuota, setWorkQuota, flags);

	ejsDefineCAccessors(ep, gcClass, "maxMemory", 
		getMaxMemory, setMaxMemory, flags);

	return ejsObjHasErrors(gcClass) ? MPR_ERR_CANT_INITIALIZE : 0;
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
