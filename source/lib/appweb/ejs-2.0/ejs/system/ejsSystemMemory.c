/*
 *	@file 	ejsSystemMemory.c
 *	@brief 	System.Memory class
 */
/********************************** Copyright *********************************/
/*
 *	Copyright (c) Mbedthis Software LLC, 2005-2006. All Rights Reserved.
 */
/********************************** Includes **********************************/

#include	"ejs.h"

/****************************** Forward Declarations***************************/

static uint getUsedMemory(Ejs *ejs);

/******************************************************************************/
/*********************************** Methods *********************************/
/******************************************************************************/

static int getUsedMemoryProc(Ejs *ejs, EjsVar *thisObj, int argc, EjsVar **argv)
{
	ejsSetReturnValueToInteger(ejs, getUsedMemory(ejs));
	return 0;
}

/******************************************************************************/

static int getUsedStackProc(Ejs *ejs, EjsVar *thisObj, int argc, EjsVar **argv)
{
	ejsSetReturnValueToInteger(ejs, mprStackSize(ejs));
	return 0;
}

/******************************************************************************/
/*
 *	Public function
 */

uint ejsGetAvailableMemory(Ejs *ejs)
{
	EjsVar			*memoryClass;
	uint			ram;

	memoryClass =  ejsGetClass(ejs, 0, "System.Memory");

	ram = ejsGetPropertyAsInteger(ejs, memoryClass, "ram");
	return ram - getUsedMemory(ejs);
}

/******************************************************************************/

static int getAvailableMemoryProc(Ejs *ejs, EjsVar *thisObj, int argc, 
	EjsVar **argv)
{
	EjsVar			*memoryClass;
	uint			ram;

	memoryClass = ejsGetClass(ejs, 0, "System.Memory");

	ram = ejsGetPropertyAsInteger(ejs, memoryClass, "ram");
#if BREW
	ejsSetReturnValueToInteger(ejs, ram - getUsedMemory(ejs));
#else
	ejsSetReturnValueToInteger(ejs, 0);
#endif
	return 0;
}

/******************************************************************************/

static uint getUsedMemory(Ejs *ejs)
{
#if BREW
	MprApp			*app;
	IHeap			*heap;
	uint			memInUse;
	void			*ptr;

	app = mprGetApp(ejs);
	ptr = (void*) &heap;
	if (ISHELL_CreateInstance(app->shell, AEECLSID_HEAP, (void**) ptr) 
			== SUCCESS) {
		memInUse = IHEAP_GetMemStats(heap);
		IHEAP_Release(heap); 
	} else {
		memInUse = 0;
	}

	return memInUse;
#else
	return 0;
#endif
}

/******************************************************************************/
/******************************** Initialization ******************************/
/******************************************************************************/

int ejsDefineMemoryClass(Ejs *ejs)
{
	EjsVar			*memoryClass;
	uint			used;

#if BREW
	MprApp			*app;
	AEEDeviceInfo	*info;

	/*
	 * Get needed information for class properties.
	 */
	info = mprAllocType(ejs, AEEDeviceInfo);
	if (info == 0) {
		return MPR_ERR_CANT_ALLOCATE;
	}
	info->wStructSize = sizeof(AEEDeviceInfo);
	app = mprGetApp(ejs);
	ISHELL_GetDeviceInfo(app->shell, info);
	used = getUsedMemory(ejs);
#else
	used = 0;
#endif

	/*
	 *	Create the class
	 */
	memoryClass =  ejsDefineClass(ejs, "System.Memory", "Object", 0);
	if (memoryClass == 0) {
		return MPR_ERR_CANT_INITIALIZE;
	}

	/*
	 *	Define the class methods
	 *	MOB -- change to accessors
	 */
	ejsDefineCMethod(ejs, memoryClass, "getUsedStack", getUsedStackProc, 
		EJS_NO_LOCAL);
	ejsDefineCMethod(ejs, memoryClass, "getUsedMemory", getUsedMemoryProc, 
		EJS_NO_LOCAL);
	ejsDefineCMethod(ejs, memoryClass, "getAvailableMemory", 
		getAvailableMemoryProc, EJS_NO_LOCAL);

	/*
	 *	Define properties
	 */
#if BREW
	ejsSetPropertyToInteger(ejs, memoryClass, "ram", info->dwRAM);

#if UNUSED
	/* MOB -- delete this */
	ejsSetPropertyToInteger(ejs, memoryClass, "available", 
		info->dwRAM - used);
#endif
#endif

#if UNUSED
	ejsSetPropertyToInteger(ejs, memoryClass, "used", used);
	ejsSetPropertyToInteger(ejs, memoryClass, "flash", 0);
#endif

	return ejsObjHasErrors(memoryClass) ? MPR_ERR_CANT_INITIALIZE : 0;
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
