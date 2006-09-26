/*
 *	@file 	ejsSystemDebug.c
 *	@brief 	System.Debug class
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
/*
 *	function bool isDebugMode()
 *	MOB -- convert to accessor
 */

static int isDebugMode(Ejs *ejs, EjsVar *thisObj, int argc, EjsVar **argv)
{
	ejsTrace(ejs, "isDebugMode()\n");
	ejsSetReturnValueToInteger(ejs, mprGetDebugMode(ejs));
	return 0;
}

/******************************************************************************/
/******************************** Initialization ******************************/
/******************************************************************************/

int ejsDefineDebugClass(Ejs *ejs)
{
	EjsVar	*systemDebugClass;

	systemDebugClass =  ejsDefineClass(ejs, "System.Debug", "Object", 0);
	if (systemDebugClass == 0) {
		return MPR_ERR_CANT_INITIALIZE;
	}

	/*
	 *	Define the class methods
	 */
	ejsDefineCMethod(ejs, systemDebugClass, "isDebugMode", isDebugMode,
		EJS_NO_LOCAL);

	return ejsObjHasErrors(systemDebugClass) ? MPR_ERR_CANT_INITIALIZE : 0;
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
