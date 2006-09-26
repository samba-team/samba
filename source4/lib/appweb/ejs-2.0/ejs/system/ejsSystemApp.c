/*
 *	@file 	ejsSystemApp.c
 *	@brief 	App class
 */
/********************************** Copyright *********************************/
/*
 *	Copyright (c) Mbedthis Software Inc, 2005-2006. All Rights Reserved.
 */
/********************************** Includes **********************************/

#include	"ejs.h"

/************************************ Code ************************************/

int ejsDefineAppClass(Ejs *ep)
{
	EjsVar	*appClass;

	appClass =  ejsDefineClass(ep, "System.App", "Object", 0);
	if (appClass == 0) {
		return MPR_ERR_CANT_INITIALIZE;
	}

	/*
	 *	Define properties 
	 */
	ejsSetPropertyToString(ep, appClass, "name", BLD_PRODUCT);
	ejsSetPropertyToString(ep, appClass, "title", BLD_NAME);
	ejsSetPropertyToString(ep, appClass, "version", BLD_VERSION);

	/*
	 *	Command line arguments
	 */
	ejsSetPropertyToNull(ep, appClass, "args");

	return ejsObjHasErrors(appClass) ? MPR_ERR_CANT_INITIALIZE : 0;
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
