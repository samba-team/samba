/*
 *	@file 	ejsStndClasses.c
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
/******************************* Function Class *******************************/
/******************************************************************************/

int ejsDefineFunctionClass(Ejs *ep)
{
	if (ejsDefineClass(ep, "Function", "Object", ejsFunctionConstructor) == 0) {
		return MPR_ERR_CANT_INITIALIZE;
	}
	return 0;
}

/******************************************************************************/
/*
 *	Function constructor
 */

int ejsFunctionConstructor(Ejs *ep, EjsVar *thisObj, int argc, EjsVar **argv)
{
	int		rc;

	if (argc != 1 || !ejsVarIsString(argv[0])) {
		ejsArgError(ep, "Usage: Function(\"function (arg) { script };\");");
	}

	rc = ejsEvalScript(ep, argv[0]->string, 0);

	/*
	 *	Note: this will convert the object into a method. It will cease to be
	 *	an object.
	 */
	if (rc == 0 && ejsVarIsMethod(ep->result)) {
		/*
		 *	Must make thisObj collectable.
		 */
		ejsMakeObjPermanent(thisObj, 0);
		ejsMakeObjLive(thisObj, 1);
		mprAssert(ejsObjIsCollectable(thisObj));
		ejsWriteVar(ep, thisObj, ep->result, EJS_SHALLOW_COPY);
	}
	return rc;
}

/******************************************************************************/
/******************************* Boolean Class ********************************/
/******************************************************************************/

int ejsDefineBooleanClass(Ejs *ep)
{
	if (ejsDefineClass(ep, "Boolean", "Object", ejsBooleanConstructor) == 0){
		return MPR_ERR_CANT_INITIALIZE;
	}
	return 0;
}

/******************************************************************************/
/*
 *	Boolean constructor
 */

int ejsBooleanConstructor(Ejs *ep, EjsVar *thisObj, int argc, EjsVar **argv)
{
	return 0;
}

/******************************************************************************/
/******************************** Number Class ********************************/
/******************************************************************************/

int ejsDefineNumberClass(Ejs *ep)
{
	if (ejsDefineClass(ep, "Number", "Object", ejsNumberConstructor) == 0) {
		return MPR_ERR_CANT_INITIALIZE;
	}
	return 0;
}

/******************************************************************************/
/*
 *	Number constructor
 */

int ejsNumberConstructor(Ejs *ep, EjsVar *thisObj, int argc, EjsVar **argv)
{
	return 0;
}

/******************************************************************************/

#else
void ejsStndClassesDummy() {}

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
