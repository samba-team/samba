/*
 *	@file 	ejsArray.c
 *	@brief 	Array class
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

/************************************ Code ************************************/

int ejsDefineArrayClass(Ejs *ep)
{
	if (ejsDefineClass(ep, "Array", "Object", ejsArrayConstructor) == 0) {
		return MPR_ERR_CANT_INITIALIZE;
	}
	return 0;
}

/******************************************************************************/
/*
 *	Routine to create the base array type
 */

EjsVar *ejsCreateArrayInternal(EJS_LOC_DEC(ep, loc), int size)
{
	EjsProperty	*pp;
	EjsVar		*obj, *vp;

	/* MOB -- need to supply hash size -- max(size, 503)); */

	obj = ejsCreateSimpleObjInternal(EJS_LOC_PASS(ep, loc), "Array");
	if (obj == 0) {
		mprAssert(0);
		return obj;
	}
	obj->isArray = 1;

	/*	MOB -- call constructor here and replace this code */

	pp = ejsSetPropertyToInteger(ep, obj, "length", size);
	ejsMakePropertyEnumerable(pp, 0);

	vp = ejsGetVarPtr(pp);
	vp->isArrayLength = 1;

	return obj;
}

/******************************************************************************/

EjsVar *ejsAddArrayElt(Ejs *ep, EjsVar *op, EjsVar *element, 
	EjsCopyDepth copyDepth)
{
	EjsProperty		*pp;
	EjsVar			*vp;
	char			idx[16];
	int				length;

	mprAssert(op->isArray);

	length = ejsGetPropertyAsInteger(ep, op, "length");

	mprItoa(idx, sizeof(idx), length);
	pp = ejsCreateProperty(ep, op, idx);
	vp = ejsGetVarPtr(pp);

	ejsWriteVar(ep, vp, element, copyDepth);

	ejsSetPropertyToInteger(ep, op, "length", length + 1);

	return vp;
}

/******************************************************************************/
/*
 *	Constructor
 */

int ejsArrayConstructor(Ejs *ep, EjsVar *thisObj, int argc, EjsVar **argv)
{
	EjsProperty		*pp;
	EjsVar			*vp;
	char			idx[16];
	int				i, max;

	thisObj->isArray = 1;
	max = 0;

	if (argc > 0) {
		if (argc == 1 && ejsVarIsNumber(argv[0])) {
			/*
			 *	x = new Array(size);
			 */
			max = (int) ejsVarToInteger(argv[0]);

		} else {
			/*
			 *	x = new Array(element0, element1, ..., elementN):
			 */
			max = argc;
			for (i = 0; i < max; i++) {
				mprItoa(idx, sizeof(idx), i);
				pp = ejsCreateSimpleProperty(ep, thisObj, idx);
				vp = ejsGetVarPtr(pp);
				ejsWriteVar(ep, vp, argv[i], EJS_SHALLOW_COPY);
			}
		}
	}

	pp = ejsCreateSimpleProperty(ep, thisObj, "length");
	ejsMakePropertyEnumerable(pp, 0);
	vp = ejsGetVarPtr(pp);
	ejsWriteVarAsInteger(ep, vp, max);
	vp->isArrayLength = 1;

	return 0;
}

/******************************************************************************/

#else
void ejsArrayDummy() {}

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
