/*
 *	@file 	ejsError.c
 *	@brief 	Error class
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
/*
 *	Parse the args and return the message. Convert non-string args using
 *	.toString.
 */

static char *getMessage(Ejs *ep, int argc, EjsVar **argv)
{
	if (argc == 0) {
		return "";

	} else if (argc == 1) {
		if (! ejsVarIsString(argv[0])) {
			if (ejsRunMethod(ep, argv[0], "toString", 0) < 0) {
				return 0;
			}
			return ep->result->string;

		} else {
			return argv[0]->string;
		}

	} else {
 		/* Don't call ejsError here or it will go recursive. */
		return 0;
	}
}


/******************************************************************************/
/*
 *	Error Constructor and also used for constructor for sub classes. 
 *
 *	Usage: new Error([message])
 */

int ejsErrorCons(Ejs *ep, EjsVar *thisObj, int argc, EjsVar **argv)
{
	char 	*msg, *stack;

	msg = getMessage(ep, argc, argv);
	if (msg == 0) {
		return -1;
	}

	ejsSetPropertyToString(ep, thisObj, "name", ejsGetBaseClassName(thisObj));
	ejsSetPropertyToString(ep, thisObj, "message", msg);

	ejsSetPropertyToUndefined(ep, thisObj, "stack");

	stack = ejsFormatStack(ep);
	if (stack) {
		ejsSetPropertyToString(ep, thisObj, "stack", stack);
		mprFree(stack);
	}

	if (ejsObjHasErrors(thisObj)) {
		return -1;
	}

	return 0;
}

/******************************************************************************/

int ejsDefineErrorClasses(Ejs *ep)
{
	if (ejsDefineClass(ep, "Error", "Object", ejsErrorCons) == 0 ||
		ejsDefineClass(ep, "AssertError", "Error", ejsErrorCons) == 0 ||
		ejsDefineClass(ep, "EvalError", "Error", ejsErrorCons) == 0 ||
		ejsDefineClass(ep, "InternalError", "Error", ejsErrorCons) == 0 ||
		ejsDefineClass(ep, "IOError", "Error", ejsErrorCons) == 0 ||
		ejsDefineClass(ep, "MemoryError", "Error", ejsErrorCons) == 0 ||
		ejsDefineClass(ep, "RangeError", "Error", ejsErrorCons) == 0 ||
		ejsDefineClass(ep, "ReferenceError", "Error", ejsErrorCons) == 0 ||
		ejsDefineClass(ep, "SyntaxError", "Error", ejsErrorCons) == 0 ||
		ejsDefineClass(ep, "TypeError", "Error", ejsErrorCons) == 0) {

		return MPR_ERR_CANT_INITIALIZE;
	}
	return 0;
}

/******************************************************************************/

#else
void ejsErrorDummy() {}

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
