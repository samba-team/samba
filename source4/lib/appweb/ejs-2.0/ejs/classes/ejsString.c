/*
 *	@file 	ejsString.c
 *	@brief 	EJScript string class
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
/*********************************** Constructors *****************************/
/******************************************************************************/
/*
 *	String constructor. 
 */

int ejsStringConstructor(Ejs *ejs, EjsVar *thisObj, int argc, EjsVar **argv)
{
	char	*str;

	if (argc == 0) {
		ejsSetReturnValueToString(ejs, "");

	} else if (argc == 1) {
		/* MOB -- rc */
		str = ejsVarToString(ejs, argv[0]);
		ejsSetReturnValueToString(ejs, str);

	} else {
		ejsArgError(ejs, "usage: String([var])");
		return -1;
	}

	return 0;
}

/******************************************************************************/
/******************************** Visible Methods *****************************/
/******************************************************************************/
/*
 *	Return a string containing the character at a given index
 *
 *	String string.charAt(Number)
 */

static int charAt(Ejs *ejs, EjsVar *thisObj, int argc, EjsVar **argv)
{
	EjsNum		num;
	char		buf[2];

	if (argc != 1) {
		ejsArgError(ejs, "usage: charAt(integer)");
		return -1;
	}

	num = ejsVarToNumber(argv[0]);
	if (num < 0 || num >= thisObj->length) {
		ejsError(ejs, EJS_RANGE_ERROR, "Bad index");
		return -1;
	}

	mprAssert(ejsVarIsString(thisObj));

	buf[0] = argv[0]->string[num];
	buf[1] = '\0';
	ejsSetReturnValueToString(ejs, buf);

	return 0;
}

/******************************************************************************/
/*
 *	Return an integer containing the character at a given index
 *
 *	Number string.charCodeAt(Number)
 */

static EjsNum charCodeAt(Ejs *ejs, EjsVar *thisObj, int argc, EjsVar **argv)
{
	EjsNum			num;

	if (argc != 1) {
		ejsArgError(ejs, "usage: charCodeAt(integer)");
		return -1;
	}

	num = ejsVarToNumber(argv[0]);
	if (num < 0 || num >= thisObj->length) {
		ejsError(ejs, EJS_RANGE_ERROR, "Bad index");
		return -1;
	}
	ejsSetReturnValueToNumber(ejs, (EjsNum) argv[0]->string[num]);

	return 0;
}

/******************************************************************************/
/*
 *	Catenate
 *
 *	String string.catenate(var, ...)
 */

static int concat(Ejs *ejs, EjsVar *thisObj, int argc, EjsVar **argv)
{
	int				i;

	if (argc == 0) {
		ejsArgError(ejs, "usage: concat(String, ...)");
		return -1;
	}

	mprAssert(ejsVarIsString(thisObj));

	for (i = 0; i < argc; i++) {
		if (ejsStrcat(ejs, thisObj, argv[i]) < 0) {
			ejsMemoryError(ejs);
			return -1;
		}
	}
	ejsSetReturnValue(ejs, thisObj);
	return 0;
}

/******************************************************************************/
/*
 *	Return the position of the first occurance of a substring
 *
 *	Number string.indexOf(String subString [, Number start])
 */

static int indexOf(Ejs *ejs, EjsVar *thisObj, int argc, EjsVar **argv)
{
	char	*pat, *s1, *s2, *origin;
	int		start, i;

	if (argc == 0 || argc > 2) {
		ejsArgError(ejs, "usage: indexOf(String [, Number])");
		return -1;
	}

	pat = ejsVarToString(ejs, argv[0]);

	if (argc == 2) {
		start = ejsVarToNumber(argv[1]);
		if (start > thisObj->length) {
			start = thisObj->length;
		}
	} else {
		start = 0;
	}

	i = start;
	for (origin = &thisObj->string[i]; i < thisObj->length; i++, origin++) {
		s1 = origin;
		for (s2 = pat; *s1 && *s2; s1++, s2++) {
			if (*s1 != *s2) {
				break;
			}
		}
		if (*s2 == '\0') {
			ejsSetReturnValueToNumber(ejs, (EjsNum) (origin - thisObj->string));
		}
	}

	ejsSetReturnValueToNumber(ejs, (EjsNum) -1);
	return 0;
}

/******************************************************************************/
/*
 *	Return the position of the last occurance of a substring
 *
 *	Number string.lastIndexOf(String subString [, Number start])
 */

static int lastIndexOf(Ejs *ejs, EjsVar *thisObj, int argc, EjsVar **argv)
{
	char	*pat, *s1, *s2, *origin;
	int		start;

	if (argc == 0 || argc > 2) {
		ejsArgError(ejs, "usage: indexOf(String [, Number])");
		return -1;
	}

	pat = ejsVarToString(ejs, argv[0]);

	if (argc == 2) {
		start = ejsVarToNumber(argv[1]);
		if (start > thisObj->length) {
			start = thisObj->length;
		}
	} else {
		start = 0;
	}

	origin = &thisObj->string[thisObj->length - 1];
	for (; origin >= &thisObj->string[start]; origin--) {

		s1 = origin;
		for (s2 = pat; *s1 && *s2; s1++, s2++) {
			if (*s1 != *s2) {
				break;
			}
		}
		if (*s2 == '\0') {
			ejsSetReturnValueToNumber(ejs, (EjsNum) (origin - thisObj->string));
		}
	}

	ejsSetReturnValueToNumber(ejs, (EjsNum) -1);
	return 0;
}

/******************************************************************************/
/*
 *	Return a substring
 *
 *	Number string.slice(Number start, Number end)
 */

static int slice(Ejs *ejs, EjsVar *thisObj, int argc, EjsVar **argv)
{
	EjsNum		start, end;

	if (argc != 2) {
		ejsArgError(ejs, "usage: slice(Number, Number)");
		return -1;
	}

	start = ejsVarToNumber(argv[0]);
	end = ejsVarToNumber(argv[1]);
	if (start < 0 || start >= thisObj->length) {
		ejsError(ejs, EJS_RANGE_ERROR, "Bad start index");
		return-1;
	}
	if (end < 0 || end >= thisObj->length) {
		ejsError(ejs, EJS_RANGE_ERROR, "Bad end index");
		return -1;
	}

	mprAssert(ejsVarIsString(thisObj));

	ejsSetReturnValueToBinaryString(ejs, (uchar*) &thisObj->string[start],
		end - start);

	return 0;
}

/******************************************************************************/
/*
 *	Split a string
 *
 *	Number string.split(String delimiter [, Number limit])
 */

static int split(Ejs *ejs, EjsVar *thisObj, int argc, EjsVar **argv)
{
	EjsVar		*array, *vp;
	char		*delim, *last, *cp;
	int			len, limit, alloc;

	if (argc == 0 || argc > 2) {
		ejsArgError(ejs, "usage: split(String [, Number])");
		return -1;
	}

	delim = ejsVarToStringEx(ejs, argv[0], &alloc);

	limit = ejsVarToNumber(argv[1]);

	array = ejsCreateArray(ejs, 0);

	len = strlen(delim);

	last = thisObj->string;
	for (cp = last; *cp; cp++) {
		if (*cp == *delim && strncmp(cp, delim, len) == 0) {
			if (cp > last) {
				vp = ejsCreateBinaryStringVar(ejs, (uchar*) last, (cp - last));
				ejsAddArrayElt(ejs, array, vp, EJS_SHALLOW_COPY);
				ejsFreeVar(ejs, vp);
			}
		}
	}

	ejsSetReturnValue(ejs, array);
	ejsFreeVar(ejs, array);

	if (alloc) {
		mprFree(delim);
	}

	return 0;
}

/******************************************************************************/
/*
 *	Create the object class
 */

int ejsDefineStringClass(Ejs *ejs)
{
	EjsVar		*sc;

	sc = ejsDefineClass(ejs, "String", "Object", ejsStringConstructor);
	if (sc == 0) {
		return MPR_ERR_CANT_INITIALIZE;
	}

	ejsDefineCMethod(ejs, sc, "charAt", charAt, EJS_NO_LOCAL);
	ejsDefineCMethod(ejs, sc, "charCodeAt", charCodeAt, EJS_NO_LOCAL);
	ejsDefineCMethod(ejs, sc, "concat", concat, EJS_NO_LOCAL);
	ejsDefineCMethod(ejs, sc, "indexOf", indexOf, EJS_NO_LOCAL);
	ejsDefineCMethod(ejs, sc, "lastIndexOf", lastIndexOf, EJS_NO_LOCAL);
	ejsDefineCMethod(ejs, sc, "slice", slice, EJS_NO_LOCAL);
	ejsDefineCMethod(ejs, sc, "split", split, EJS_NO_LOCAL);
#if UNUSED
	ejsDefineCMethod(ejs, sc, "match", match, EJS_NO_LOCAL);
	ejsDefineCMethod(ejs, sc, "replace", replace, EJS_NO_LOCAL);
	ejsDefineCMethod(ejs, sc, "search", search, EJS_NO_LOCAL);
	ejsDefineCMethod(ejs, sc, "substring", substring, EJS_NO_LOCAL);
	//	MOB bad name
	ejsDefineCMethod(ejs, sc, "substr", substr, EJS_NO_LOCAL);
	ejsDefineCMethod(ejs, sc, "toLowerCase", toLowerCase, EJS_NO_LOCAL);
	ejsDefineCMethod(ejs, sc, "toUpperCase", toUpperCase, EJS_NO_LOCAL);

	//	Static method
	ejsDefineCMethod(ejs, sc, "fromCharCode", fromCharCode, 0, EJS_NO_LOCAL);
#endif

	if (ejsObjHasErrors(sc)) {
		ejsFreeVar(ejs, sc);
		return MPR_ERR_CANT_CREATE;
	}
	return 0;
}

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
