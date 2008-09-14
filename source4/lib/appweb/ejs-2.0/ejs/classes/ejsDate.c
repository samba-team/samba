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

#if BLD_FEATURE_EJS && 0

/******************************************************************************/
/*
 *	Date constructor

 *
 *	Date();
 *	Date(milliseconds);
 *	Date(dateString);
 *	Date(year, month, date);
 *	Date(year, month, date, hour, minute, second);
 */

int ejsDateConstructor(Ejs *ep, EjsVar *thisObj, int argc, EjsVar **argv)
{
	return 0;
}

/******************************************************************************/

static int load(Ejs *ep, EjsVar *thisObj, int argc, EjsVar **argv)
{
	const char	*fileName;
	XmlState	*parser;
	Exml		*xp;
	MprFile		*file;

	if (argc != 1 || !ejsVarIsString(argv[0])) {
		ejsError(ep, EJS_ARG_ERROR, "Bad args. Usage: load(fileName);");
		return -1;
	}
	fileName = argv[0]->string;
	
	/* FUTURE -- not romable 
		Need rom code in MPR not MprServices
	*/
	file = mprOpen(ep, fileName, O_RDONLY, 0664);
	if (file == 0) {
		ejsError(ep, EJS_IO_ERROR, "Can't open: %s", fileName);
		return -1;
	}

	xp = initParser(ep, thisObj, fileName);
	parser = exmlGetParseArg(xp);

	exmlSetInputStream(xp, readFileData, (void*) file);

	if (exmlParse(xp) < 0) {
		if (! ejsGotException(ep)) {
			ejsError(ep, EJS_IO_ERROR, "Can't parse XML file: %s\nDetails %s", 
				fileName, exmlGetErrorMsg(xp));
		}
		termParser(xp);
		mprClose(file);
		return -1;
	}

	ejsSetReturnValue(ep, parser->nodeStack[0].obj);

	termParser(xp);
	mprClose(file);

	return 0;
}

/******************************************************************************/

int ejsDefineDateClass(Ejs *ep)
{
	EjsVar	*dateClass;

	dateClass = ejsDefineClass(ep, "Date", "Object", ejsDateConstructor);
	if (dateClass == 0) {
		return MPR_ERR_CANT_INITIALIZE;
	}

	ejsDefineCMethod(ep, dateClass, "getDate", xxxProc, EJS_NO_LOCAL);

	/* Returns  "Friday" or 4 ? */
	ejsDefineCMethod(ep, dateClass, "getDay", xxxProc, EJS_NO_LOCAL);

	ejsDefineCMethod(ep, dateClass, "getMonth", xxxProc, EJS_NO_LOCAL);
	ejsDefineCMethod(ep, dateClass, "getFullYear", xxxProc, EJS_NO_LOCAL);
	ejsDefineCMethod(ep, dateClass, "getYear", xxxProc, EJS_NO_LOCAL);
	ejsDefineCMethod(ep, dateClass, "getHours", xxxProc, EJS_NO_LOCAL);
	ejsDefineCMethod(ep, dateClass, "getMinutes", xxxProc, EJS_NO_LOCAL);
	ejsDefineCMethod(ep, dateClass, "getSeconds", xxxProc, EJS_NO_LOCAL);
	ejsDefineCMethod(ep, dateClass, "getMilliseconds", xxxProc, EJS_NO_LOCAL);
	ejsDefineCMethod(ep, dateClass, "getTime", xxxProc, EJS_NO_LOCAL);
	ejsDefineCMethod(ep, dateClass, "getTimeZoneOffset", xxxProc, EJS_NO_LOCAL);

	ejsDefineCMethod(ep, dateClass, "parse", xxxProc, EJS_NO_LOCAL);
	ejsDefineCMethod(ep, dateClass, "setDate", xxxProc, EJS_NO_LOCAL);
	ejsDefineCMethod(ep, dateClass, "setMonth", xxxProc, EJS_NO_LOCAL);
	ejsDefineCMethod(ep, dateClass, "setFullYear", xxxProc, EJS_NO_LOCAL);
	ejsDefineCMethod(ep, dateClass, "setYear", xxxProc, EJS_NO_LOCAL);
	ejsDefineCMethod(ep, dateClass, "setMinutes", xxxProc, EJS_NO_LOCAL);
	ejsDefineCMethod(ep, dateClass, "setSeconds", xxxProc, EJS_NO_LOCAL);
	ejsDefineCMethod(ep, dateClass, "setMilliseconds", xxxProc, EJS_NO_LOCAL);
	ejsDefineCMethod(ep, dateClass, "setTime", xxxProc, EJS_NO_LOCAL);

	ejsDefineCMethod(ep, dateClass, "toString", xxxProc, EJS_NO_LOCAL);
	ejsDefineCMethod(ep, dateClass, "toGMTString", xxxProc, EJS_NO_LOCAL);
	ejsDefineCMethod(ep, dateClass, "toUTCString", xxxProc, EJS_NO_LOCAL);
	ejsDefineCMethod(ep, dateClass, "toLocaleString", xxxProc, EJS_NO_LOCAL);
	ejsDefineCMethod(ep, dateClass, "UTC", xxxProc, EJS_NO_LOCAL);
	ejsDefineCMethod(ep, dateClass, "valueOf", xxxProc, EJS_NO_LOCAL);
	/*
		UTC: getUTCDate, getUTCDay, getUTCMonth, getUTCFullYear, getUTCHours,
			getUTCMinutes, getUTCSeconds, getUTCMilliseconds
			setUTCDate, setUTCDay, setUTCMonth, setUTCFullYear, setUTCHours,
			setUTCMinutes, setUTCSeconds, setUTCMilliseconds
	 */

	return ejsObjHasErrors(dateClass) ? MPR_ERR_CANT_INITIALIZE : 0;
}

/******************************************************************************/
/*
	Time is since 1970/01/01 GMT

	Normal: Fri Feb 10 2006 05:06:44 GMT-0800 (Pacific Standard Time)
	UTC: Sat, 11 Feb 2006 05:06:44 GMT

	//	Using without New

	println(Date());

	var myDate = new Date();
	myDate.setFullYear(2010, 0, 14);

	var today = new Date();

	if (myDate > today) {
	} else {
	}


	 X=Date() should be equivalent to X=(new Date()).toString()

 */
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
