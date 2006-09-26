/*
 *	@file 	ejsFile.c
 *	@brief 	File class for the EJ System Object Model
 */
/********************************** Copyright *********************************/
/*
 *	Copyright (c) Mbedthis Software LLC, 2003-2006. All Rights Reserved.
 */
/********************************** Includes **********************************/

#include	"ejs.h"

/******************************************************************************/
/*
 *	Default Constructor
 */

/******************************************************************************/
/************************************ Methods *********************************/
/******************************************************************************/
/*
 *	function open();
 */

static int openProc(Ejs *ep, EjsVar *thisObj, int argc, EjsVar **argv)
{
	ejsTrace(ep, "File.open()\n");
	return 0;
}

/******************************************************************************/
/*
 *	function close();
 */

static int closeProc(Ejs *ep, EjsVar *thisObj, int argc, EjsVar **argv)
{
	ejsTrace(ep, "File.close()\n");
	return 0;
}

/******************************************************************************/
/*
 *	function read();
 */

static int readProc(Ejs *ep, EjsVar *thisObj, int argc, EjsVar **argv)
{
	ejsTrace(ep, "File.read()\n");
	return 0;
}

/******************************************************************************/
/*
 *	function write();
 */

static int writeProc(Ejs *ep, EjsVar *thisObj, int argc, EjsVar **argv)
{
	ejsTrace(ep, "File.write()\n");
	return 0;
}

/******************************************************************************/
/******************************** Initialization ******************************/
/******************************************************************************/

int ejsDefineFileClass(Ejs *ep)
{
	EjsVar	*fileClass;

	fileClass = ejsDefineClass(ep, "File", "Object", 0);
	if (fileClass == 0) {
		return MPR_ERR_CANT_INITIALIZE;
	}

	/*
	 *	Define the methods
	 */
	ejsDefineCMethod(ep, fileClass, "open", openProc, 0);
	ejsDefineCMethod(ep, fileClass, "close", closeProc, 0);
	ejsDefineCMethod(ep, fileClass, "read", readProc, 0);
	ejsDefineCMethod(ep, fileClass, "write", writeProc, 0);

	return ejsObjHasErrors(fileClass) ? MPR_ERR_CANT_INITIALIZE: 0;
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
