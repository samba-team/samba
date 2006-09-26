/*
 *	@file 	ejsSystem.c
 *	@brief 	System class for the EJS Object Model
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
#if UNUSED
/*
 *	function int random()
 */

static int randomProc(Ejs *ep, EjsVar *thisObj, int argc, EjsVar **argv)
{
	ejsTrace(ep, "random()\n");
	return 0;
}

/******************************************************************************/
/*
 *	function void yield()
 */

static int yieldProc(Ejs *ep, EjsVar *thisObj, int argc, EjsVar **argv)
{
	ejsTrace(ep, "yield()\n");
	return 0;
}

/******************************************************************************/
/*
 *	function void sleep(int milliSeconds)
 */

static int sleepProc(Ejs *ep, EjsVar *thisObj, int argc, EjsVar **argv)
{
	ejsTrace(ep, "sleep()\n");
	return 0;
}

#endif
/******************************************************************************/
/*
 *	function void exit(int status)
 *
 *	Exit the widget with the given status. All JavaScript processing ceases.
 */

static int exitProc(Ejs *ep, EjsVar *thisObj, int argc, EjsVar **argv)
{
	int		status;

	status = 0;
	if ((argc == 1) && ejsVarIsInteger(argv[0])) {
		status = argv[0]->integer;
	}
	ejsExit(ep, status);
	return 0;
}

/******************************************************************************/
/******************************** Initialization ******************************/
/******************************************************************************/

int ejsDefineSystemClass(Ejs *ep)
{
	EjsVar	*systemClass;

	/*
	 *	We create the system class and define static methods on it.
	 *	NOTE: There is no object instance
	 */
	systemClass =  ejsDefineClass(ep, "System", "Object", 0);
	if (systemClass == 0) {
		return MPR_ERR_CANT_INITIALIZE;
	}

	ejsDefineCMethod(ep, systemClass, "exit", exitProc, EJS_NO_LOCAL);

#if UNUSED
	ejsDefineCMethod(ep, systemClass, "random", randomProc, EJS_NO_LOCAL);
	ejsDefineCMethod(ep, systemClass, "yield", yieldProc, EJS_NO_LOCAL);
	ejsDefineCMethod(ep, systemClass, "sleep", sleepProc, EJS_NO_LOCAL);

	/*
	 *	Define properties 
	 */
	ejsSetPropertyToString(systemClass, "name", "");
#endif

	return ejsObjHasErrors(systemClass) ? MPR_ERR_CANT_INITIALIZE : 0;
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
