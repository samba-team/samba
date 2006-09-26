/*
 *	@file 	ejsClass.c
 *	@brief 	EJS class support
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
/********************************* Includes ***********************************/

#include	"ejs.h"

#if BLD_FEATURE_EJS

/************************************ Code ************************************/
/*
 *	Internal API
 *
 *	Routine to create a simple class object. This routine will create a
 *	stand-alone class object. Callers must insert this into the relevant
 *	"global" object for name resolution. From these class objects, instance
 *	objects may be created via the javascript "new" command.
 *
 *	Users should use ejsDefineClass
 */

EjsVar *ejsCreateSimpleClass(Ejs *ep, EjsVar *baseClass, const char *className)
{
	EjsProperty	*pp;
	EjsVar		*classObj;

	/*
	 *	Create an instance of an Object to act as the static class object
	 */
	classObj = ejsCreateSimpleObjUsingClass(ep, baseClass);
	if (classObj == 0) {
		mprAssert(classObj);
		return 0;
	}
	ejsSetClassName(ep, classObj, className);

	/*
	 *	Set the propotype property to point to this class.
	 *	Note: this is a self reference so the alive bit will not be turned on.
	 */
	pp = ejsSetProperty(ep, classObj, "prototype", classObj);
	ejsMakePropertyEnumerable(pp, 0);

	return classObj;
}

/******************************************************************************/
/*
 *	Define a class in the given interpreter. If parentClass is specified, the
 *	class is defined in the parent. Otherwise, the class will be defined
 *	locally/globally. ClassName and extends are full variable specs 
 *	(may contain ".")
 */

EjsVar *ejsDefineClass(Ejs *ep, const char *className, const char *extends, 
	EjsCMethod constructor)
{
	EjsVar		*parentClass, *classObj, *baseClass, *vp;
	char		*name;
	char		*cp;

	/*
	 *	If the className is a qualified name (with "."), then get the 
	 *	parent class name.
	 */
	name = mprStrdup(ep, className);
	cp = strrchr(name, '.');
	if (cp != 0) {
		*cp++ = '\0';
		className = cp;
		parentClass = ejsFindProperty(ep, 0, 0, ep->global, ep->local, name, 0);
		if (parentClass == 0 || parentClass->type != EJS_TYPE_OBJECT) {
			mprError(ep, MPR_LOC, "Can't find class's parent class %s", name);
			mprFree(name);
			return 0;
		}

	} else {
		/*
		 *	Simple class name without a "." so create the class locally 
		 *	if a local scope exists, otherwise globally.
		 */
		parentClass = (ep->local) ? ep->local : ep->global;
	}

	if (parentClass == 0) {
		mprError(ep, MPR_LOC, "Can't find parent class");
		mprFree(name);
		return 0;
	}

	/* OPT should use function that doesn't parse [] . */
	baseClass = ejsGetClass(ep, 0, extends);
	if (baseClass == 0) {
		mprAssert(baseClass);
		mprFree(name);
		return 0;
	}

	classObj = ejsCreateSimpleClass(ep, baseClass, className);
	if (classObj == 0) {
		mprAssert(classObj);
		mprFree(name);
		return 0;
	}

	if (constructor) {
		ejsDefineCMethod(ep, classObj, className, constructor, 0);
	}

	ejsSetPropertyAndFree(ep, parentClass, className, classObj);

	vp = ejsGetPropertyAsVar(ep, parentClass, className);
	mprFree(name);

	return vp;
}

/******************************************************************************/
/*
 *	Find a class and return the property defining the class. ClassName may 
 *	contain "." and is interpreted relative to obj. Obj is typically some
 *	parent object, ep->local or ep->global. If obj is null, then the global 
 *	space is used.
 */

EjsVar *ejsGetClass(Ejs *ep, EjsVar *obj, const char *className)
{
	EjsVar		*vp;

	mprAssert(ep);

	/*
	 *	Search first for a constructor of the name of class
	 *	global may not be defined yet.
	 */
	if (obj) {
		vp = ejsFindProperty(ep, 0, 0, obj, 0, className, 0);

	} else {
		mprAssert(ep->global);
		vp = ejsFindProperty(ep, 0, 0, ep->global, ep->local, className, 0);
	}
	if (vp == 0 || vp->type != EJS_TYPE_OBJECT) {
		return 0;
	}

	/*
	 *	Return a reference to the prototype (self) reference. This
	 *	ensures that even if "obj" is deleted, this reference will remain
	 *	usable.
	 */
	return ejsGetPropertyAsVar(ep, vp, "prototype");
}

/******************************************************************************/
/*
 *	Return the class name of a class or object
 */

const char *ejsGetClassName(EjsVar *vp)
{
	EjsObj 	*obj;

	mprAssert(vp);
	mprAssert(vp->type == EJS_TYPE_OBJECT);
	mprAssert(vp->objectState->baseClass);

	if (vp == 0 || !ejsVarIsObject(vp)) {
		return 0;
	}
	obj = vp->objectState;

	return obj->className;
}

/******************************************************************************/
/*
 *	Return the class name of an objects underlying class
 *	If called on an object, it returns the base class. 
 *	If called on a class, it returns the base class for the class. 
 */

const char *ejsGetBaseClassName(EjsVar *vp)
{
	EjsObj 	*obj;

	mprAssert(vp);
	mprAssert(vp->type == EJS_TYPE_OBJECT);
	mprAssert(vp->objectState->baseClass);

	if (vp == 0 || !ejsVarIsObject(vp)) {
		return 0;
	}
	obj = vp->objectState;
	if (obj->baseClass == 0) {
		return 0;
	}
	mprAssert(obj->baseClass->objectState);

	return obj->baseClass->objectState->className;
}

/******************************************************************************/

EjsVar *ejsGetBaseClass(EjsVar *vp)
{
	if (vp == 0 || !ejsVarIsObject(vp) || vp->objectState == 0) {
		mprAssert(0);
		return 0;
	}
	return vp->objectState->baseClass;
}

/******************************************************************************/

void ejsSetBaseClass(EjsVar *vp, EjsVar *baseClass)
{
	if (vp == 0 || !ejsVarIsObject(vp) || vp->objectState == 0) {
		mprAssert(0);
		return;
	}
	vp->objectState->baseClass = baseClass;
}

/******************************************************************************/

#else
void ejsProcsDummy() {}

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
