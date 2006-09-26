/*
 *	@file 	ejsObject.c
 *	@brief 	Object class
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

/****************************** Forward Declarations **************************/
/*
 *	Support routines
 */

static void formatVar(Ejs *ep, MprBuf *bp, EjsVar *vp);

/******************************************************************************/
/*
 *	Routine to create an object of the desired class. Class name may 
 *	contain "." 
 *
 *	The created object will be a stand-alone class NOT entered into the 
 *	properties of any other object. Callers must do this if required. ClassName 
 *	may contain "." and is interpreted relative to "obj" if supplied.
 *
 *	Note: this does not call the constructors for the various objects and base
 *	classes.
 */

EjsVar *ejsCreateSimpleObjInternal(EJS_LOC_DEC(ep, loc), const char *className)
{
	EjsVar	*baseClass;

	if (className && *className) {
		baseClass = ejsGetClass(ep, 0, className);
		if (baseClass == 0) {
			mprError(ep, MPR_LOC, "Can't find base class %s", className);
			return 0;
		}
	} else {
		baseClass = 0;
	}

	return ejsCreateSimpleObjUsingClassInt(EJS_LOC_PASS(ep, loc), 
		baseClass);
}

/******************************************************************************/
/*
 *	Create an object based upon the specified base class object. It will be a 
 *	stand-alone class not entered into the properties of any other object. 
 *	Callers must do this if required. 
 *
 *	Note: this does not call the constructors for the various objects and base
 *	classes.
 */

EjsVar *ejsCreateSimpleObjUsingClassInt(EJS_LOC_DEC(ep, loc), 
	EjsVar *baseClass)
{
	EjsVar		*vp;

	mprAssert(baseClass);

	if (baseClass == 0) {
		mprError(ep, MPR_LOC, "Missing base class\n");
		return 0;
	}

	vp = ejsCreateObjVarInternal(EJS_LOC_PASS(ep, loc));
	if (vp == 0) {
		return vp;
	}

	ejsSetBaseClass(vp, baseClass);

	/*
	 *	This makes all internal method accesses faster
	 *	NOTE: this code is duplicated in ejsCreateSimpleClass
	 */
	mprAssert(vp->objectState);
	vp->objectState->methods = baseClass->objectState->methods;

	return vp;
}

/******************************************************************************/

void ejsSetMethods(Ejs *ep, EjsVar *op)
{
	op->objectState->methods = ep->global->objectState->methods;
}

/******************************************************************************/
/******************************** Internal Methods ****************************/
/******************************************************************************/

static EjsVar *createObjProperty(Ejs *ep, EjsVar *obj, const char *property)
{
	return ejsGetVarPtr(ejsCreateSimpleProperty(ep, obj, property));
}

/******************************************************************************/

static int deleteObjProperty(Ejs *ep, EjsVar *obj, const char *property)
{
	return ejsDeleteProperty(ep, obj, property);
}

/******************************************************************************/

static EjsVar *getObjProperty(Ejs *ep, EjsVar *obj, const char *property)
{
	return ejsGetVarPtr(ejsGetSimpleProperty(ep, obj, property));
}

/******************************************************************************/
/*
 *	Set the value of a property. Create if it does not exist
 */

static EjsVar *setObjProperty(Ejs *ep, EjsVar *obj, const char *property, 
	const EjsVar *value)
{
	EjsProperty		*pp;
	EjsVar			*vp;

	pp = ejsCreateSimpleProperty(ep, obj, property);
	if (pp == 0) {
		mprAssert(pp);
		return 0;
	}
	vp = ejsGetVarPtr(pp);
	if (ejsWriteVar(ep, vp, value, EJS_SHALLOW_COPY) < 0) {
		mprAssert(0);
		return 0;
	}
	return ejsGetVarPtr(pp);
}

/******************************************************************************/
/*********************************** Constructors *****************************/
/******************************************************************************/
#if UNUSED
/*
 *	Object constructor. We don't use this for speed. Think very carefully if
 *	you add an object constructor.
 */

int ejsObjectConstructor(Ejs *ep, EjsVar *thisObj, int argc, EjsVar **argv)
{
	return 0;
}

#endif
/******************************************************************************/
/******************************** Visible Methods *****************************/
/******************************************************************************/

static int cloneMethod(Ejs *ep, EjsVar *thisObj, int argc, EjsVar **argv)
{
	int		copyDepth;

	copyDepth = EJS_DEEP_COPY;

	if (argc == 1 && ejsVarToBoolean(argv[0])) {
		copyDepth =  EJS_RECURSIVE_DEEP_COPY;
	}

	ejsWriteVar(ep, ep->result, thisObj, copyDepth);

	return 0;
}

/******************************************************************************/

static int toStringMethod(Ejs *ep, EjsVar *thisObj, int argc, EjsVar **argv)
{
	MprBuf	*bp;
	int		saveMaxDepth, saveDepth, saveFlags;

	saveMaxDepth = ep->maxDepth;

	if (argc >= 1) {
		ep->maxDepth = ejsVarToInteger(argv[0]);
	} else if (ep->maxDepth == 0) {
		ep->maxDepth = MAXINT;
	}

	saveFlags = ep->flags;
	if (argc >= 2) {
		if (ejsVarToBoolean(argv[1])) {
			ep->flags |= EJS_FLAGS_ENUM_HIDDEN;
		}
	}
	if (argc == 3) {
		if (ejsVarToBoolean(argv[2])) {
			ep->flags |= EJS_FLAGS_ENUM_BASE;
		}
	}

	bp = mprCreateBuf(ep, 0, 0);

	saveDepth = ep->depth;

	formatVar(ep, bp, thisObj);

	ep->depth = saveDepth;
	ep->maxDepth = saveMaxDepth;

	mprAddNullToBuf(bp);

	ejsWriteVarAsString(ep, ep->result, mprGetBufStart(bp));
	mprFree(bp);

	ep->flags = saveFlags;

	return 0;
}

/******************************************************************************/

static int valueOfMethod(Ejs *ep, EjsVar *thisObj, int argc, EjsVar **argv)
{
	if (argc != 0) {
		mprAssert(0);
		return -1;
	}

	switch (thisObj->type) {
	default:
	case EJS_TYPE_UNDEFINED:
	case EJS_TYPE_NULL:
	case EJS_TYPE_CMETHOD:
	case EJS_TYPE_OBJECT:
	case EJS_TYPE_METHOD:
	case EJS_TYPE_STRING_CMETHOD:
		ejsWriteVar(ep, ep->result, thisObj, EJS_SHALLOW_COPY);
		break;

	case EJS_TYPE_STRING:
		ejsWriteVarAsInteger(ep, ep->result, atoi(thisObj->string));
		break;

	case EJS_TYPE_BOOL:
	case EJS_TYPE_INT:
#if BLD_FEATURE_INT64
	case EJS_TYPE_INT64:
#endif
#if BLD_FEATURE_FLOATING_POINT
	case EJS_TYPE_FLOAT:
#endif
		ejsWriteVar(ep, ep->result, thisObj, EJS_SHALLOW_COPY);
		break;
	} 
	return 0;
}

/******************************************************************************/

static int hashGetAccessor(Ejs *ejs, EjsVar *thisObj, int argc, EjsVar **argv)
{
	ejsSetReturnValueToInteger(ejs, (int) thisObj->objectState);
	return 0;
}

/******************************************************************************/

static int classGetAccessor(Ejs *ejs, EjsVar *thisObj, int argc, EjsVar **argv)
{
	if (thisObj->objectState == 0 || thisObj->objectState->baseClass == 0) {
		ejsSetReturnValueToString(ejs, "object");
	} else {
		ejsSetReturnValueToString(ejs, 
			thisObj->objectState->baseClass->objectState->className);
	}
	return 0;
}

/******************************************************************************/
/*
 *	Format an object. Called recursively to format properties and contained 
 *	objects.
 */

static void formatVar(Ejs *ep, MprBuf *bp, EjsVar *vp)
{
	EjsProperty	*pp, *first;
	EjsVar		*propVar, *baseClass;
	char		*buf, *value;
	int			i;

	if (vp->type == EJS_TYPE_OBJECT) {
		if (!vp->objectState->visited) {

			mprPutStringToBuf(bp, vp->isArray ? "[\n" : "{\n");

			ep->depth++;
			vp->objectState->visited = 1;

			if (ep->depth <= ep->maxDepth) {
				first = ejsGetFirstProperty(vp, EJS_ENUM_ALL);

				if (ep->flags & EJS_FLAGS_ENUM_BASE) {
					baseClass = vp->objectState->baseClass;
					if (baseClass) {
						for (i = 0; i < ep->depth; i++) {
							mprPutStringToBuf(bp, "  ");
						}
						mprPutStringToBuf(bp, baseClass->objectState->objName);
						mprPutStringToBuf(bp, ": /* Base Class */ ");
						if (baseClass->objectState == vp->objectState) {
							value = "this";
						} else if (ejsRunMethodCmd(ep, baseClass, "toString", 
								"%d", ep->maxDepth) < 0) {
							value = "[object Object]";
						} else {
							mprAssert(ejsVarIsString(ep->result));
							value = ep->result->string;
						}
						mprPutStringToBuf(bp, value);
						if (first) {
							mprPutStringToBuf(bp, ",\n");
						}
					}
				}

				pp = first;
				while (pp) {
					if (! pp->dontEnumerate || 
							ep->flags & EJS_FLAGS_ENUM_HIDDEN) {
						for (i = 0; i < ep->depth; i++) {
							mprPutStringToBuf(bp, "  ");
						}

						if (! vp->isArray) {
							mprPutStringToBuf(bp, pp->name);
							mprPutStringToBuf(bp, ": ");
						}

						propVar = ejsGetVarPtr(pp);
						if (propVar->type == EJS_TYPE_OBJECT) {
							if (pp->var.objectState == vp->objectState) {
								value = "this";
							} else if (ejsRunMethodCmd(ep, propVar, 
									"toString", "%d", ep->maxDepth) < 0) {
								value = "[object Object]";
							} else {
								mprAssert(ejsVarIsString(ep->result));
								value = ep->result->string;
							}
							mprPutStringToBuf(bp, value);

						} else {
							formatVar(ep, bp, &pp->var);
						}

						pp = ejsGetNextProperty(pp, EJS_ENUM_ALL);
						if (pp) {
							mprPutStringToBuf(bp, ",\n");
						}
					} else {
						pp = ejsGetNextProperty(pp, EJS_ENUM_ALL);
					}
				}
			}
			vp->objectState->visited = 0;

			mprPutCharToBuf(bp, '\n');

			ep->depth--;
			for (i = 0; i < ep->depth; i++) {
				mprPutStringToBuf(bp, "  ");
			}
			mprPutCharToBuf(bp, vp->isArray ? ']' : '}');
		}

	} else if (vp->type == EJS_TYPE_METHOD) {

		mprPutStringToBuf(bp, "function (");
		for (i = 0; i < vp->method.args->length; i++) {
			mprPutStringToBuf(bp, vp->method.args->items[i]);
			if ((i + 1) < vp->method.args->length) {
				mprPutStringToBuf(bp, ", ");
			}
		}
		mprPutStringToBuf(bp, ") {");
		mprPutStringToBuf(bp, vp->method.body);
		for (i = 0; i < ep->depth; i++) {
			mprPutStringToBuf(bp, "  ");
		}
		mprPutStringToBuf(bp, "}");

	} else {

		if (vp->type == EJS_TYPE_STRING) {
			mprPutCharToBuf(bp, '\"');
		}

		/*
		 *	We don't use ejsVarToString for arrays, objects and strings.
		 *	This is because ejsVarToString does not call "obj.toString"
		 *	and it is not required for strings.
		 * 	MOB - rc
		 */
		buf = ejsVarToString(ep, vp);
		mprPutStringToBuf(bp, buf);

		if (vp->type == EJS_TYPE_STRING) {
			mprPutCharToBuf(bp, '\"');
		}
	}
}

/******************************************************************************/
/*
 *	mixin code. Blends code at the "thisObj" level.
 */ 

static int mixinMethod(Ejs *ep, EjsVar *thisObj, int argc, EjsVar **argv)
{
	EjsProperty	*pp;
	char		*buf;
	int			fid, i, rc;

	mprAssert(argv);

	/*
	 *	Create a variable scope block set to the current object
	 */
	rc = 0;
	fid = ejsSetBlock(ep, thisObj);

	for (i = 0; i < argc; i++) {

		if (ejsVarIsString(argv[i])) {
			rc = ejsEvalScript(ep, argv[i]->string, 0);

		}  else if (ejsVarIsObject(argv[i])) {

			/*	MOB -- OPT. When we have proper scope chains, we should just
			 	refer to the module and not copy */
			pp = ejsGetFirstProperty(argv[i], EJS_ENUM_ALL);
			while (pp) {
				ejsSetProperty(ep, thisObj, pp->name, ejsGetVarPtr(pp));
				pp = ejsGetNextProperty(pp, EJS_ENUM_ALL);
			}

		} else {
			/* MOB - rc */
			buf = ejsVarToString(ep, argv[i]);
			rc = ejsEvalScript(ep, buf, 0);

		}
		if (rc < 0) {
			ejsCloseBlock(ep, fid);
			return -1;
		}
	} 
	ejsCloseBlock(ep, fid);
	return 0;
}

/******************************************************************************/
/*
 *	Create the object class
 */

int ejsDefineObjectClass(Ejs *ep)
{
	EjsMethods	*methods;
	EjsProperty	*objectProp, *protoProp;
	EjsVar		*op, *globalClass;

	/*
	 *	Must specially hand-craft the object class as it is the base class
	 *	of all objects.
	 */
	op = ejsCreateObjVar(ep);
	if (op == 0) {
		return MPR_ERR_CANT_CREATE;
	}
	ejsSetClassName(ep, op, "Object");

	/*
	 *	Don't use a constructor for objects for speed
	 */
	ejsMakeClassNoConstructor(op);

	/*
	 *	MOB -- should mark properties as public / private and class or instance.
	 */
	ejsDefineCMethod(ep, op, "clone", cloneMethod, EJS_NO_LOCAL);
	ejsDefineCMethod(ep, op, "toString", toStringMethod, EJS_NO_LOCAL);
	ejsDefineCMethod(ep, op, "valueOf", valueOfMethod, EJS_NO_LOCAL);
	ejsDefineCMethod(ep, op, "mixin", mixinMethod, EJS_NO_LOCAL);

	ejsDefineCAccessors(ep, op, "hash", hashGetAccessor, 0, EJS_NO_LOCAL);
	ejsDefineCAccessors(ep, op, "baseClass", classGetAccessor, 0, EJS_NO_LOCAL);

	/*
	 *	MOB -- make this an accessor
	 */
	protoProp = ejsSetProperty(ep, op, "prototype", op);
	if (protoProp == 0) {
		ejsFreeVar(ep, op);
		return MPR_ERR_CANT_CREATE;
	}

	/*
	 *	Setup the internal methods. Most classes will never override these.
	 *	The XML class will. We rely on talloc to free internal. Use "ep" as
	 *	the parent as we need "methods" to live while the interpreter lives.
	 */
	methods = mprAllocTypeZeroed(ep, EjsMethods);
	op->objectState->methods = methods;

	methods->createProperty = createObjProperty;
	methods->deleteProperty = deleteObjProperty;
	methods->getProperty = getObjProperty;
	methods->setProperty = setObjProperty;

	objectProp = ejsSetPropertyAndFree(ep, ep->global, "Object", op);

	/*
	 *	Change the global class to use Object's methods 
	 */
	globalClass = ep->service->globalClass;
	globalClass->objectState->methods = methods;
	globalClass->objectState->baseClass = ejsGetVarPtr(protoProp);

	ep->objectClass = ejsGetVarPtr(objectProp);

	if (ejsObjHasErrors(ejsGetVarPtr(objectProp))) {
		ejsFreeVar(ep, op);
		return MPR_ERR_CANT_CREATE;
	}
	return 0;
}

/******************************************************************************/

#else
void ejsObjectDummy() {}

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
