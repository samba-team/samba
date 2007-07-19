/**
 *	@file 	ejsVar.c
 *	@brief 	Mbedthis Portable Runtime Universal Variable Type
 */

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

/******************************* Documentation ********************************/

/*
 *	This module is NOT multithreaded. 
 *
 *	Properties are variables that are stored in an object type variable.
 *	Properties can be primitive data types, other objects or methods.
 *	Properties are indexed by a character name.
 */

/********************************** Includes **********************************/

#include	"ejs.h"

/***************************** Forward Declarations ***************************/

static EjsProperty	*allocProperty(Ejs *ep, EjsVar *op, const char *property, 
						int propertyIndex, EjsProperty *last);
static EjsVar		*copyVar(EJS_LOC_DEC(ep, loc), EjsVar *dest, 
						const EjsVar *src, EjsCopyDepth copyDepth);
static EjsObj 		*createObj(EJS_LOC_DEC(ep, loc));
static char 		*getNextVarToken(char **next, char *tokBuf, int tokBufLen);
static int			hash(const char *property);
static void 		unlinkProperty(EjsObj *obj, EjsPropLink *propLink);
static void 		linkPropertyBefore(EjsObj *obj, EjsPropLink *at, 
						EjsPropLink *propLink);
static int 			sortAllProperties(Ejs *ep, EjsProperty *p1, 
						EjsProperty *p2, const char *propertyName, int order);
static int 			sortByProperty(Ejs *ep, EjsProperty *p1, EjsProperty *p2,
						const char *propertyName, int order);
static int 			dupString(MPR_LOC_DEC(ctx, loc), uchar **dest, 
						const void *src, int nbytes);
#if UNUSED && KEEP
static void 		linkPropertyAfter(EjsObj *obj, EjsPropLink *at, 
						EjsPropLink *propLink);
#endif

static EjsProperty 	*hashLookup(EjsObj *obj, const char *property, 
						int *propertyIndex, EjsProperty **hashTail);

/******************************************************************************/
/********************************** Var Routines ******************************/
/******************************************************************************/

EjsType ejsGetVarType(EjsVar *vp)
{
	mprAssert(vp);

	return vp->type;
}

/******************************************************************************/

void ejsFreeVar(Ejs *ep, EjsVar *vp)
{
	if (vp) {
		ejsClearVar(ep, vp);
		ejsFree(ep, vp, EJS_SLAB_VAR);
	}
}

/******************************************************************************/
#if UNUSED
/*
 *	Clear the value by freeing any allocated data. This will release objects
 *	so that later garbage collection can reclaim storage if there are no other
 *	object references.
 */

void ejsZeroVar(Ejs *ep, EjsVar *vp)
{
	vp->type = EJS_TYPE_UNDEFINED;
	vp->objectState = 0;
	vp->method.body = 0;
	vp->method.args = 0;
	vp->callsSuper = 0;
	vp->ptr.destructor = 0;
	vp->allocatedData = 0;
}

#endif
/******************************************************************************/
/*
 *	Clear the value by freeing any allocated data. This will release objects
 *	so that later garbage collection can reclaim storage if there are no other
 *	object references.
 */

void ejsClearVar(Ejs *ep, EjsVar *vp)
{
	MprArray	*argList;
	int			i;

	mprAssert(vp);
	mprAssert(ep);

	if (! vp->allocatedData) {
		vp->type = EJS_TYPE_UNDEFINED;
		return;
	}
	if (vp->type == EJS_TYPE_UNDEFINED) {
		return;
	}

	switch (vp->type) {
	default:
		break;

	case EJS_TYPE_STRING:
		mprFree(vp->string);
		vp->string = 0;
		break;

	case EJS_TYPE_OBJECT:
		/* 
 		 *	Set the "alive" bit so that the GC will cleanup if no 
		 *	other references.
		 */
		if (vp->objectState) {
			vp->objectState->alive = 1;
		}
		vp->objectState = 0;
		break;

	case EJS_TYPE_METHOD:
		argList = vp->method.args;
		/* 
		 *	MOB OPT -- should be able to do just one mprFree(vp->method.args)
		 */
		mprFree(vp->method.body);
		if (argList) {
			for (i = 0; i < argList->length; i++) {
				mprFree(argList->items[i]);
			}
			mprFree(vp->method.args);
		}
		vp->method.args = 0;
		vp->method.body = 0;
		vp->callsSuper = 0;
		break;

	case EJS_TYPE_PTR:
		if (vp->ptr.destructor) {
			(vp->ptr.destructor)(ep, vp);
		}
		break;
	}

	vp->type = EJS_TYPE_UNDEFINED;
	vp->allocatedData = 0;
}

/******************************************************************************/
/*
 *	Initialize an undefined value.
 */

EjsVar *ejsCreateUndefinedVar(Ejs *ep)
{
	EjsVar	*vp;

	mprAssert(ep);

	vp = ejsAllocVar(EJS_LOC_ARGS(ep));
	if (vp) {
		vp->type = EJS_TYPE_UNDEFINED;
	}
	return vp;
}

/******************************************************************************/
/*
 *	Initialize an null value.
 */

EjsVar *ejsCreateNullVar(Ejs *ep)
{
	EjsVar	*vp;

	mprAssert(ep);

	vp = ejsAllocVar(EJS_LOC_ARGS(ep));
	if (vp) {
		vp->type = EJS_TYPE_NULL;
	}
	return vp;
}

/******************************************************************************/

EjsVar *ejsCreateBoolVar(Ejs *ep, int value)
{
	EjsVar	*vp;

	mprAssert(ep);

	vp = ejsAllocVar(EJS_LOC_ARGS(ep));
	if (vp) {
		vp->type = EJS_TYPE_BOOL;
		vp->boolean = value;
	}
	return vp;
}

/******************************************************************************/
/*
 *	Initialize a C method.
 */

EjsVar *ejsCreateCMethodVar(Ejs *ep, EjsCMethod fn, void *userData, int flags)
{
	EjsVar	*vp;

	mprAssert(ep);

	vp = ejsAllocVar(EJS_LOC_ARGS(ep));
	if (vp) {
		vp->type = EJS_TYPE_CMETHOD;
		vp->cMethod.fn = fn;
		vp->cMethod.userData = userData;
		vp->flags = flags;
	}
	return vp;
}

/******************************************************************************/
/*
 *	Initialize a C method.
 */

EjsVar *ejsCreateStringCMethodVar(Ejs *ep, EjsStringCMethod fn, 
	void *userData, int flags)
{
	EjsVar	*vp;

	mprAssert(ep);
	mprAssert(fn);

	vp = ejsAllocVar(EJS_LOC_ARGS(ep));
	if (vp) {
		vp->type = EJS_TYPE_STRING_CMETHOD;
		vp->cMethodWithStrings.fn = fn;
		vp->cMethodWithStrings.userData = userData;
		vp->flags = flags;
	}
	return vp;
}

/******************************************************************************/
/*
 *	Initialize an opaque pointer. 
 */

EjsVar *ejsCreatePtrVar(Ejs *ep, void *ptr, EjsDestructor destructor)
{
	EjsVar	*vp;

	mprAssert(ep);
	mprAssert(ptr);

	vp = ejsAllocVar(EJS_LOC_ARGS(ep));
	if (vp) {
		vp->type = EJS_TYPE_PTR;
		vp->ptr.userPtr = ptr;
		vp->ptr.destructor = destructor;
		vp->allocatedData = 1;
	}
	return vp;
}

/******************************************************************************/
#if BLD_FEATURE_FLOATING_POINT
/*
 *	Initialize a floating value.
 */

EjsVar *ejsCreateFloatVar(Ejs *ep, double value)
{
	EjsVar	*vp;

	mprAssert(ep);

	vp = ejsAllocVar(EJS_LOC_ARGS(ep));
	if (vp) {
		vp->type = EJS_TYPE_FLOAT;
		vp->floating = value;
	}
	return vp;
}

#endif
/******************************************************************************/
/*
 *	Initialize an integer value.
 */

EjsVar *ejsCreateIntegerVar(Ejs *ep, int value)
{
	EjsVar	*vp;

	mprAssert(ep);

	vp = ejsAllocVar(EJS_LOC_ARGS(ep));
	if (vp) {
		vp->type = EJS_TYPE_INT;
		vp->integer = value;
	}
	return vp;
}

/******************************************************************************/
#if BLD_FEATURE_INT64
/*
 *	Initialize a 64-bit integer value.
 */

EjsVar *ejsCreateInteger64Var(Ejs *ep, int64 value)
{
	EjsVar	*vp;

	mprAssert(ep);

	vp = ejsAllocVar(EJS_LOC_ARGS(ep));
	if (vp) {
		vp->type = EJS_TYPE_INT64;
		vp->integer64 = value;
	}
	return vp;
}

#endif /* BLD_FEATURE_INT64 */
/******************************************************************************/
/*
 *	Initialize an number variable. Type is defined by configure.
 */

EjsVar *ejsCreateNumberVar(Ejs *ep, EjsNum value)
{
	EjsVar	*vp;

	mprAssert(ep);

	vp = ejsAllocVar(EJS_LOC_ARGS(ep));
	mprAssert(vp);

	if (vp) {
		vp->type = BLD_FEATURE_NUM_TYPE_ID;
#if   BLD_FEATURE_NUM_TYPE_ID == EJS_TYPE_INT64
		vp->integer64 = value;
#elif BLD_FEATURE_NUM_TYPE_ID == EJS_TYPE_FLOAT
		vp->float = value;
#else
		vp->integer = value;
#endif
	}
	return vp;
}

/******************************************************************************/
/*
 *	Initialize a (bare) JavaScript method. args and body can be null.
 */

EjsVar *ejsCreateMethodVar(Ejs *ep, const char *body, MprArray *args, int flags)
{
	EjsVar	*vp;
	int		i;

	mprAssert(ep);

	vp = ejsAllocVar(EJS_LOC_ARGS(ep));
	mprAssert(vp);

	if (vp == 0) {
		return 0;
	}

	vp->type = EJS_TYPE_METHOD;

	vp->allocatedData = 1;

	vp->method.args = mprCreateItemArray(ep, EJS_INC_ARGS, EJS_MAX_ARGS);
	if (vp->method.args == 0) {
		mprAssert(vp->method.args);
		ejsFreeVar(ep, vp);
		return 0;
	}

	if (args) {
		for (i = 0; i < args->length; i++) {
			mprAddItem(vp->method.args, 
				mprStrdup(vp->method.args, mprGetItem(args, i)));
		}
	}
	vp->method.body = mprStrdup(vp->method.args, body);

	if (vp->method.body == 0) {
		ejsFreeVar(ep, vp);
		return 0;
	}
	vp->flags = flags;

	return vp;
}

/******************************************************************************/
/*
 *	Initialize an object variable. 
 */

EjsVar *ejsCreateObjVarInternal(EJS_LOC_DEC(ep, loc))
{
	EjsVar		*vp;

	mprAssert(ep);

	vp = ejsAllocVar(EJS_LOC_PASS(ep, loc));
	mprAssert(vp);

	if (vp) {
		vp->type = EJS_TYPE_OBJECT;
		vp->objectState = createObj(EJS_LOC_PASS(ep, loc));
		if (vp->objectState == 0) {
			ejsFreeVar(ep, vp);
			return 0;
		}
		vp->allocatedData = 1;
	}
	return vp;
}

/******************************************************************************/
/*
 *	Initialize a string value.
 */

EjsVar *ejsCreateStringVarInternal(EJS_LOC_DEC(ep, loc), const char *value)
{
	EjsVar	*vp;

	mprAssert(ep);

	vp = ejsAllocVar(EJS_LOC_PASS(ep, loc));
	mprAssert(vp);

	if (vp) {
		vp->type = EJS_TYPE_STRING;
		vp->string = mprStrdupInternal(EJS_LOC_PASS(ep, loc), value);
		if (vp->string == 0) {
			ejsFreeVar(ep, vp);
			return 0;
		}
		vp->length = strlen(vp->string);
		vp->allocatedData = 1;
	}
	return vp;
}

/******************************************************************************/
/*
 *	Initialize a binary string value.
 */

EjsVar *ejsCreateBinaryStringVar(Ejs *ep, const uchar *value, int len)
{
	EjsVar	*vp;

	mprAssert(ep);

	vp = ejsAllocVar(EJS_LOC_ARGS(ep));
	if (vp) {
		vp->type = EJS_TYPE_STRING;
		vp->length = dupString(MPR_LOC_ARGS(ep), &vp->ustring, value, len);
		if (vp->length < 0) {
			ejsFreeVar(ep, vp);
			return 0;
		}
		vp->allocatedData = 1;
	}
	return vp;
}

/******************************************************************************/

void ejsSetClassName(Ejs *ep, EjsVar *vp, const char *name)
{
	EjsObj	*obj;

	if (vp == 0 || !ejsVarIsObject(vp) || vp->objectState == 0) {
		mprAssert(0);
		return;
	}
	obj = vp->objectState;

	if (obj->className) {
		mprFree(obj->className);
	}
	obj->className = mprStrdup(ep, name);
}

/******************************************************************************/

EjsVar *ejsDupVarInternal(EJS_LOC_DEC(ep, loc), EjsVar *src, 
	EjsCopyDepth copyDepth)
{
	EjsVar	*vp;

	vp = ejsAllocVar(EJS_LOC_PASS(ep, loc));
	if (vp == 0) {
		return 0;
	}

	vp->type = EJS_TYPE_UNDEFINED;

	return copyVar(EJS_LOC_PASS(ep, loc), vp, src, copyDepth);
}

/******************************************************************************/
/*
 *	Set a var to a new value
 */

EjsVar *ejsWriteVarInternal(EJS_LOC_DEC(ep, loc), EjsVar *dest, 
	const EjsVar *src, EjsCopyDepth copyDepth)
{
	mprAssert(dest);
	mprAssert(src);

	return copyVar(EJS_LOC_PASS(ep, loc), dest, src, copyDepth);
}

/******************************************************************************/
/*
 *	Set a var using a new bool value
 */

EjsVar *ejsWriteVarAsBoolean(Ejs *ep, EjsVar *dest, int value)
{
	mprAssert(dest);

	if (dest->type != EJS_TYPE_UNDEFINED) {
		ejsClearVar(ep, dest);
	}

	dest->type = EJS_TYPE_BOOL;
	dest->boolean = value;
	dest->allocatedData = 0;
	dest->flags = 0;

	return dest;
}

/******************************************************************************/
/*
 *	Set a var using a new C Method
 */

EjsVar *ejsWriteVarAsCMethod(Ejs *ep, EjsVar *dest, EjsCMethod fn, 
	void *userData, int flags)
{
	mprAssert(dest);

	if (dest->type != EJS_TYPE_UNDEFINED) {
		ejsClearVar(ep, dest);
	}

	dest->type = EJS_TYPE_CMETHOD;
	dest->cMethod.fn = fn;
	dest->cMethod.userData = userData;
	dest->flags = flags;
	dest->allocatedData = 0;

	return dest;
}

/******************************************************************************/
#if BLD_FEATURE_FLOATING_POINT
/*
 *	Set a var using a new float value
 */

EjsVar *ejsWriteVarAsFloat(Ejs *ep, EjsVar *dest, double value)
{
	mprAssert(dest);

	if (dest->type != EJS_TYPE_UNDEFINED) {
		ejsClearVar(ep, dest);
	}

	dest->type = EJS_TYPE_FLOAT;
	dest->floating = value;
	dest->allocatedData = 0;
	dest->flags = 0;

	return dest;
}

#endif
/******************************************************************************/
/*
 *	Set a var using a new integer value
 */

EjsVar *ejsWriteVarAsInteger(Ejs *ep, EjsVar *dest, int value)
{
	mprAssert(dest);

	if (dest->type != EJS_TYPE_UNDEFINED) {
		ejsClearVar(ep, dest);
	}

	dest->type = EJS_TYPE_INT;
	dest->integer = value;
	dest->allocatedData = 0;
	dest->flags = 0;

	return dest;
}

/******************************************************************************/
#if BLD_FEATURE_INT64
/*
 *	Set a var using a new integer value
 */

EjsVar *ejsWriteVarAsInteger64(Ejs *ep, EjsVar *dest, int64 value)
{
	mprAssert(dest);

	if (dest->type != EJS_TYPE_UNDEFINED) {
		ejsClearVar(ep, dest);
	}

	dest->type = EJS_TYPE_INT64;
	dest->integer64 = value;
	dest->allocatedData = 0;
	dest->flags = 0;

	return dest;
}

#endif
/******************************************************************************/
/*
 *	Set a var using a new Method
 */

EjsVar *ejsWriteVarAsMethod(Ejs *ep, EjsVar *dest, const char *body,
	MprArray *args)
{
	EjsVar		**srcArgs, *arg;
	int			i;

	mprAssert(ep);
	mprAssert(dest);
	mprAssert(body);

	if (dest->type != EJS_TYPE_UNDEFINED) {
		ejsClearVar(ep, dest);
	}

	dest->method.args = mprCreateItemArray(ep, EJS_INC_ARGS, EJS_MAX_ARGS);
	if (dest->method.args == 0) {
		return 0;
	}

	dest->type = EJS_TYPE_METHOD;

	if (args) {
		srcArgs = (EjsVar**) args->items;
		for (i = 0; i < args->length; i++) {
			arg = ejsDupVar(ep, srcArgs[i], EJS_SHALLOW_COPY);
			if (arg == 0) {
				return 0;
			}
			if (mprAddItem(dest->method.args, arg) < 0) {
				return 0;
			}
		}
	}

	dest->method.body = mprStrdup(dest->method.args, body);
	if (dest->method.body == 0) {
		return 0;
	}

	dest->allocatedData = 1;
	dest->flags = 0;

	return dest;
}

/******************************************************************************/
/*
 *	Set a var to null
 */

EjsVar *ejsWriteVarAsNull(Ejs *ep, EjsVar *dest)
{
	mprAssert(dest);

	if (dest->type != EJS_TYPE_UNDEFINED) {
		ejsClearVar(ep, dest);
	}

	dest->type = EJS_TYPE_NULL;
	dest->allocatedData = 0;
	dest->flags = 0;

	return dest;
}

/******************************************************************************/
/*
 *	Set a var using a new number value
 */

EjsVar *ejsWriteVarAsNumber(Ejs *ep, EjsVar *dest, EjsNum value)
{
	mprAssert(dest);

	if (dest->type != EJS_TYPE_UNDEFINED) {
		ejsClearVar(ep, dest);
	}

	dest->type = EJS_NUM_VAR;
	dest->ejsNumber = value;
	dest->allocatedData = 0;
	dest->flags = 0;

	return dest;
}

/******************************************************************************/
/*
 *	Set a var using a new C Method
 */

EjsVar *ejsWriteVarAsStringCMethod(Ejs *ep, EjsVar *dest, EjsStringCMethod fn, 
	void *userData, int flags)
{
	mprAssert(dest);

	if (dest->type != EJS_TYPE_UNDEFINED) {
		ejsClearVar(ep, dest);
	}

	dest->type = EJS_TYPE_CMETHOD;
	dest->cMethodWithStrings.fn = fn;
	dest->cMethodWithStrings.userData = userData;
	dest->flags = flags;
	dest->allocatedData = 0;

	return dest;
}

/******************************************************************************/
/*
 *	Set a var using a new string value
 */

EjsVar *ejsWriteVarAsStringInternal(EJS_LOC_DEC(ep, loc), EjsVar *dest, 
	const char *value)
{
	mprAssert(dest);
	mprAssert(value);

	if (dest->type != EJS_TYPE_UNDEFINED) {
		ejsClearVar(ep, dest);
	}

	dest->string = mprStrdupInternal(EJS_LOC_PASS(ep, loc), value);
	if (dest->string == 0) {
		return 0;
	}

	dest->length = strlen(dest->string);

	dest->type = EJS_TYPE_STRING;
	dest->allocatedData = 1;
	dest->flags = 0;

	return dest;
}

/******************************************************************************/
/*
 *	Set a var using a new string value
 */

EjsVar *ejsWriteVarAsBinaryString(Ejs *ep, EjsVar *dest, const uchar *value,
	int len)
{
	mprAssert(dest);
	mprAssert(value);

	ejsClearVar(ep, dest);

	if (dest->type != EJS_TYPE_UNDEFINED) {
		ejsClearVar(ep, dest);
	}

	dest->length = dupString(MPR_LOC_ARGS(ep), &dest->ustring, value, len);
	if (dest->length < 0) {
		return 0;
	}

	dest->type = EJS_TYPE_STRING;
	dest->allocatedData = 1;
	dest->flags = 0;

	return dest;
}

/******************************************************************************/
/*
 *	Set a var to undefined
 */

EjsVar *ejsWriteVarAsUndefined(Ejs *ep, EjsVar *dest)
{
	mprAssert(dest);

	if (dest->type != EJS_TYPE_UNDEFINED) {
		ejsClearVar(ep, dest);
	}

	dest->type = EJS_TYPE_UNDEFINED;
	dest->allocatedData = 0;
	dest->flags = 0;

	return dest;
}

/******************************************************************************/
/*
 *	Convert a value to a text based representation of its value
 *	If you provide a format, you MUST ensure you know the type.
 *	Caller must free the result.
 */

char *ejsFormatVar(Ejs *ep, const char *fmt, EjsVar *vp)
{
	char	*buf, *src, *value, *allocValue;
	uchar	*ubuf;
	int		len;

	buf = 0;
	allocValue = 0;
	value = 0;

	switch (vp->type) {
	case EJS_TYPE_UNDEFINED:
		value = "undefined";
		break;

	case EJS_TYPE_NULL:
		value = "null";
		break;

	case EJS_TYPE_PTR:
		if (fmt == NULL || *fmt == '\0') {
			len = mprAllocSprintf(MPR_LOC_ARGS(ep), &buf, 0, 
				"[Opaque Pointer %p]", vp->ptr.userPtr);
		} else {
			len = mprAllocSprintf(MPR_LOC_ARGS(ep), &buf, 0, fmt, vp->ptr);
		}
		goto done;

	case EJS_TYPE_BOOL:
		value = (vp->boolean) ? "true" : "false";
		break;

#if BLD_FEATURE_FLOATING_POINT
	case EJS_TYPE_FLOAT:
		if (fmt == NULL || *fmt == '\0') {
			fmt = "%f";
		}
		len = mprAllocSprintf(MPR_LOC_ARGS(ep), &buf, 0, fmt, vp->floating);
		goto done;
#endif

	case EJS_TYPE_INT:
		if (fmt == NULL || *fmt == '\0') {
			fmt = "%d";
		}
		mprAllocSprintf(MPR_LOC_ARGS(ep), &buf, 0, fmt, vp->integer);
		goto done;

#if BLD_FEATURE_INT64
	case EJS_TYPE_INT64:
		if (fmt == NULL || *fmt == '\0') {
			fmt = "%Ld";
		}
		mprAllocSprintf(MPR_LOC_ARGS(ep), &buf, 0, fmt, vp->integer64);
		goto done;
#endif

	case EJS_TYPE_CMETHOD:
		value = "[C Method]";
		break;

	case EJS_TYPE_STRING_CMETHOD:
		value = "[C StringMethod]";
		break;

	case EJS_TYPE_METHOD:
		value = ejsVarToString(ep, vp);
		break;

	case EJS_TYPE_OBJECT:
		value = ejsVarToString(ep, vp);
		break;

	case EJS_TYPE_STRING:
		src = vp->string;
		mprAssert(src);

		if (fmt && *fmt && src) {
			mprAllocSprintf(MPR_LOC_ARGS(ep), &buf, 0, fmt, src);

		} else if (src == NULL) {
			buf = mprStrdup(ep, "null");

		} else {
			ubuf = (uchar*) buf;
			if (dupString(MPR_LOC_ARGS(ep), &ubuf, src, vp->length) < 0) {
				return mprStrdup(ep, "");
			}
			buf = (char*) ubuf;
		}
		break;

	default:
		mprAssert(0);
	}

	if (fmt == NULL || *fmt == '\0') {
		len = mprAllocSprintf(MPR_LOC_ARGS(ep), &buf, 0, "%s", value);
	} else {
		len = mprAllocSprintf(MPR_LOC_ARGS(ep), &buf, 0, fmt, value);
	}

done:
	if (allocValue) {
		mprFree(allocValue);
	}
	return buf;
}

/******************************************************************************/
/*
 *	Convert the variable to a boolean. Only for primitive types.
 */

int ejsVarToBoolean(EjsVar *vp)
{
	mprAssert(vp);

	switch (vp->type) {
	case EJS_TYPE_UNDEFINED:
	case EJS_TYPE_NULL:
	case EJS_TYPE_STRING_CMETHOD:
	case EJS_TYPE_CMETHOD:
	case EJS_TYPE_METHOD:
		return 0;

	case EJS_TYPE_OBJECT:
		return (vp->objectState != NULL);

	case EJS_TYPE_PTR:
		return (vp->ptr.userPtr != NULL);

	case EJS_TYPE_BOOL:
		return vp->boolean;

#if BLD_FEATURE_FLOATING_POINT
	case EJS_TYPE_FLOAT:
		return (vp->floating != 0 && !ejsIsNan(vp->floating));
#endif

	case EJS_TYPE_INT:
		return (vp->integer != 0);

#if BLD_FEATURE_INT64
	case EJS_TYPE_INT64:
		return (vp->integer64 != 0);
#endif

	case EJS_TYPE_STRING:
		return (vp->length > 0);
#if UNUSED
		if (strcmp(vp->string, "true") == 0 || 
				strcmp(vp->string, "TRUE") == 0) {
			return 1;

		} else if (strcmp(vp->string, "false") == 0 || 
				strcmp(vp->string, "FALSE") == 0) {
			return 0;

		} else {
			return atoi(vp->string);
		}
#endif
	}

	/* Not reached */
	return 0;
}

/******************************************************************************/
#if BLD_FEATURE_FLOATING_POINT
/*
 *	Convert the variable to a floating point number. Only for primitive types.
 */

double ejsVarToFloat(EjsVar *vp)
{
	mprAssert(vp);

	switch (vp->type) {
	case EJS_TYPE_UNDEFINED:
	case EJS_TYPE_NULL:
	case EJS_TYPE_STRING_CMETHOD:
	case EJS_TYPE_CMETHOD:
	case EJS_TYPE_METHOD:
	case EJS_TYPE_OBJECT:
	case EJS_TYPE_PTR:
		return 0;

	case EJS_TYPE_BOOL:
		return (vp->boolean) ? 1.0 : 0.0;

	case EJS_TYPE_FLOAT:
		return vp->floating;

	case EJS_TYPE_INT:
		return (double) vp->integer;

#if BLD_FEATURE_INT64
	case EJS_TYPE_INT64:
		return (double) vp->integer64;
#endif

	case EJS_TYPE_STRING:
		if (vp->length == 0) {
			return 0.0;
		} else {
			return atof(vp->string);
		}
	}

	/* Not reached */
	return 0;
}

#endif
/******************************************************************************/
/*
 *	Convert the variable to an Integer type. Only works for primitive types.
 */

int ejsVarToInteger(EjsVar *vp)
{
	mprAssert(vp);

	switch (vp->type) {
	case EJS_TYPE_UNDEFINED:
	case EJS_TYPE_NULL:
	case EJS_TYPE_STRING_CMETHOD:
	case EJS_TYPE_CMETHOD:
	case EJS_TYPE_METHOD:
	case EJS_TYPE_OBJECT:
		return 0;

	case EJS_TYPE_BOOL:
		return (vp->boolean) ? 1 : 0;

#if BLD_FEATURE_FLOATING_POINT
	case EJS_TYPE_FLOAT:
		if (ejsIsNan(vp->floating)) {
			return 0;
		}
		return (int) vp->floating;
#endif

	case EJS_TYPE_INT:
		return vp->integer;

#if BLD_FEATURE_INT64
	case EJS_TYPE_INT64:
		return (int) vp->integer64;
#endif

	case EJS_TYPE_STRING:
		if (vp->length == 0) {
			return 0;
		} else {
			return ejsParseInteger(vp->string);
		}
	}

	/* Not reached */
	return 0;
}

/******************************************************************************/
#if BLD_FEATURE_INT64
/*
 *	Convert the variable to an Integer64 type. Only works for primitive types.
 */

int64 ejsVarToInteger64(EjsVar *vp)
{
	mprAssert(vp);

	switch (vp->type) {
	case EJS_TYPE_UNDEFINED:
	case EJS_TYPE_NULL:
	case EJS_TYPE_STRING_CMETHOD:
	case EJS_TYPE_CMETHOD:
	case EJS_TYPE_METHOD:
	case EJS_TYPE_OBJECT:
	case EJS_TYPE_PTR:
		return 0;

	case EJS_TYPE_BOOL:
		return (vp->boolean) ? 1 : 0;

#if BLD_FEATURE_FLOATING_POINT
	case EJS_TYPE_FLOAT:
		if (ejsIsNan(vp->floating)) {
			return 0;
		}
		return (int64) vp->floating;
#endif

	case EJS_TYPE_INT:
		return vp->integer;

	case EJS_TYPE_INT64:
		return vp->integer64;

	case EJS_TYPE_STRING:
		if (vp->length == 0) {
			return 0;
		} else {
			return ejsParseInteger64(vp->string);
		}
	}

	/* Not reached */
	return 0;
}

#endif /* BLD_FEATURE_INT64 */
/******************************************************************************/
/*
 *	Convert the variable to a number type. Only works for primitive types.
 */

EjsNum ejsVarToNumber(EjsVar *vp)
{
#if BLD_FEATURE_NUM_TYPE_ID == EJS_TYPE_INT64
	return ejsVarToInteger64(vp);
#elif BLD_FEATURE_NUM_TYPE_ID == EJS_TYPE_FLOAT
	return ejsVarToFloat(vp);
#else 
	return ejsVarToInteger(vp);
#endif
}

/******************************************************************************/
/*
 *	Convert a var to a string. Store the result in ep->castTemp. If allocated
 *	set ep->castAlloc to TRUE. Caller must NOT free the result.
 */

char *ejsVarToString(Ejs *ep, EjsVar *vp)
{
	MprBuf	*bp;
	char	numBuf[16];
	int		len, i;

	if (ep->castAlloc) {
		mprFree(ep->castTemp);
	}
	ep->castTemp = 0;
	ep->castAlloc = 0;

	switch (vp->type) {
	case EJS_TYPE_UNDEFINED:
		ep->castTemp = "undefined";
		break;

	case EJS_TYPE_NULL:
		ep->castTemp = "null";
		break;

	case EJS_TYPE_PTR:
		len = mprAllocSprintf(MPR_LOC_ARGS(ep), &ep->castTemp, 0, 
			"[Opaque Pointer %p]", vp->ptr.userPtr);
		ep->castAlloc = 1;
		break;

	case EJS_TYPE_BOOL:
		if (vp->boolean) {
			ep->castTemp = "true";
		} else {
			ep->castTemp = "false";
		}
		break;

#if BLD_FEATURE_FLOATING_POINT
	case EJS_TYPE_FLOAT:
		len = mprAllocSprintf(MPR_LOC_ARGS(ep), &ep->castTemp, 0, 
			"%f", vp->floating);
		ep->castAlloc = 1;
		break;
#endif

	case EJS_TYPE_INT:
		mprItoa(numBuf, sizeof(numBuf), vp->integer);
		ep->castTemp = mprStrdup(ep, numBuf);
		ep->castAlloc = 1;
		break;

#if BLD_FEATURE_INT64
	case EJS_TYPE_INT64:
		mprAllocSprintf(MPR_LOC_ARGS(ep), &ep->castTemp, 0, 
			"%Ld", vp->integer64);
		ep->castAlloc = 1;
		break;
#endif

	case EJS_TYPE_CMETHOD:
		ep->castTemp = "[C Method]";
		break;

	case EJS_TYPE_STRING_CMETHOD:
		ep->castTemp = "[C StringMethod]";
		break;

	case EJS_TYPE_METHOD:
		bp = mprCreateBuf(ep, 0, 0);
		mprPutStringToBuf(bp, "function (");
		for (i = 0; i < vp->method.args->length; i++) {
			mprPutStringToBuf(bp, vp->method.args->items[i]);
			if ((i + 1) < vp->method.args->length) {
				mprPutStringToBuf(bp, ", ");
			}
		}
		mprPutStringToBuf(bp, ") {");
		mprPutStringToBuf(bp, vp->method.body);
		mprPutStringToBuf(bp, "}");
		mprAddNullToBuf(bp);
		ep->castTemp = mprStealBuf(ep, bp);
		ep->castAlloc = 1;
		mprFree(bp);
		break;

	case EJS_TYPE_OBJECT:
		if (ejsRunMethod(ep, vp, "toString", 0) < 0) {
			return mprStrdup(ep, "[object Object]");
		}
		ep->castTemp = mprStrdup(ep, ep->result->string);
		ep->castAlloc = 1;
		break;

	case EJS_TYPE_STRING:
		if (vp->string == 0) {
			ep->castTemp = "null";
		} else {
			ep->castTemp = vp->string;
		}
		break;

	default:
		mprAssert(0);
	}

	mprAssert(ep->castTemp);
	return ep->castTemp;
}

/******************************************************************************/

char *ejsVarToStringEx(Ejs *ep, EjsVar *vp, bool *alloc)
{
	char	*str;

	mprAssert(alloc);

	str = ejsVarToString(ep, vp);
	*alloc = ep->castAlloc;
	ep->castAlloc = 0;
	ep->castTemp = 0;
	return str;
}

/******************************************************************************/
/*
 *	Parse a string based on formatting instructions and intelligently 
 *	create a variable.
 *
 *	Float format: [+|-]DIGITS][DIGITS][(e|E)[+|-]DIGITS]
 */

EjsVar *ejsParseVar(Ejs *ep, const char *buf, EjsType preferredType)
{
	EjsType			type;
	const char		*cp;
	int				isHex;

	mprAssert(buf);

	type = preferredType;

	if (preferredType == EJS_TYPE_UNDEFINED) {
		isHex = 0;
		if (*buf == '-' || *buf == '+') {
			type = EJS_NUM_VAR;

		} else if (!isdigit((int) *buf)) {
			if (strcmp(buf, "true") == 0 || strcmp(buf, "false") == 0) {
				type = EJS_TYPE_BOOL;
			} else {
				type = EJS_TYPE_STRING;
			}

		} else if (isdigit((int) *buf)) {
			type = EJS_NUM_VAR;
			cp = buf;
			if (*cp && tolower(cp[1]) == 'x') {
				cp = &cp[2];
				isHex = 1;
				for (cp = buf; *cp; cp++) {
					if (! isxdigit((int) *cp)) {
						break;
					}
				}
			} else {
#if BLD_FEATURE_FLOATING_POINT
				/* Could be integer or float */
				for (cp = buf; *cp; cp++) {
					if (! isdigit((int) *cp)) {
						int c = tolower(*cp);
						if (c == '.' || c == 'e' || c == 'f') {
							type = EJS_TYPE_FLOAT;
							break;
						}
					}
				}
#endif
			}
		}
	}

	switch (type) {
	case EJS_TYPE_OBJECT:
	case EJS_TYPE_UNDEFINED:
	case EJS_TYPE_NULL:
	case EJS_TYPE_PTR:
	default:
		break;

	case EJS_TYPE_BOOL:
		return ejsCreateBoolVar(ep, ejsParseBoolean(buf));

	case EJS_TYPE_INT:
		return ejsCreateIntegerVar(ep, ejsParseInteger(buf));

#if BLD_FEATURE_INT64
	case EJS_TYPE_INT64:
		return ejsCreateInteger64Var(ep, ejsParseInteger64(buf));
#endif

	case EJS_TYPE_STRING:
		if (strcmp(buf, "null") == 0) {
			return ejsCreateNullVar(ep);

		} else if (strcmp(buf, "undefined") == 0) {
			return ejsCreateUndefinedVar(ep);
		} 
			
		return ejsCreateStringVar(ep, buf);

#if BLD_FEATURE_FLOATING_POINT
	case EJS_TYPE_FLOAT:
		return ejsCreateFloatVar(ep, atof(buf));
#endif

	}
	return ejsCreateUndefinedVar(ep);
}

/******************************************************************************/
/*
 *	Convert the variable to a number type. Only works for primitive types.
 */

bool ejsParseBoolean(const char *s)
{
	if (s == 0 || *s == '\0') {
		return 0;
	}
	if (strcmp(s, "false") == 0 || strcmp(s, "FALSE") == 0) {
		return 0;
	}
	return 1;
}

/******************************************************************************/
/*
 *	Convert the variable to a number type. Only works for primitive types.
 */

EjsNum ejsParseNumber(const char *s)
{
#if BLD_FEATURE_NUM_TYPE_ID == EJS_TYPE_INT64
	return ejsParseInteger64(s);
#elif BLD_FEATURE_NUM_TYPE_ID == EJS_TYPE_FLOAT
	return ejsParseFloat(s);
#else 
	return ejsParseInteger(s);
#endif
}

/******************************************************************************/
#if BLD_FEATURE_INT64
/*
 *	Convert the string buffer to an Integer64.
 */

int64 ejsParseInteger64(const char *str)
{
	const char	*cp;
	int64		num64;
	int			radix, c, negative;

	mprAssert(str);

	cp = str;
	num64 = 0;
	negative = 0;

	if (*cp == '-') {
		cp++;
		negative = 1;
	} else if (*cp == '+') {
		cp++;
	}

	/*
	 *	Parse a number. Observe hex and octal prefixes (0x, 0)
	 */
	if (*cp != '0') {
		/* 
		 *	Normal numbers (Radix 10)
		 */
		while (isdigit((int) *cp)) {
			num64 = (*cp - '0') + (num64 * 10);
			cp++;
		}
	} else {
		cp++;
		if (tolower(*cp) == 'x') {
			cp++;
			radix = 16;
			while (*cp) {
				c = tolower(*cp);
				if (isdigit(c)) {
					num64 = (c - '0') + (num64 * radix);
				} else if (c >= 'a' && c <= 'f') {
					num64 = (c - 'a' + 10) + (num64 * radix);
				} else {
					break;
				}
				cp++;
			}

		} else{
			radix = 8;
			while (*cp) {
				c = tolower(*cp);
				if (isdigit(c) && c < '8') {
					num64 = (c - '0') + (num64 * radix);
				} else {
					break;
				}
				cp++;
			}
		}
	}

	if (negative) {
		return 0 - num64;
	}
	return num64;
}

#endif /* BLD_FEATURE_INT64 */
/******************************************************************************/
/*
 *	Convert the string buffer to an Integer.
 */

int ejsParseInteger(const char *str)
{
	const char	*cp;
	int			num;
	int			radix, c, negative;

	mprAssert(str);

	cp = str;
	num = 0;
	negative = 0;

	if (*cp == '-') {
		cp++;
		negative = 1;
	} else if (*cp == '+') {
		cp++;
	}

	/*
	 *	Parse a number. Observe hex and octal prefixes (0x, 0)
	 */
	if (*cp != '0') {
		/* 
		 *	Normal numbers (Radix 10)
		 */
		while (isdigit((int) *cp)) {
			num = (*cp - '0') + (num * 10);
			cp++;
		}
	} else {
		cp++;
		if (tolower(*cp) == 'x') {
			cp++;
			radix = 16;
			while (*cp) {
				c = tolower(*cp);
				if (isdigit(c)) {
					num = (c - '0') + (num * radix);
				} else if (c >= 'a' && c <= 'f') {
					num = (c - 'a' + 10) + (num * radix);
				} else {
					break;
				}
				cp++;
			}

		} else{
			radix = 8;
			while (*cp) {
				c = tolower(*cp);
				if (isdigit(c) && c < '8') {
					num = (c - '0') + (num * radix);
				} else {
					break;
				}
				cp++;
			}
		}
	}

	if (negative) {
		return 0 - num;
	}
	return num;
}

/******************************************************************************/
#if BLD_FEATURE_FLOATING_POINT
/*
 *	Convert the string buffer to an Floating.
 */

double ejsParseFloat(const char *str)
{
	return atof(str);
}

/******************************************************************************/

int ejsIsNan(double f)
{
#if WIN
	return _isnan(f);
#elif VXWORKS
	/* FUTURE */
	return (0);
#else
	return (f == FP_NAN);
#endif
}
/******************************************************************************/

int ejsIsInfinite(double f)
{
#if WIN
	return !_finite(f);
#elif VXWORKS
	/* FUTURE */
	return (0);
#else
	return (f == FP_INFINITE);
#endif
}

#endif /* BLD_FEATURE_FLOATING_POINT */

/******************************************************************************/
/*
 *	Single point of control for all assignment to properties.
 * 
 *	Copy an objects core value (only). This preserves the destination object's 
 *	name. This implements copy by reference for objects and copy by value for 
 *	strings and other types. Caller must free dest prior to calling.
 */

static EjsVar *copyVar(EJS_LOC_DEC(ep, loc), EjsVar *dest, const EjsVar *src, 
	EjsCopyDepth copyDepth)
{
	Ejs				*ejsContext;
	EjsObj			*srcObj;
	EjsProperty		*destp;
	const char		**srcArgs;
	char			*str;
	int				i;

	mprAssert(dest);
	mprAssert(src);

	if (dest == src) {
		return dest;
	}

	if (dest->type != EJS_TYPE_UNDEFINED) {
		ejsClearVar(ep, dest);
	}

	dest->allocatedData = 0;

	switch (src->type) {
	default:
	case EJS_TYPE_UNDEFINED:
	case EJS_TYPE_NULL:
		break;

	case EJS_TYPE_BOOL:
		dest->boolean = src->boolean;
		break;

	case EJS_TYPE_PTR:
		dest->ptr = src->ptr;
		if (dest->ptr.destructor) {
			dest->allocatedData = 1;
		}
		break;

	case EJS_TYPE_STRING_CMETHOD:
		dest->cMethodWithStrings = src->cMethodWithStrings;
		break;

	case EJS_TYPE_CMETHOD:
		dest->cMethod = src->cMethod;
		break;

#if BLD_FEATURE_FLOATING_POINT
	case EJS_TYPE_FLOAT:
		dest->floating = src->floating;
		break;
#endif

	case EJS_TYPE_INT:
		dest->integer = src->integer;
		break;

#if BLD_FEATURE_INT64
	case EJS_TYPE_INT64:
		dest->integer64 = src->integer64;
		break;
#endif

	case EJS_TYPE_OBJECT:
		if (copyDepth == EJS_SHALLOW_COPY) {

			/*
			 *	If doing a shallow copy and the src object is from the same
			 *	interpreter, or we are copying from the master interpreter, or
			 *	we are using a shared slab, then we can do a shallow copy.
			 *	Otherwise, we must do a deep copy.
			 */
			srcObj = src->objectState;
			if (srcObj->ejs == ep || srcObj->ejs == ep->service->master ||
					(ep->flags & EJS_FLAGS_SHARED_SLAB)) {
				dest->objectState = src->objectState;
				dest->allocatedData = 1;
				break;
			}
		}

		/*
		 *	Doing a deep or recursive deep. Can get here if doing a shallow
		 *	copy and the object is from another non-master interpeter and not
		 *	using a shared slab.
		 *
		 *	We must make sure the data is allocated using the right memory
		 *	context.  It must be the same as the destination parent object.
		 *	Otherwise, when we free the property memory, the parent may
		 *	have a dangling pointer.
		 */
		if (dest->isProperty) {
			destp = ejsGetPropertyPtr(dest);
			if (destp->parentObj == 0) {
				ejsContext = ep;

			} else {
				mprAssert(destp->parentObj);
				ejsContext = destp->parentObj->ejs;
				mprAssert(ejsContext);
			}

		} else {
			ejsContext = ep;
		}

		dest->objectState = createObj(EJS_LOC_PASS(ejsContext, loc));
		if (dest->objectState == 0) {
			/* Memory Error */
			return 0;
		}

		dest->objectState->baseClass = src->objectState->baseClass;
		dest->objectState->methods = src->objectState->methods;
		dest->objectState->noConstructor = src->objectState->noConstructor;
		dest->objectState->objName = 
			mprStrdup(ejsContext, src->objectState->objName);

		if (dest->objectState->objName == 0) {
			return 0;
		}

		if (ejsCopyProperties(ep, dest, src, copyDepth) == 0) {
			return 0;
		}
		dest->allocatedData = 1;
		break;

	case EJS_TYPE_METHOD:
		dest->method.args = mprCreateItemArray(ep, EJS_INC_ARGS, 
			EJS_MAX_ARGS);
		if (dest->method.args == 0) {
			return 0;
		}
		dest->allocatedData = 1;
		if (src->method.args) {
			srcArgs = (const char**) src->method.args->items;
			for (i = 0; i < src->method.args->length; i++) {
				str = mprStrdupInternal(EJS_LOC_PASS(dest->method.args, 
					loc), srcArgs[i]);
				if (str == 0) {
					mprFree(dest->method.args);
					dest->method.args = 0;
					return 0;
				}
				if (mprAddItem(dest->method.args, str) < 0) {
					mprFree(dest->method.args);
					dest->method.args = 0;
					return 0;
				}
			}
		}
		dest->method.body = mprStrdup(dest->method.args, src->method.body);
		if (dest->method.body == 0) {
			mprFree(dest->method.args);
			dest->method.args = 0;
			return 0;
		}
		dest->callsSuper = src->callsSuper;
		break;

	case EJS_TYPE_STRING:
		dest->length = src->length;
		if (src->string) {
			/* Shallow, deep or recursive deep */
			dest->length = dupString(MPR_LOC_PASS(ep, loc), &dest->ustring, 
				src->ustring, src->length);
			if (dest->length < 0) {
				return 0;
			}
			dest->allocatedData = 1;

		} else {
			dest->string = src->string;
			dest->allocatedData = 0;
		}
		break;
	}

	dest->type = src->type;
	dest->flags = src->flags;
	dest->isArray = src->isArray;

	return dest;
}

/******************************************************************************/
/*
 *	Copy all properies in an object. Must preserve property order
 */

EjsVar *ejsCopyProperties(Ejs *ep, EjsVar *dest, const EjsVar *src, 
	EjsCopyDepth copyDepth)
{
	EjsProperty	*srcProp, *destProp, *last, *next;
	int			propertyIndex;
	
	srcProp = ejsGetFirstProperty(src, EJS_ENUM_ALL);
	while (srcProp) {
		next = ejsGetNextProperty(srcProp, EJS_ENUM_ALL);
		if (srcProp->visited) {
			srcProp = next;
			continue;
		}

		/*
		 *	This finds the last variable in the hash chain
		 *	FUTURE OPT. This is slow. If used double link, we could locate the
		 *	tail more easily.
		 */
		destProp = hashLookup(dest->objectState, srcProp->name,  
			&propertyIndex, &last);
		mprAssert(destProp == 0);

		destProp = allocProperty(ep, dest, srcProp->name, propertyIndex, last);
		if (destProp == 0) {
			mprAssert(destProp);
			return 0;
		}

		/*
		 *	Recursively copy the object. If DEEP_COPY, then we
		 *	will do a shallow copy of the object contents. If
		 *	RECURSIVE_DEEP, then we do a deep copy at all levels.
		 */
		srcProp->visited = 1;

		if (copyVar(EJS_LOC_ARGS(ep), ejsGetVarPtr(destProp), 
				ejsGetVarPtr(srcProp), 
				(copyDepth == EJS_DEEP_COPY) ? EJS_SHALLOW_COPY : copyDepth) 
				== 0) {
			return 0;
		}
		srcProp->visited = 0;

		srcProp = next;
	}
	return dest;
}

/******************************************************************************/
/********************************** Properties ********************************/
/******************************************************************************/
/*
 *	Create a property in an object and return a pointer to it. If the property
 *	already exists then just return a pointer to it (no error).
 *	To test for existance of a property, use GetProperty
 */

static EjsProperty *hashLookup(EjsObj *obj, const char *property, 
	int *propertyIndex, EjsProperty **hashTail)
{
	EjsProperty	*prop, *last;
	int			index;

	mprAssert(obj);
	mprAssert(property);

	if (obj == 0 || property == 0 || *property == '\0') {
		mprAssert(0);
		return 0;
	}

	/*
	 *	Find the property in the hash chain if it exists
 	 */
	index = hash(property);
	prop = obj->propertyHash[index];
	for (last = 0; prop != 0; last = prop, prop = prop->hashNext) {
		if (prop->name[0] == property[0] && 
				strcmp(prop->name, property) == 0) {
			break;
		}
	}
	if (propertyIndex) {
		*propertyIndex = index;
	}
	if (hashTail) {
		*hashTail = last;
	}

	return prop;
}

/******************************************************************************/
/*
 *	Create a property in an object and return a pointer to it. If the property
 *	already exists then just return a pointer to it (no error). If the property
 *	does not exist, create an undefined variable. To test for existance of a 
 *	property, use GetProperty.
 */

EjsProperty *ejsCreateSimpleProperty(Ejs *ep, EjsVar *op, const char *property)
{
	EjsProperty	*prop, *last;
	int			propertyIndex;

	if (op == 0 || op->type != EJS_TYPE_OBJECT || property == 0 || 
			*property == '\0') {
		mprAssert(0);
		return 0;
	}

	/*
	 *	Find the property in the hash chain if it exists
 	 */
	prop = hashLookup(op->objectState, property,  &propertyIndex, &last);

	if (prop == 0) {
		/*
		 *	Create a new property
		 */
		prop = allocProperty(ep, op, property, propertyIndex, last);
		if (prop == 0) {
			mprAssert(prop == 0);
			return 0;
		}
	}
	return prop;
}

/******************************************************************************/
/*
 *	Create a property in an object and return a pointer to it. If the property
 *	already exists then just return a pointer to it (no error).
 *	To test for existance of a property, use GetProperty
 */

EjsProperty *ejsCreateSimpleNonUniqueProperty(Ejs *ep, EjsVar *op, 
	const char *property)
{
	EjsProperty	*prop, *last;
	int			propertyIndex;

	if (op == 0 || op->type != EJS_TYPE_OBJECT || property == 0 || 
			*property == '\0') {
		mprAssert(0);
		return 0;
	}

	/*
	 *	Find end of chain
	 */
	propertyIndex = hash(property);
	prop = op->objectState->propertyHash[propertyIndex];
	for (last = 0; prop != 0; last = prop, prop = prop->hashNext) {
		;
	}

	return allocProperty(ep, op, property, propertyIndex, last);
}

/******************************************************************************/
/*
 *	Find a property in an object and return a pointer to it.
 *	This does NOT traverse base classes.
 */

EjsProperty *ejsGetSimpleProperty(Ejs *ep, EjsVar *op, const char *property)
{
	mprAssert(op);
	mprAssert(op->type == EJS_TYPE_OBJECT);
	mprAssert(property && *property);

	/* 
	 *	This is an internal API. It has very little checking.
	 */
	return hashLookup(op->objectState, property,  0, 0);
}

/******************************************************************************/

/*
 *	NOTE: There is no ejsSetSimpleProperty as all the ejsSetProperty routines
 *	operate only on the instance and don't follow base classes. ie. there is
 *	no simple version required. However, there is a ejsSetBaseProperty routine
 *	that will follow base classes and is used to set static properties in base
 *	classes
 */

/******************************************************************************/
/******************************* Property Access ******************************/
/******************************************************************************/
/*
 *	The property get routines follow base classes and utilize the propery 
 *	method access routines. The property set routines do not follow base
 *	classes. The property ejsSetBase... routines do follow base classes.
 */

/*
 *	Find a property in an object and return a pointer to it.
 *	This follows base classes.
 */

EjsProperty *ejsGetProperty(Ejs *ep, EjsVar *op, const char *property)
{
	EjsVar		*vp, *newOp;
	int			maxBaseClasses = 50;

	do {
		if (op->type != EJS_TYPE_OBJECT) {
			mprAssert(op->type == EJS_TYPE_OBJECT);
			return 0;
		}
		mprAssert(op->objectState);

		vp = ejsGetPropertyMethod(ep, op, property);
		if (vp != 0) {
			/*
			 *	Found
			 */
			break;
		}

		newOp = op->objectState->baseClass;
		if (newOp == 0) {
			if (op->objectState != ep->objectClass->objectState) {
				newOp = ep->objectClass;
			}
		}
		op = newOp;

		/*
		 *	A little bit of sanity checking
		 */
		if (--maxBaseClasses <= 0) {
			mprAssert(maxBaseClasses > 0);
			break;
		}

	} while (op);

	return ejsGetPropertyPtr(vp);
}

/******************************************************************************/
/*
 *	Get the property's variable. Optionally create if it does not exist.
 */

EjsVar *ejsGetPropertyAsVar(Ejs *ep, EjsVar *vp, const char *property)
{
	return ejsGetVarPtr(ejsGetProperty(ep, vp, property));
}

/******************************************************************************/
/*
 *	Get the property's value as a binary string. 
 */

const uchar *ejsGetPropertyAsBinaryString(Ejs *ep, EjsVar *obj, 
	const char *property, int *length)
{
	EjsVar			*vp;

	vp = ejsGetVarPtr(ejsGetProperty(ep, obj, property));
	if (vp == 0 || ejsVarIsUndefined(vp)) {
		return 0;
	}

	if (vp->type == EJS_TYPE_STRING) {
		if (length) {
			*length = vp->length;
		}
		return vp->ustring;
	}
	return 0;
}

/******************************************************************************/
/*
 *	Get the property's value as a string.
 */

const char *ejsGetPropertyAsString(Ejs *ep, EjsVar *obj, const char *property)
{
	EjsVar			*vp;

	vp = ejsGetVarPtr(ejsGetProperty(ep, obj, property));
	if (vp == 0 || ejsVarIsUndefined(vp)) {
		return 0;
	}

	if (vp->type == EJS_TYPE_STRING) {
		return vp->string;
	}
	return 0;
}

/******************************************************************************/
/*
 *	Get the property's value as a number.
 */

BLD_FEATURE_NUM_TYPE ejsGetPropertyAsNumber(Ejs *ep, EjsVar *obj, 
	const char *property)
{
	EjsVar		*vp;

	vp = ejsGetVarPtr(ejsGetProperty(ep, obj, property));
	if (vp == 0 || ejsVarIsUndefined(vp)) {
		return 0;
	}

	return ejsVarToNumber(vp);
}

/******************************************************************************/
/*
 *	Get the property's value as a integer.
 */

int ejsGetPropertyAsInteger(Ejs *ep, EjsVar *obj, const char *property)
{
	EjsVar		*vp;

	vp = ejsGetVarPtr(ejsGetProperty(ep, obj, property));
	if (vp == 0 || ejsVarIsUndefined(vp)) {
		return 0;
	}

	return ejsVarToInteger(vp);
}

/******************************************************************************/
/*
 *	Get the property's value as a boolean.
 */

bool ejsGetPropertyAsBoolean(Ejs *ep, EjsVar *obj, const char *property)
{
	EjsVar		*vp;

	vp = ejsGetVarPtr(ejsGetProperty(ep, obj, property));
	if (vp == 0 || ejsVarIsUndefined(vp)) {
		return 0;
	}

	return ejsVarToBoolean(vp);
}

/******************************************************************************/
/*
 *	Get the property's value as a pointer.
 */

void *ejsGetPropertyAsPtr(Ejs *ep, EjsVar *obj, const char *property)
{
	EjsVar		*vp;

	vp = ejsGetVarPtr(ejsGetProperty(ep, obj, property));
	if (vp == 0 || ejsVarIsUndefined(vp)) {
		return 0;
	}
	if (vp->type == EJS_TYPE_PTR) {
		return vp->ptr.userPtr;
	}
	return 0;
}

/******************************************************************************/
/*
 *	Create a property in the object. This will override any base class
 *	properties.
 *
 *	MOB -- need to spell out the difference between ejsSetProperty and
 *	ejsCreateProperty.
 */

EjsProperty *ejsCreateProperty(Ejs *ep, EjsVar *obj, const char *property)
{
	EjsVar	*vp;

	vp = ejsCreatePropertyMethod(ep, obj, property);
	return ejsGetPropertyPtr(vp);
}

/******************************************************************************/
/*
 *	Set a property's variable value. Create the property if it does not exist.
 *	This routine DOES follow base classes.
 */

EjsProperty *ejsSetBaseProperty(Ejs *ep, EjsVar *op, const char *property, 
	const EjsVar *value)
{
	EjsVar		*vp, *newOp;
	int			maxBaseClasses = 50;

	do {
		if (op->type != EJS_TYPE_OBJECT) {
			mprAssert(op->type == EJS_TYPE_OBJECT);
			return 0;
		}
		mprAssert(op->objectState);

		vp = ejsGetPropertyMethod(ep, op, property);
		if (vp != 0) {
			/*
			 *	Found
			 */
			vp = ejsSetPropertyMethod(ep, op, property, value);
			break;
		}

		newOp = op->objectState->baseClass;
		if (newOp == 0) {
			if (op->objectState != ep->objectClass->objectState) {
				newOp = ep->objectClass;
			}
		}
		op = newOp;

		/*
		 *	A little bit of sanity checking
		 */
		if (--maxBaseClasses <= 0) {
			mprAssert(maxBaseClasses > 0);
			break;
		}

	} while (op);

	return ejsGetPropertyPtr(vp);
}

/******************************************************************************/
/*
 *	Set a property's variable value. Create the property if it does not exist.
 *	This does NOT follow base classes. Okay when updating instance properties,
 *	but not for class (static) properties. This does a shallow copy which 
 *	will copy references.
 */

EjsProperty *ejsSetProperty(Ejs *ep, EjsVar *obj, const char *property, 
	const EjsVar *value)
{
	EjsVar		*vp;

	vp = ejsSetPropertyMethod(ep, obj, property, value);

	return ejsGetPropertyPtr(vp);
}

/******************************************************************************/
/*
 *	Set a property's variable value by assigning the given value. The caller
 *	must NOT free value as it is assigned directly into the property's value.
 */

EjsProperty *ejsSetPropertyAndFree(Ejs *ep, EjsVar *obj, 
	const char *property, EjsVar *value)
{
	EjsVar		*vp;

	vp = ejsSetPropertyMethod(ep, obj, property, value);

	ejsFree(ep, value, EJS_SLAB_VAR);
	
	return ejsGetPropertyPtr(vp);
}

/******************************************************************************/

EjsProperty *ejsSetPropertyToCMethod(Ejs *ep, EjsVar *vp, const char *prop, 
	EjsCMethod fn, void *userData, int flags)
{
	EjsVar		v;

	ejsInitVar(&v, EJS_TYPE_CMETHOD);
	v.cMethod.fn = fn;
	v.cMethod.userData = userData;
	v.flags = flags;

	return ejsSetProperty(ep, vp, prop, &v);
}

/******************************************************************************/

EjsProperty *ejsSetPropertyToBoolean(Ejs *ep, EjsVar *vp, const char *prop, 
	int value)
{
	EjsVar		v;

	ejsInitVar(&v, EJS_TYPE_BOOL);
	v.boolean = value;

	return ejsSetProperty(ep, vp, prop, &v);
}

/******************************************************************************/
#if BLD_FEATURE_FLOATING_POINT

EjsProperty *ejsSetPropertyToFloat(Ejs *ep, EjsVar *vp, const char *prop, 
	double value)
{
	EjsVar		v;

	ejsInitVar(&v, EJS_TYPE_FLOAT);
	v.floating = value;

	return ejsSetProperty(ep, vp, prop, &v);
}

#endif
/******************************************************************************/

EjsProperty *ejsSetPropertyToInteger(Ejs *ep, EjsVar *vp, const char *prop, 
	int value)
{
	EjsVar		v;

	ejsInitVar(&v, EJS_TYPE_INT);
	v.integer = value;

	return ejsSetProperty(ep, vp, prop, &v);
}

/******************************************************************************/
#if BLD_FEATURE_INT64

EjsProperty *ejsSetPropertyToInteger64(Ejs *ep, EjsVar *vp, const char *prop, 
	int64 value)
{
	EjsVar		v;

	ejsInitVar(&v, EJS_TYPE_INT64);
	v.integer64 = value;

	return ejsSetProperty(ep, vp, prop, &v);
}

#endif
/******************************************************************************/

EjsProperty *ejsSetPropertyToNull(Ejs *ep, EjsVar *vp, const char *prop)
{
	EjsVar		v;

	ejsInitVar(&v, EJS_TYPE_NULL);

	return ejsSetProperty(ep, vp, prop, &v);
}

/******************************************************************************/

EjsProperty *ejsSetPropertyToMethod(Ejs *ep, EjsVar *vp, const char *prop, 
	const char *body, MprArray *args, int flags)
{
	return ejsSetPropertyAndFree(ep, vp, prop, 
		ejsCreateMethodVar(ep, body, args, flags));
}

/******************************************************************************/

EjsProperty *ejsSetPropertyToNumber(Ejs *ep, EjsVar *vp, const char *prop, 
	EjsNum value)
{
	return ejsSetPropertyAndFree(ep, vp, prop, ejsCreateNumberVar(ep, value));
}

/******************************************************************************/

EjsProperty *ejsSetPropertyToStringCMethod(Ejs *ep, EjsVar *vp, 
	const char *prop, EjsStringCMethod fn, void *userData, int flags)
{
	EjsVar		v;

	ejsInitVar(&v, EJS_TYPE_STRING_CMETHOD);
	v.cMethodWithStrings.fn = fn;
	v.cMethodWithStrings.userData = userData;
	v.flags = flags;

	return ejsSetProperty(ep, vp, prop, &v);
}

/******************************************************************************/

EjsProperty *ejsSetPropertyToString(Ejs *ep, EjsVar *vp, const char *prop, 
	const char *value)
{
	EjsProperty		*pp;
	EjsVar			v;

	ejsInitVar(&v, EJS_TYPE_STRING);

	/* FUTURE OPT */
	v.string = mprStrdupInternal(EJS_LOC_ARGS(ep), value);
	if (v.string == 0) {
		return 0;
	}
	v.length = strlen(v.string);
	v.allocatedData = 1;

	pp = ejsSetProperty(ep, vp, prop, &v);

	mprFree(v.string);

	return pp;
}

/******************************************************************************/

EjsProperty *ejsSetPropertyToBinaryString(Ejs *ep, EjsVar *vp, 
	const char *prop, const uchar *value, int len)
{
	EjsProperty		*pp;
	EjsVar			v;

	ejsInitVar(&v, EJS_TYPE_STRING);

	/* FUTURE OPT */
	v.length = dupString(MPR_LOC_ARGS(ep), &v.ustring, value, len);
	if (v.length < 0) {
		return 0;
	}
	v.allocatedData = 1;

	pp = ejsSetProperty(ep, vp, prop, &v);

	mprFree(v.ustring);

	return pp;
}

/******************************************************************************/

EjsProperty *ejsSetPropertyToUndefined(Ejs *ep, EjsVar *vp, const char *prop)
{
	EjsVar		v;

	ejsInitVar(&v, EJS_TYPE_UNDEFINED);

	return ejsSetProperty(ep, vp, prop, &v);
}

/******************************************************************************/

EjsProperty	*ejsSetPropertyToPtr(Ejs *ep, EjsVar *vp, const char *prop, 
	void *ptr, EjsDestructor destructor)
{
	EjsVar		v;

	ejsInitVar(&v, EJS_TYPE_PTR);
	v.ptr.userPtr = ptr;
	v.ptr.destructor = destructor;
	v.allocatedData = 1;

	return ejsSetProperty(ep, vp, prop, &v);
}

/******************************************************************************/

EjsProperty *ejsSetPropertyToNewObj(Ejs *ep, EjsVar *vp, const char *prop,
	const char *className, MprArray *args)
{
	return ejsSetPropertyAndFree(ep, vp, prop, 
		ejsCreateObjUsingArgv(ep, 0, className, args));
}

/******************************************************************************/

EjsProperty *ejsSetPropertyToObj(Ejs *ep, EjsVar *op, const char *prop)
{
	return ejsSetPropertyAndFree(ep, op, prop, ejsCreateObjVar(ep));
}

/******************************************************************************/
/*
 *	Convenience routines
 */

EjsVar *ejsSetPropertyToObjAsVar(Ejs *ep, EjsVar *op, const char *prop)
{
	return ejsGetVarPtr(ejsSetPropertyToObj(ep, op, prop));
}

/******************************************************************************/
/******************************************************************************/
/******************************************************************************/
/******************************************************************************/
/*
 *	Create a script method
 */

EjsProperty *ejsDefineMethod(Ejs *ep, EjsVar *vp, const char *prop, 
	const char *body, MprArray *args)
{
	if (vp == 0) {
		vp = ejsGetGlobalObj(ep);
	}
	return ejsSetPropertyToMethod(ep, vp, prop, body, args, 0);
}

/******************************************************************************/
/*
 *	Create a C language method
 */

EjsProperty *ejsDefineCMethod(Ejs *ep, EjsVar *vp, const char *prop, 
	EjsCMethod fn, int flags)
{
	if (vp == 0) {
		vp = ejsGetGlobalObj(ep);
	}
	return ejsSetPropertyToCMethod(ep, vp, prop, fn, 0, flags);
}

/******************************************************************************/
/*
 *	Define accessors
 */

EjsProperty *ejsDefineAccessors(Ejs *ep, EjsVar *vp, const char *prop, 
	const char *getBody, const char *setBody)
{
	EjsProperty	*pp;
	MprArray	*args;
	char		*propName;

	if (vp == 0) {
		vp = ejsGetGlobalObj(ep);
	}

	if (ejsSetPropertyToMethod(ep, vp, prop, getBody, 0, EJS_GET_ACCESSOR) < 0){
		ejsMemoryError(ep);
		return 0;
	}

	/* MOB -- OPT to use SLAB */
	/* MOB -- need to encapsulate this logic */

	if (mprAllocStrcat(MPR_LOC_ARGS(ep), &propName, EJS_MAX_ID+5, 0, 
			"-set-", prop, NULL) < 0) {
		ejsMemoryError(ep);
		return 0;
	}

	args = mprCreateItemArray(ep, EJS_INC_ARGS, EJS_MAX_ARGS);
	mprAddItem(args, mprStrdup(args, "value"));

	pp = ejsSetPropertyToMethod(ep, vp, propName, setBody, args, 
		EJS_SET_ACCESSOR);
	mprFree(propName);

	if (pp == 0) {
		ejsMemoryError(ep);
		return 0;
	}

	return pp;
}

/******************************************************************************/
/*
 *	Define C accessors
 */

EjsProperty *ejsDefineCAccessors(Ejs *ep, EjsVar *vp, const char *prop, 
	EjsCMethod getFn, EjsCMethod setFn, int flags)
{
	EjsProperty	*pp;
	char		*propName;

	if (vp == 0) {
		vp = ejsGetGlobalObj(ep);
	}
	pp = ejsSetPropertyToCMethod(ep, vp, prop, getFn, 0, 
			flags | EJS_GET_ACCESSOR);
	if (pp == 0) {
		ejsMemoryError(ep);
		return 0;
	}

	/* MOB -- OPT to use SLAB */
	if (mprAllocStrcat(MPR_LOC_ARGS(ep), &propName, EJS_MAX_ID + 5, 0, 
			"-set-", prop, NULL) < 0) {
		ejsMemoryError(ep);
		return 0;
	}
	pp = ejsSetPropertyToCMethod(ep, vp, propName, setFn, 0, 
		flags | EJS_SET_ACCESSOR);
	mprFree(propName);

	if (pp == 0) {
		ejsMemoryError(ep);
		return 0;
	}
	return pp;
}

/******************************************************************************/
/*
 *	Create a C language method with string arguments
 */

EjsProperty *ejsDefineStringCMethod(Ejs *ep, EjsVar *vp, const char *prop, 
	EjsStringCMethod fn, int flags)
{
	if (vp == 0) {
		vp = ejsGetGlobalObj(ep);
	}
	return ejsSetPropertyToStringCMethod(ep, vp, prop, fn, 0, flags);
}

/******************************************************************************/

void ejsSetCMethodUserData(EjsVar *obj, void *userData)
{
	/*
	 *	This is a little dirty. We rely on the userData being in the same
	 *	place in the var structure.
	 */
	obj->cMethod.userData = userData;
}

/******************************************************************************/

void ejsSetVarFlags(EjsVar *obj, int flags)
{
	obj->flags = flags;
}

/******************************************************************************/

void *ejsGetCMethodUserData(EjsVar *obj)
{
	return obj->cMethod.userData;
}

/******************************************************************************/

int ejsGetVarFlags(EjsVar *obj)
{
	return obj->flags;
}

/******************************************************************************/

void ejsSetObjDestructor(Ejs *ep, EjsVar *obj, EjsDestructor destructor)
{
	obj->objectState->destructor = destructor;
}

/******************************************************************************/

void ejsClearObjDestructor(Ejs *ep, EjsVar *obj)
{
	obj->objectState->destructor = 0;
}

/******************************************************************************/
/*
 *	Create a new property
 */

static EjsProperty *allocProperty(Ejs *ep, EjsVar *op, const char *property, 
	int propertyIndex, EjsProperty *last)
{
	EjsProperty		*prop;
	EjsObj			*obj;

	obj = op->objectState;

	/*
	 *	Allocate the property using the memory context of the owning object
	 */
	prop = ejsAllocProperty(EJS_LOC_ARGS(obj->ejs));
	if (prop == 0) {
		return 0;
	}
	if (mprStrcpy(prop->name, sizeof(prop->name), property) < 0) {
		ejsError(ep, EJS_REFERENCE_ERROR, 
			"Property name %s is too long. Max is %d letters.", 
			prop->name, EJS_MAX_ID);
		return 0;
	}

	ejsSetVarName(ep, ejsGetVarPtr(prop), &prop->name[0]);

	/*
	 *	Do hash linkage
	 */
	if (last) {
		last->hashNext = prop;
	} else {
		obj->propertyHash[propertyIndex] = prop;
	}

#if BLD_DEBUG
	prop->link.propertyName = prop->name;
	prop->link.property = prop;
	prop->link.head = &obj->link;
#endif

	/*
	 *	Inserting before the dummy head will append to the end
	 */
	linkPropertyBefore(obj, &obj->link, &prop->link);

	obj->numProperties++;
	prop->parentObj = obj;
	mprAssert(obj->ejs);

	return prop;
}

/******************************************************************************/
/*
 *	Delete a property from this object
 */

int ejsDeleteProperty(Ejs *ep, EjsVar *vp, const char *property)
{
	EjsProperty		*prop, *last;
	EjsObj			*obj;
	int				propertyIndex;

	mprAssert(vp);
	mprAssert(property && *property);
	mprAssert(vp->type == EJS_TYPE_OBJECT);

	if (vp->type != EJS_TYPE_OBJECT) {
		mprAssert(vp->type == EJS_TYPE_OBJECT);
		return MPR_ERR_BAD_ARGS;
	}

	prop = hashLookup(vp->objectState, property,  &propertyIndex, &last);
	if (prop == (EjsProperty*) 0) {
		return MPR_ERR_NOT_FOUND;
	}
	obj = vp->objectState;

#if FUTURE
 	if (prop->readonly) {
		mprAssert(! prop->readonly);
		return MPR_ERR_READ_ONLY;
	}
#endif

	/*
     *	If doing enumerations, then the object will mark preventDelete to
	 *	prevent any properties being deleted and thus disturbing the
	 *	traversal.
	 */
	if (obj->preventDeleteProp) {
		obj->delayedDeleteProp = 1;
		prop->delayedDelete = 1;
		return 0;
	}

	/*
	 *	Remove from hash 
	 */
	if (last) {
		last->hashNext = prop->hashNext;
	} else {
		obj->propertyHash[propertyIndex] = prop->hashNext;
	}

	unlinkProperty(obj, &prop->link);
	obj->numProperties--;
	
	/*
	 *	Free any property data and return to the slab
	 */
	if (prop->var.type != EJS_TYPE_OBJECT) {
		ejsClearVar(ep, ejsGetVarPtr(prop));
	}
	ejsFree(ep, prop, EJS_SLAB_PROPERTY);

	return 0;
}

/******************************************************************************/
/*
 *	Remove a property's value from this object. The property is set to 
 *	undefined.
 */

EjsVar *ejsClearProperty(Ejs *ep, EjsVar *vp, const char *property)
{
	EjsProperty		*prop;

	mprAssert(vp);
	mprAssert(property && *property);
	mprAssert(vp->type == EJS_TYPE_OBJECT);

	if (vp->type != EJS_TYPE_OBJECT) {
		mprAssert(vp->type == EJS_TYPE_OBJECT);
		return 0;
	}

	prop = hashLookup(vp->objectState, property, 0, 0);
	if (prop == (EjsProperty*) 0) {
		return 0;
	}
#if FUTURE
 	if (prop->readonly) {
		mprAssert(! prop->readonly);
		return 0;
	}
#endif

	ejsClearVar(ep, &prop->var);
	return &prop->var;
}

/******************************************************************************/
/*
 *	Unlink a property from the ordered list of properties
 */

static void unlinkProperty(EjsObj *obj, EjsPropLink *propLink)
{
	propLink->prev->next = propLink->next;
	propLink->next->prev = propLink->prev;
}

/******************************************************************************/
#if UNUSED && KEEP
/*
 *	Insert a link after a specified link. 
 */

static void linkPropertyAfter(EjsObj *obj, EjsPropLink *at, 
	EjsPropLink *propLink)
{
	propLink->next = at->next;
	propLink->prev = at;

	at->next->prev = propLink;
	at->next = propLink;
}

#endif
/******************************************************************************/
/*
 *	Insert a link before a specified link. 
 */

static void linkPropertyBefore(EjsObj *obj, EjsPropLink *at, 
	EjsPropLink *propLink)
{
	propLink->prev = at->prev;
	propLink->next = at;

	at->prev->next = propLink;
	at->prev = propLink;
}

/******************************************************************************/
/*
 *	This routine will sort properties in an object. If propertyName is not
 *	null, then the properties in op must be objects with a property of the
 *	name propertyName. If propertyName is null, then the properties of op
 *	are directly sorted. If order is 1, they are sorted in ascending order.
 *	If -1, they are sorted in descending order.
 *
 *	NOTE: arrays keep their original index values.
 */
	
void ejsSortProperties(Ejs *ep, EjsVar *op, EjsSortFn fn, 
	const char *propertyName, int order)
{
	EjsProperty		*p1, *p2, *tmp;
	EjsPropLink			*l1, *l2, *oldL1Spot;
	EjsObj			*obj;

	obj = op->objectState;

	p1 = ejsGetFirstProperty(op, 0);
	while (p1) {
		if (p1->dontEnumerate) {
			p1 = ejsGetNextProperty(p1, 0);
			continue;
		}

		p2 = ejsGetFirstProperty(op, 0);
		while (p2 && p2 != p1) {

			if (p2->dontEnumerate) {
				p2 = ejsGetNextProperty(p2, 0);
				continue;
			}
			
			if (fn == 0) {
				if (propertyName) {
					fn = sortByProperty;
				} else {
					fn = sortAllProperties;
				}
			}

			if (fn(ep, p1, p2, propertyName, order) < 0) {

				l1 = &p1->link;
				l2 = &p2->link;

				/*
				 *	Swap the properties without disturbing the hash chains.
				 * 	l1 is always after l2 in the list. Unlink l1 and remember 
				 *	the one after l1.
				 */
				oldL1Spot = l1->next;
				unlinkProperty(obj, l1);

				/*
				 *	Manually reinsert l1 by replacing l2 with l1. l2 is out of
				 *	the chain.
			 	 */
				l2->prev->next = l1;
				l2->next->prev = l1;
				l1->prev = l2->prev;
				l1->next = l2->next;

				/*
				 *	Reinsert l2 before the spot where l1 was.
				 */
				linkPropertyBefore(obj, oldL1Spot, l2);

				/*
 				 *	Swap the pointers so we continue to traverse correctly
				 */
				tmp = p1;
				p1 = p2;
				p2 = tmp;
			}
			p2 = ejsGetNextProperty(p2, 0);
		}
		p1 = ejsGetNextProperty(p1, 0);
	}
}

/******************************************************************************/
/*
 *	Sort properties. Strings are sorted in ascending ASCII collating sequence
 *	Numbers are sorted in increasing numerical order.
 */
static int sortAllProperties(Ejs *ep, EjsProperty *p1, EjsProperty *p2,
	const char *propertyName, int order)
{
	EjsVar	*v1, *v2;
	char	*buf1, *buf2;
	int		rc, buf1Alloc;

	v1 = ejsGetVarPtr(p1);
	v2 = ejsGetVarPtr(p2);

	if (v1->type == v2->type) {
		/* MOB -- should support Numbers */
		if (v1->type == EJS_TYPE_INT) {
			if (v1->integer < v2->integer) {
				return - order;

			} else if (v1->integer == v2->integer) {
				return 0;
			}
			return order;

#if BLD_FEATURE_FLOATING_POINT
		} else if (v1->type == EJS_TYPE_FLOAT) {
			if (v1->floating < v2->floating) {
				return - order;

			} else if (v1->floating == v2->floating) {
				return 0;
			}
			return order;

#endif
		} else if (v1->type == EJS_TYPE_STRING) {
			/* MOB -- need binary support ? */
			return strcmp(v1->string, v2->string) * order;

		} else {

			buf1 = ejsVarToStringEx(ep, v1, &buf1Alloc);
			buf2 = ejsVarToString(ep, v2);

			rc = strcmp(buf1, buf2);

			if (buf1Alloc) {
				mprFree(buf1);
			}

			return rc * order;
		}

	} else {
		/* Type mismatch in array */
		return 0;
	}
	return 0;
}

/******************************************************************************/
/*
 *	Sort an object by a given property. 
 */
static int sortByProperty(Ejs *ep, EjsProperty *p1, EjsProperty *p2,
	const char *propertyName, int order)
{
	EjsVar	*o1, *o2, *v1, *v2;
	char	*buf1, *buf2;
	int		rc, buf1Alloc;

	o1 = ejsGetVarPtr(p1);
	o2 = ejsGetVarPtr(p2);

	if (!ejsVarIsObject(o1) || !ejsVarIsObject(o2)) {
		mprAssert(ejsVarIsObject(o1));
		mprAssert(ejsVarIsObject(o2));
		return 0;
	}

	v1 = ejsGetPropertyAsVar(ep, o1, propertyName);
	v2 = ejsGetPropertyAsVar(ep, o2, propertyName);

	if (v1 == 0 || v2 == 0) {
		/* Property name not found */
		return 0;
	}

	if (v1->type != v2->type) {
		mprAssert(v1->type == v2->type);
		return 0;
	}

	if (v1->type == v2->type) {
		/* MOB -- should support Numbers */
		if (v1->type == EJS_TYPE_INT) {
			if (v1->integer < v2->integer) {
				return -order;

			} else if (v1->integer == v2->integer) {
				return 0;
			}
			return order;

#if BLD_FEATURE_FLOATING_POINT
		} else if (v1->type == EJS_TYPE_FLOAT) {
			if (v1->floating < v2->floating) {
				return -order;

			} else if (v1->floating == v2->floating) {
				return 0;
			}
			return order;

#endif
		} else if (v1->type == EJS_TYPE_STRING) {
			/* MOB -- need binary support ? */
			return strcmp(v1->string, v2->string) * order;

		} else {
			buf1 = ejsVarToStringEx(ep, v1, &buf1Alloc);

			buf2 = ejsVarToString(ep, v2);

			rc = strcmp(buf1, buf2);

			if (buf1Alloc) {
				mprFree(buf1);
			}

			return rc * order;
		}

	} else {
		/* Type mismatch in array */
		return 0;
	}
	return 0;
}

/******************************************************************************/
/*
 *	Set a property's name
 */

void ejsSetPropertyName(EjsProperty *pp, const char *property)
{
	mprStrcpy(pp->name, sizeof(pp->name), property);
}

/******************************************************************************/

int ejsMakePropertyEnumerable(EjsProperty *prop, int enumerate)
{
	int		oldValue;

	oldValue = prop->dontEnumerate;
	prop->dontEnumerate = !enumerate;
	return oldValue;
}

/******************************************************************************/

void ejsMakePropertyPrivate(EjsProperty *prop, int isPrivate)
{
	prop->isPrivate = isPrivate;
}

/******************************************************************************/
/*
 *	Make a variable read only. Can still be deleted.
 */

void ejsMakePropertyReadOnly(EjsProperty *prop, int readonly)
{
	prop->readonly = readonly;
}

/******************************************************************************/

int ejsMakeObjPermanent(EjsVar *vp, int permanent)
{
	int		oldValue;

	if (vp && vp->type == EJS_TYPE_OBJECT) {
		oldValue = vp->objectState->permanent;
		vp->objectState->permanent = permanent;
	} else {
		oldValue = 0;
	}
	return oldValue;
}

/******************************************************************************/

int ejsMakeObjLive(EjsVar *vp, bool alive)
{
	int		oldValue;

	oldValue = 0;
	if (vp && vp->type == EJS_TYPE_OBJECT) {
		oldValue = vp->objectState->alive;
		vp->objectState->alive = alive;
	} else {
		oldValue = 0;
	}
	return oldValue;
}

/******************************************************************************/

void ejsMakeClassNoConstructor(EjsVar *vp)
{
	mprAssert(vp->type == EJS_TYPE_OBJECT);

	if (vp->type == EJS_TYPE_OBJECT) {
		vp->objectState->noConstructor = 1;
	}
}

/******************************************************************************/
/*
 *	Get the count of properties.
 */

int ejsGetPropertyCount(EjsVar *vp)
{
	EjsProperty		*pp;
	EjsPropLink		*lp, *head;
	int				count;

	mprAssert(vp);

	if (vp->type != EJS_TYPE_OBJECT) {
		return 0;
	}

	count = 0;

	head = &vp->objectState->link;
	for (lp = head->next; lp != head; lp = lp->next) {
		pp = ejsGetPropertyFromLink(lp);
		if (! pp->dontEnumerate) {
			count++;
		}
	}
	return count;
}

/******************************************************************************/
/*
 *	Get the first property in an object. Used for walking all properties in an
 *	object. This will only enumerate properties in this class and not in base
 *	classes.
 */

EjsProperty *ejsGetFirstProperty(const EjsVar *op, int flags)
{
	EjsProperty		*pp;
	EjsObj			*obj;
	EjsPropLink		*head, *lp;

	mprAssert(op);
	mprAssert(op->type == EJS_TYPE_OBJECT);

	if (op->type != EJS_TYPE_OBJECT) {
		mprAssert(op->type == EJS_TYPE_OBJECT);
		return 0;
	}
	pp = 0;

	do {
		obj = op->objectState;

		head = &obj->link;
		lp = head->next;

		while (lp != head) {
			pp = ejsGetPropertyFromLink(lp);
			if (! pp->dontEnumerate || (flags & EJS_ENUM_HIDDEN)) {
				break;
			}
			lp = lp->next;
		}
		if (lp != head || op->type != EJS_TYPE_OBJECT || 
				!(flags & EJS_ENUM_CLASSES)) {
			break;
		}

		op = obj->baseClass;

	} while (lp == 0 && op);

	return pp;
}

/******************************************************************************/
/*
 *	Get the next property in sequence. This will only enumerate properties in 
 *	this class and not in base classes.
 */

EjsProperty *ejsGetNextProperty(EjsProperty *last, int flags)
{
	EjsProperty		*pp;
	EjsObj			*obj;
	EjsPropLink		*lp, *head;

	obj = last->parentObj;

	lp = last->link.next;
	head = &obj->link;
	pp = 0;

	while (obj) {
		while (lp != head) {
			pp = ejsGetPropertyFromLink(lp);
			if (! pp->dontEnumerate || (flags & EJS_ENUM_HIDDEN)) {
				break;
			}
			lp = lp->next;
		}
		if (lp != head || !(flags & EJS_ENUM_CLASSES)) {
			break;
		}

		/*
		 *	Now iterate over properties in base classes (down the chain)
		 */
		if (obj->baseClass == 0) {
			break;
		}

		obj = obj->baseClass->objectState;
		if (obj == 0) {
			break;
		}
	}
	return pp;
}

/******************************************************************************/
/*
 *	Find a variable given a variable name and return the parent object and 
 *	the variable itself. This routine supports literal variable and property 
 *	names that may be objects or arrays but may NOT have expressions. 
 *	Returns -1 on errors or if the variable is not found.
 *	FUTURE -- Needs OPT
 */

EjsVar *ejsFindProperty(Ejs *ep, EjsVar **obj, char **property, EjsVar *global, 
	EjsVar *local, const char *fullName, int create)
{
	EjsProperty	*currentProp;
	EjsVar		*currentObj;
	/* MOB -- WARNING BIG */
	char		tokBuf[EJS_MAX_ID], propertyName[EJS_MAX_ID];
	char		*token, *next, *cp, *endp;

	mprAssert(fullName && *fullName);

	currentProp = 0;
	currentObj = 0;

	if (global == 0) {
		global = ep->global;
	}

	if (obj) {
		*obj = 0;
	}
	if (property) {
		*property = 0;
	}

	if (fullName == 0) {
		return 0;
	}

	next = (char*) fullName;
	token = getNextVarToken(&next, tokBuf, sizeof(tokBuf));
	mprStrcpy(propertyName, sizeof(propertyName), token);

	if (local) {
		currentProp = ejsGetProperty(ep, local, token);
		currentObj = local;
	}
	if (currentProp == 0) {
		currentProp = ejsGetProperty(ep, global, token);
		currentObj = global;
	}

	token = getNextVarToken(&next, tokBuf, sizeof(tokBuf));

	while (currentObj != 0 && token != 0 && *token) {

		if (currentProp == 0) {
			return 0;
		}
		currentObj = &currentProp->var;
		currentProp = 0;

		if (*token == '[') {
			token = getNextVarToken(&next, tokBuf, sizeof(tokBuf));

			mprStrcpy(propertyName, sizeof(propertyName), token);
			cp = propertyName;
			if (*cp == '\"') {
				cp++;
				if ((endp = strchr(cp, '\"')) != 0) {
					*endp = '\0';
				}
			} else if (*cp == '\'') {
				cp++;
				if ((endp = strchr(cp, '\'')) != 0) {
					*endp = '\0';
				}
			}

			currentProp = ejsGetProperty(ep, currentObj, propertyName);

			token = getNextVarToken(&next, tokBuf, sizeof(tokBuf));
			if (*token != ']') {
				return 0;
			}

		} else if (*token == '.') {
			token = getNextVarToken(&next, tokBuf, sizeof(tokBuf));
			if (!isalpha((int) token[0]) && 
					token[0] != '_' && token[0] != '$') {
				return 0;
			}

			mprStrcpy(propertyName, sizeof(propertyName), token);
			currentProp = ejsGetProperty(ep, currentObj, token);

		} else {
			currentProp = ejsGetProperty(ep, currentObj, token);
		}

		if (next == 0 || *next == '\0') {
			break;
		}
		token = getNextVarToken(&next, tokBuf, sizeof(tokBuf));
	}

	if (obj) {
		*obj = currentObj;
	}


	if (currentProp == 0 && currentObj >= 0 && create) {
		currentProp = ejsCreateSimpleProperty(ep, currentObj, propertyName);
	}

	if (property) {
		*property = currentProp->name;
	}
	return ejsGetVarPtr(currentProp);
}

/******************************************************************************/
/*
 *	Get the next token as part of a variable specification. This will return
 *	a pointer to the next token and will return a pointer to the next token 
 *	(after this one) in "next". The tokBuf holds the parsed token.
 */

static char *getNextVarToken(char **next, char *tokBuf, int tokBufLen)
{
	char	*start, *cp;
	int		len;

	start = *next;
	while (isspace((int) *start) || *start == '\n' || *start == '\r') {
		start++;
	}
	cp = start;

	if (*cp == '.' || *cp == '[' || *cp == ']') {
		cp++;
	} else {
		while (*cp && *cp != '.' && *cp != '[' && *cp != ']' && 
				!isspace((int) *cp) && *cp != '\n' && *cp != '\r') {
			cp++;
		}
	}
	len = mprMemcpy(tokBuf, tokBufLen - 1, start, cp - start);
	tokBuf[len] = '\0';
	
	*next = cp;
	return tokBuf;
}

/******************************************************************************/

EjsVar *ejsGetGlobalClass(Ejs *ep)
{
	return ep->global;
}

/******************************************************************************/
/*************************** Property Access Methods **************************/
/******************************************************************************/
/*
 *	Create an undefined property. This routine calls the object method hooks.
 */

/* MOB -- better suffix than "Method" */
EjsVar *ejsCreatePropertyMethod(Ejs *ep, EjsVar *op, const char *property)
{
	EjsVar		*vp;

	mprAssert(ep);
	mprAssert(op);
	mprAssert(property && *property);

	if (op == 0) {
		return 0;
	}

	mprAssert(op->type == EJS_TYPE_OBJECT);
	mprAssert(op->objectState);

	if (op->objectState == 0) {
		return 0;
	}

	if (op->objectState->methods == 0) {
		vp = ejsGetVarPtr(ejsCreateSimpleProperty(ep, op, property));
	} else {
		vp = (op->objectState->methods->createProperty)(ep, op, property);
	}

	if (vp == 0) {
		mprAssert(vp);
		op->objectState->hasErrors = 1;
		return 0;
	}

	/*
	 * 	FUTURE - find a better way.
	 */
	if (op->isArray) {
		ejsSetArrayLength(ep, op, property, 0, 0);
	}
	return vp;
}

/******************************************************************************/

int ejsDeletePropertyMethod(Ejs *ep, EjsVar *op, const char *property)
{
	int		rc;

	mprAssert(ep);
	mprAssert(op);
	mprAssert(property && *property);

	if (op == 0) {
		return -1;
	}

	mprAssert(op->type == EJS_TYPE_OBJECT);
	mprAssert(op->objectState);

	if (op->objectState == 0) {
		return -1;
	}

	if (op->objectState->methods == 0) {
		rc = ejsDeleteProperty(ep, op, property);
	} else {
		rc = (op->objectState->methods->deleteProperty)(ep, op, property);
	}

	if (rc < 0) {
		op->objectState->hasErrors = 1;
	}

	op->objectState->dirty = 1;

	return rc;
}

/******************************************************************************/
/*
 *	Set the value of a property. Create if it does not exist
 *	If the object has property accessor methods defined, use those.
 */

EjsVar *ejsSetPropertyMethod(Ejs *ep, EjsVar *op, const char *property, 
	const EjsVar *value)
{
	EjsVar			*vp;

	mprAssert(ep);
	mprAssert(op);
	mprAssert(property && *property);
	mprAssert(value);

	if (op == 0) {
		return 0;
	}

	mprAssert(op->type == EJS_TYPE_OBJECT);
	mprAssert(op->objectState);

	if (op->objectState == 0) {
		return 0;
	}

	if (op->objectState->methods == 0) {
		vp = ejsGetVarPtr(ejsCreateSimpleProperty(ep, op, property));
		if (vp && ejsWriteVar(ep, vp, (EjsVar*) value, EJS_SHALLOW_COPY) < 0) {
			mprAssert(0);
			op->objectState->hasErrors = 1;
			return 0;
		}

	} else {
		vp = (op->objectState->methods->setProperty)(ep, op, property, value);
	}

	if (vp == 0) {
		mprAssert(vp);
		op->objectState->hasErrors = 1;
		return 0;
	}
	
	if (vp->type == EJS_TYPE_OBJECT) {
		/*
		 *	We make an object alive (and subject to garbage collection) when
		 *	it is referenced in some other object. If this is undesirable, the
		 *	caller should make the object permanent while calling this routine
		 *	and then afterward clear the alive bit by calling ejsMakeObjLive().
		 */
		if (op->objectState != vp->objectState) {
			vp->objectState->alive = 1;
		}
#if BLD_DEBUG
		{
			EjsProperty	*pp = ejsGetPropertyPtr(vp);
			ejsSetVarName(ep, vp, &pp->name[0]);
			if (value->propertyName == 0) {
				ejsSetVarName(ep, (EjsVar*) value, &pp->name[0]);
			}
		}
#endif
	}

	/*
	 *	Trap assignments to array.length. MOB - find a better way.
	 */
	if (vp->isArrayLength) {
		ejsSetArrayLength(ep, op, 0, 0, value);
	}

	op->objectState->dirty = 1;

	return vp;
}

/******************************************************************************/

EjsVar *ejsGetPropertyMethod(Ejs *ep, EjsVar *op, const char *property)
{
	mprAssert(ep);
	mprAssert(op);
	mprAssert(property && *property);

	if (op == 0) {
		return 0;
	}

	mprAssert(op->type == EJS_TYPE_OBJECT);
	mprAssert(op->objectState);

	if (op->objectState == 0) {
		return 0;
	}

	if (op->objectState->methods == 0) {
		return ejsGetVarPtr(ejsGetSimpleProperty(ep, op, property));
	} else {
		return (op->objectState->methods->getProperty)(ep, op, property);
	}
}

/******************************************************************************/
/*************************** Advisory Locking Support *************************/
/******************************************************************************/
#if BLD_FEATURE_MULTITHREAD

void ejsLockObj(EjsVar *vp)
{
	mprAssert(vp);
	mprAssert(vp->type == EJS_TYPE_OBJECT);
	mprAssert(vp->objectState);

	if (vp->objectState->mutex == 0) {
		vp->objectState->mutex = mprCreateLock(vp->objectState->ejs);
	}
	mprLock(vp->objectState->mutex);
}

/******************************************************************************/

void ejsUnlockObj(EjsVar *vp)
{
	mprAssert(vp);
	mprAssert(vp->type == EJS_TYPE_OBJECT);
	mprAssert(vp->objectState);

	if (vp->objectState->mutex) {
		mprUnlock(vp->objectState->mutex);
	}
}

#endif
/******************************************************************************/
/************************** Internal Support Routines *************************/
/******************************************************************************/
/*
 *	Create an object.
 */

static EjsObj *createObj(EJS_LOC_DEC(ep, loc))
{
	EjsObj			*op;
	EjsPropLink		*lp;

	op = (EjsObj*) ejsAllocObj(EJS_LOC_PASS(ep, loc));
	if (op == NULL) {
		return 0;
	}

	/*
	 *	The objectState holds the dummy head for the ordered list of properties
	 */
	lp = &op->link;
	lp->next = lp->prev = lp;

#if BLD_DEBUG
	/*
	 *	This makes it much easier to debug the list
	 */
	lp->head = lp;
	lp->propertyName = "dummyHead";
#endif

	return op;
}

/******************************************************************************/
/*
 *	Destroy an object. Called by the garbage collector if there are no more 
 *	references to an object.
 */

int ejsDestroyObj(Ejs *ep, EjsObj *obj)
{
	EjsProperty		*pp;
	EjsPropLink		*lp, *head, *nextLink;

	mprAssert(obj);

	if (obj->destructor) {
		EjsVar	v;
		memset(&v, 0, sizeof(v));
		v.type = EJS_TYPE_OBJECT;
		v.objectState = obj;
		ejsSetVarName(ep, &v, "destructor");

#if BLD_FEATURE_ALLOC_LEAK_TRACK
		v.gc.allocatedBy = "static";
#endif

		if ((obj->destructor)(ep, &v) < 0) {
			return -1;
		}
	}
	mprFree(obj->objName);
	obj->objName = 0;

	/*
	 *	Just for safety. An object may be marked by a GC on the default 
 	 *	interpreter. After destroying, it won't be on the free list and so
	 *	won't be reset.
	 */
	obj->gcMarked = 0;
	obj->visited = 0;

	head = &obj->link;
	for (lp = head->next; lp != head; lp = nextLink) {

		pp = ejsGetPropertyFromLink(lp);
		nextLink = lp->next;

		/*
		 *	We don't unlink as we are destroying all properties.
 		 *	If an object, we don't need to clear either.
		 */
		if (pp->var.type != EJS_TYPE_OBJECT) {
			ejsClearVar(ep, ejsGetVarPtr(pp));
		}
		ejsFree(ep, pp, EJS_SLAB_PROPERTY);
	}

#if BLD_FEATURE_MULTITHREAD
	if (obj->mutex) {
		mprDestroyLock(obj->mutex);
	}
#endif

	ejsFree(ep, obj, EJS_SLAB_OBJ);
	return 0;
}

/******************************************************************************/
/*
 *	Fast hash. The history of this algorithm is part of lost computer science 
 *	folk lore.
 */

static int hash(const char *property)
{
	uint	sum;

	mprAssert(property);

	sum = 0;
	while (*property) {
		sum += (sum * 33) + *property++;
	}

	return sum % EJS_OBJ_HASH_SIZE;
}

/******************************************************************************/
/*
 *	Set a new length for an array. If create is non-null, then it is the name
 *	of a new array index. If delete is set, it is the name of an index being
 *	deleted. If setLength is set to a variable, it counts the new length for the
 *	array. Note that create and delete are ignored if they are non-integer 
 *	array indexes (eg. normal properties).
 */

void ejsSetArrayLength(Ejs *ep, EjsVar *obj, const char *create, 
	const char *delete, const EjsVar *setLength)
{
	EjsVar			*vp;
	char			idx[16];
	int				oldSize, newSize, i;

	vp = ejsGetPropertyAsVar(ep, obj, "length");
 	oldSize = vp->integer;
	newSize = oldSize;

	if (create) {
		if (isdigit(*create)) {
			i = atoi(create);
			newSize = max(i + 1, oldSize);
		}
	} else if (delete) {
		if (isdigit(*delete)) {
			i = atoi(delete);
			newSize = (i == (oldSize - 1) ? oldSize - 1 : oldSize);
		}
	} else {
		newSize = setLength->integer;
	}

	for (i = newSize; i < oldSize; i++) {
		mprItoa(idx, sizeof(idx), i);
		ejsDeleteProperty(ep, obj, idx);
	}
	
	if (ejsWriteVarAsInteger(ep, vp, newSize) == 0) {
		mprAssert(0);
	}
}

/******************************************************************************/

void ejsClearObjErrors(EjsVar *vp)
{
	if (vp == 0 || vp->type != EJS_TYPE_OBJECT || vp->objectState == 0) {
		mprAssert(0);
		return;
	}
	vp->objectState->hasErrors = 0;
}

/******************************************************************************/

int ejsObjHasErrors(EjsVar *vp)
{
	if (vp == 0 || vp->type != EJS_TYPE_OBJECT || vp->objectState == 0) {
		mprAssert(0);
		return -1;
	}
	return vp->objectState->hasErrors;
}

/******************************************************************************/

bool ejsIsObjDirty(EjsVar *vp)
{
	mprAssert(vp->type == EJS_TYPE_OBJECT && vp->objectState);

	if (vp->type == EJS_TYPE_OBJECT && vp->objectState) {
		return vp->objectState->dirty;
	}
	return 0;
}

/******************************************************************************/

void ejsResetObjDirtyBit(EjsVar *vp)
{
	mprAssert(vp->type == EJS_TYPE_OBJECT && vp->objectState);

	if (vp->type == EJS_TYPE_OBJECT && vp->objectState) {
		vp->objectState->dirty = 0;
	}
}

/******************************************************************************/
/*
 *	Copy a string. Always null terminate.
 */

static int dupString(MPR_LOC_DEC(ctx, loc), uchar **dest, const void *src, 
	int nbytes)
{
	mprAssert(dest);
	mprAssert(src);

	if (nbytes > 0) {
		*dest = mprMemdupInternal(MPR_LOC_PASS(ctx, loc), src, nbytes + 1);
		if (*dest == 0) {
			return MPR_ERR_MEMORY;
		}

	} else {
		*dest = (uchar*) mprAlloc(ctx, 1);
		nbytes = 0;
	}

	(*dest)[nbytes] = '\0';

	return nbytes;
}

/******************************************************************************/

const char *ejsGetVarTypeAsString(EjsVar *vp)
{
	switch (vp->type) {
	default:
	case EJS_TYPE_UNDEFINED:
		return "undefined";
	case EJS_TYPE_NULL:
		return "null";
	case EJS_TYPE_BOOL:
		return "bool";
	case EJS_TYPE_CMETHOD:
		return "cmethod";
	case EJS_TYPE_FLOAT:
		return "float";
	case EJS_TYPE_INT:
		return "int";
	case EJS_TYPE_INT64:
		return "int64";
	case EJS_TYPE_OBJECT:
		return "object";
	case EJS_TYPE_METHOD:
		return "method";
	case EJS_TYPE_STRING:
		return "string";
	case EJS_TYPE_STRING_CMETHOD:
		return "string method";
	case EJS_TYPE_PTR:
		return "ptr";
	}
}

/******************************************************************************/

void *ejsGetVarUserPtr(EjsVar *vp)
{
	mprAssert(vp);
	mprAssert(vp->type == EJS_TYPE_PTR);

	if (!ejsVarIsPtr(vp)) {
		return 0;
	}
	return vp->ptr.userPtr;
}

/******************************************************************************/

void ejsSetVarUserPtr(EjsVar *vp, void *data)
{
	mprAssert(vp);
	mprAssert(vp->type == EJS_TYPE_PTR);

	vp->ptr.userPtr = data;
}

/******************************************************************************/
/*
 *	Return TRUE if target is a subclass (or the same class) as baseClass.
 */

bool ejsIsSubClass(EjsVar *target, EjsVar *baseClass)
{
	do {
		if (target->objectState == baseClass->objectState) {
			return 1;
		}
		target = target->objectState->baseClass;
	} while (target);

	return 0;
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
