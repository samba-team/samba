/* 
   Unix SMB/CIFS implementation.

   utility functions for manipulating mpr variables in ejs calls

   Copyright (C) Andrew Tridgell 2005
   
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/

#include "includes.h"
#include "lib/ejs/ejs.h"
#include "lib/ldb/include/ldb.h"

/*
  return a default mpr object
*/
struct MprVar mprObject(const char *name)
{
	return ejsCreateObj(name?name:"(NULL)", MPR_DEFAULT_HASH_SIZE);
}

/*
  find a mpr component, allowing for sub objects, using the '.' convention
*/
 NTSTATUS mprGetVar(struct MprVar **v, const char *name)
{
	const char *p = strchr(name, '.');
	char *objname;
	NTSTATUS status;
	if (p == NULL) {
		*v = mprGetProperty(*v, name, NULL);
		if (*v == NULL) {
			DEBUG(1,("mprGetVar unable to find '%s'\n", name));
			return NT_STATUS_INVALID_PARAMETER;
		}
		return NT_STATUS_OK;
	}
	objname = talloc_strndup(mprMemCtx(), name, p-name);
	NT_STATUS_HAVE_NO_MEMORY(objname);
	*v = mprGetProperty(*v, objname, NULL);
	NT_STATUS_HAVE_NO_MEMORY(*v);
	status = mprGetVar(v, p+1);
	talloc_free(objname);
	return status;
}


/*
  set a mpr component, allowing for sub objects, using the '.' convention
  destroys 'val' after setting
*/
 NTSTATUS mprSetVar(struct MprVar *v, const char *name, struct MprVar val)
{
	const char *p = strchr(name, '.');
	char *objname;
	struct MprVar *v2;
	NTSTATUS status;
	if (p == NULL) {
		v2 = mprSetProperty(v, name, &val);
		if (v2 == NULL) {
			DEBUG(1,("mprSetVar unable to set '%s'\n", name));
			return NT_STATUS_INVALID_PARAMETER_MIX;
		}
		mprDestroyVar(&val);
		return NT_STATUS_OK;
	}
	objname = talloc_strndup(mprMemCtx(), name, p-name);
	if (objname == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	v2 = mprGetProperty(v, objname, NULL);
	if (v2 == NULL) {
		mprSetVar(v, objname, mprObject(objname));
		v2 = mprGetProperty(v, objname, NULL);
	}
	status = mprSetVar(v2, p+1, val);
	talloc_free(objname);
	return status;
}



/*
  add an indexed array element to a property
*/
 void mprAddArray(struct MprVar *var, int i, struct MprVar v)
{
	char idx[16];
	mprItoa(i, idx, sizeof(idx));
	mprSetVar(var, idx, v);
	mprSetVar(var, "length", mprCreateIntegerVar(i+1));
}

/*
  construct a MprVar from a list
*/
struct MprVar mprList(const char *name, const char **list)
{
	struct MprVar var;
	int i;

	var = mprObject(name);
	for (i=0;list && list[i];i++) {
		mprAddArray(&var, i, mprString(list[i]));
	}
	if (i==0) {
		mprSetVar(&var, "length", mprCreateIntegerVar(i));
	}
	return var;
}

/*
  construct a MprVar from a string, using NULL if needed
*/
struct MprVar mprString(const char *s)
{
	if (s == NULL) {
		return mprCreatePtrVar(NULL);
	}
	return mprCreateStringVar(s, True);
}

/*
  construct a string MprVar from a lump of data
*/
struct MprVar mprData(const uint8_t *p, size_t length)
{
	struct MprVar var;
	char *s = talloc_strndup(mprMemCtx(), p, length);
	if (s == NULL) {
		return mprCreateUndefinedVar();
	}
	var = mprString(s);
	talloc_free(s);
	return var;
}

/*
  turn a ldb_message into a ejs object variable
*/
struct MprVar mprLdbMessage(struct ldb_message *msg)
{
	struct MprVar var;
	int i;
	/* we force some attributes to always be an array in the
	   returned structure. This makes the scripting easier, as you don't 
	   need a special case for the single value case */
	const char *multivalued[] = { "objectClass", "memberOf", "privilege", 
					    "member", NULL };

	var = mprObject(msg->dn);

	for (i=0;i<msg->num_elements;i++) {
		struct ldb_message_element *el = &msg->elements[i];
		struct MprVar val;
		if (el->num_values == 1 &&
		    !str_list_check_ci(multivalued, el->name)) {
			val = mprData(el->values[0].data, el->values[0].length);
		} else {
			int j;
			val = mprObject(el->name);
			for (j=0;j<el->num_values;j++) {
				mprAddArray(&val, j, 
					    mprData(el->values[j].data, 
						    el->values[j].length));
			}
		}
		mprSetVar(&var, el->name, val);
	}

	/* add the dn if it is not already specified */
	if (mprGetProperty(&var, "dn", 0) == 0) {
		mprSetVar(&var, "dn", mprString(msg->dn));
	}
	
	return var;		
}


/*
  turn an array of ldb_messages into a ejs object variable
*/
struct MprVar mprLdbArray(struct ldb_message **msg, int count, const char *name)
{
	struct MprVar res;
	int i;

	res = mprObject(name);
	for (i=0;i<count;i++) {
		mprAddArray(&res, i, mprLdbMessage(msg[i]));
	}
	return res;
}


/*
  turn a MprVar string variable into a const char *
 */
const char *mprToString(const struct MprVar *v)
{
	if (!mprVarIsString(v->type)) return NULL;
	return v->string;
}

/*
  turn a MprVar integer variable into an int
 */
int mprToInt(const struct MprVar *v)
{
	if (!mprVarIsNumber(v->type)) return 0;
	return mprVarToNumber(v);
}

/*
  turn a MprVar object variable into a string list
  this assumes the object variable consists only of strings
*/
const char **mprToList(TALLOC_CTX *mem_ctx, struct MprVar *v)
{
	const char **list = NULL;
	struct MprVar *el;

	if (v->type != MPR_TYPE_OBJECT ||
	    v->properties == NULL) {
		return NULL;
	}
	for (el=mprGetFirstProperty(v, MPR_ENUM_DATA);
	     el;
	     el=mprGetNextProperty(v, el, MPR_ENUM_DATA)) {
		const char *s = mprToString(el);
		if (s) {
			list = str_list_add(list, s);
		}
	}
	talloc_steal(mem_ctx, list);
	return list;
}


/*
  turn a MprVar object variable into a string list
  this assumes the object variable is an array of strings
*/
const char **mprToArray(TALLOC_CTX *mem_ctx, struct MprVar *v)
{
	const char **list = NULL;
	struct MprVar *len;
	int length, i;

	len = mprGetProperty(v, "length", NULL);
	if (len == NULL) {
		return NULL;
	}
	length = mprToInt(len);

	for (i=0;i<length;i++) {
		char idx[16];
		struct MprVar *vs;
		mprItoa(i, idx, sizeof(idx));		
		vs = mprGetProperty(v, idx, NULL);
		if (vs == NULL || vs->type != MPR_TYPE_STRING) {
			talloc_free(list);
			return NULL;
		}
		list = str_list_add(list, mprToString(vs));
	}
	talloc_steal(mem_ctx, list);
	return list;
}

/*
  turn a NTSTATUS into a MprVar object with lots of funky properties
*/
struct MprVar mprNTSTATUS(NTSTATUS status)
{
	struct MprVar res;

	res = mprObject("ntstatus");

	mprSetVar(&res, "errstr", mprString(nt_errstr(status)));
	mprSetVar(&res, "v", mprCreateIntegerVar(NT_STATUS_V(status)));
	mprSetVar(&res, "is_ok", mprCreateBoolVar(NT_STATUS_IS_OK(status)));
	mprSetVar(&res, "is_err", mprCreateBoolVar(NT_STATUS_IS_ERR(status)));

	return res;
}

/*
  turn a WERROR into a MprVar object with lots of funky properties
*/
struct MprVar mprWERROR(WERROR status)
{
	struct MprVar res;

	res = mprObject("werror");

	mprSetVar(&res, "errstr", mprString(win_errstr(status)));
	mprSetVar(&res, "v", mprCreateIntegerVar(W_ERROR_V(status)));
	mprSetVar(&res, "is_ok", mprCreateBoolVar(W_ERROR_IS_OK(status)));
	mprSetVar(&res, "is_err", mprCreateBoolVar(!W_ERROR_IS_OK(status)));

	return res;
}


/*
  set a pointer in a existing MprVar
*/
void mprSetPtr(struct MprVar *v, const char *propname, const void *p)
{
	mprSetVar(v, propname, mprCreatePtrVar(discard_const(p)));
}

/*
  set a pointer in a existing MprVar, making it a child of the property
*/
void mprSetPtrChild(struct MprVar *v, const char *propname, const void *p)
{
	mprSetVar(v, propname, mprCreatePtrVar(discard_const(p)));
	talloc_steal(mprGetProperty(v, propname, NULL), p);
}

/*
  get a pointer from a MprVar
*/
void *mprGetPtr(struct MprVar *v, const char *propname)
{
	struct MprVar *val;
	val = mprGetProperty(v, propname, NULL);
	if (val == NULL) {
		return NULL;
	}
	if (val->type != MPR_TYPE_PTR) {
		return NULL;
	}
	return val->ptr;
}

/*
  set the return value then free the variable
*/
 void mpr_Return(int eid, struct MprVar v)
{ 
	ejsSetReturnValue(eid, v);
	mprDestroyVar(&v);
}

/*
  set the return value then free the variable
*/
void mpr_ReturnString(int eid, const char *s)
{ 
	mpr_Return(eid, mprString(s));
}


