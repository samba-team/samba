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
#include "lib/appweb/ejs/ejs.h"
#include "lib/ldb/include/ldb.h"
#include "scripting/ejs/smbcalls.h"

/*
  return a default mpr object
*/
struct MprVar mprObject(const char *name)
{
	return ejsCreateObj(name && *name?name:"(NULL)", MPR_DEFAULT_HASH_SIZE);
}

/*
  return a empty mpr array
*/
struct MprVar mprArray(const char *name)
{
	return ejsCreateArray(name && *name?name:"(NULL)", 0);
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
}

/*
  construct a MprVar from a list
*/
struct MprVar mprList(const char *name, const char **list)
{
	struct MprVar var;
	int i;

	var = mprArray(name);
	for (i=0;list && list[i];i++) {
		mprAddArray(&var, i, mprString(list[i]));
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
	char *s = talloc_strndup(mprMemCtx(), (const char *)p, length);
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
static struct MprVar mprLdbMessage(struct ldb_context *ldb, struct ldb_message *msg)
{
	struct MprVar var;
	int i;
	/* we force some attributes to always be an array in the
	   returned structure. This makes the scripting easier, as you don't 
	   need a special case for the single value case */
	const char *multivalued[] = { "objectClass", "memberOf", "privilege", 
					    "member", NULL };

	var = mprObject(ldb_dn_alloc_linearized(msg, msg->dn));

	for (i=0;i<msg->num_elements;i++) {
		struct ldb_message_element *el = &msg->elements[i];
		struct MprVar val;
		const struct ldb_schema_attribute *a;
		struct ldb_val v;

		a = ldb_schema_attribute_by_name(ldb, el->name);
		if (a == NULL) {
			goto failed;
		}

		if (el->num_values == 1 &&
		    !str_list_check_ci(multivalued, el->name)) {
			if (a->syntax->ldif_write_fn(ldb, msg, &el->values[0], &v) != 0) {
				goto failed;
			}
			/* FIXME: nasty hack, remove me when ejs will support
			 * arbitrary string and does not truncate on \0 */
			if (strlen((char *)v.data) != v.length) {
				val = mprDataBlob(v);
			} else {
				val = mprData(v.data, v.length);
			}
		} else {
			int j;
			val = mprArray(el->name);
			for (j=0;j<el->num_values;j++) {
				if (a->syntax->ldif_write_fn(ldb, msg, 
							     &el->values[j], &v) != 0) {
					goto failed;
				}
				/* FIXME: nasty hack, remove me when ejs will support
				 * arbitrary string and does not truncate on \0 */
				if (strlen((char *)v.data) != v.length) {
					mprAddArray(&val, j, mprDataBlob(v));
				} else {
					mprAddArray(&val, j, mprData(v.data, v.length));
				}
			}
		}
		mprSetVar(&var, el->name, val);
	}

	/* add the dn if it is not already specified */
	if (mprGetProperty(&var, "dn", 0) == 0) {
		mprSetVar(&var, "dn", mprString(ldb_dn_alloc_linearized(msg, msg->dn)));
	}
	
	return var;		
failed:
	return mprCreateUndefinedVar();
}


/*
  build a MprVar result object for ldb operations with lots of funky properties
*/
struct MprVar mprLdbResult(struct ldb_context *ldb, int err, struct ldb_result *result)
{
	struct MprVar ret;
	struct MprVar ary;

	ret = mprObject("ldbret");

	mprSetVar(&ret, "error", mprCreateIntegerVar(err));
	mprSetVar(&ret, "errstr", mprString(ldb_errstring(ldb)));

	ary = mprArray("ldb_message");
	if (result) {
		int i;

		for (i = 0; i < result->count; i++) {
			mprAddArray(&ary, i, mprLdbMessage(ldb, result->msgs[i]));
		}
	}

	mprSetVar(&ret, "msgs", ary);

	/* TODO: add referrals, exteded ops, and controls */

	return ret;
}


/*
  turn a MprVar string variable into a const char *
 */
const char *mprToString(struct MprVar *v)
{
	if (v->trigger) {
		mprReadProperty(v, 0);
	}
	if (!mprVarIsString(v->type)) return NULL;
	return v->string;
}

/*
  turn a MprVar integer variable into an int
 */
int mprToInt(struct MprVar *v)
{
	if (v->trigger) {
		mprReadProperty(v, 0);
	}
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
  create a data-blob in a mpr variable
*/
struct MprVar mprDataBlob(DATA_BLOB blob)
{
	struct MprVar res;
	struct datablob *pblob = talloc(mprMemCtx(), struct datablob);
	*pblob = data_blob_talloc(pblob, blob.data, blob.length);

	res = mprObject("DATA_BLOB");

	mprSetVar(&res, "size", mprCreateIntegerVar(blob.length));
	mprSetPtrChild(&res, "blob", pblob);

	return res;
}

/*
  return a data blob from a mpr var created using mprDataBlob
*/
struct datablob *mprToDataBlob(struct MprVar *v)
{
	return talloc_get_type(mprGetPtr(v, "blob"), struct datablob);
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
  set a pointer in a existing MprVar, freeing it when the property goes away
*/
void mprSetPtrChild(struct MprVar *v, const char *propname, const void *p)
{
	mprSetVar(v, propname, mprCreatePtrVar(discard_const(p)));
	v = mprGetProperty(v, propname, NULL);
	v->allocatedData = 1;
	talloc_steal(mprMemCtx(), p);
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


/*
  set a C function in a variable
*/
 void mprSetCFunction(struct MprVar *obj, const char *name, MprCFunction fn)
{
	mprSetVar(obj, name, mprCreateCFunctionVar(fn, obj, MPR_VAR_SCRIPT_HANDLE));
}

/*
  set a string C function in a variable
*/
 void mprSetStringCFunction(struct MprVar *obj, const char *name, MprStringCFunction fn)
{
	mprSetVar(obj, name, mprCreateStringCFunctionVar(fn, obj, MPR_VAR_SCRIPT_HANDLE));
}

/*
  get a pointer in the current object
*/
void *mprGetThisPtr(int eid, const char *name)
{
	struct MprVar *this = mprGetProperty(ejsGetLocalObject(eid), "this", 0);
	return mprGetPtr(this, name);
}

/*
  set a pointer as a child of the local object
*/
void mprSetThisPtr(int eid, const char *name, void *ptr)
{
	struct MprVar *this = mprGetProperty(ejsGetLocalObject(eid), "this", 0);
	mprSetPtrChild(this, name, ptr);
}

/*
  used by object xxx_init() routines to allow for the caller
  to supply a pre-existing object to add properties to,
  or create a new object. This makes inheritance easy
*/
struct MprVar *mprInitObject(int eid, const char *name, int argc, struct MprVar **argv)
{
	if (argc > 0 && mprVarIsObject(argv[0]->type)) {
		return argv[0];
	}
	mpr_Return(eid, mprObject(name));
	return ejsGetReturnValue(eid);
}
