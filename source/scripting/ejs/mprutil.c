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
  add an indexed array element to a property
*/
static void mprAddArray(struct MprVar *var, int i, struct MprVar v)
{
	char idx[16];
	mprItoa(i, idx, sizeof(idx));
	mprCreateProperty(var, idx, &v);
}

/*
  construct a MprVar from a list
*/
struct MprVar mprList(const char *name, const char **list)
{
	struct MprVar var;
	int i;

	var = mprCreateObjVar(name, MPR_DEFAULT_HASH_SIZE);
	for (i=0;list && list[i];i++) {
		mprAddArray(&var, i, mprCreateStringVar(list[i], 1));
	}
	return var;
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
	var = mprCreateStringVar(s, 1);
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
	struct MprVar val;

	var = mprCreateObjVar(msg->dn, MPR_DEFAULT_HASH_SIZE);

	for (i=0;i<msg->num_elements;i++) {
		struct ldb_message_element *el = &msg->elements[i];
		if (el->num_values == 1 &&
		    !str_list_check_ci(multivalued, el->name)) {
			val = mprData(el->values[0].data, el->values[0].length);
		} else {
			int j;
			val = mprCreateObjVar(el->name, MPR_DEFAULT_HASH_SIZE);
			for (j=0;j<el->num_values;j++) {
				mprAddArray(&val, j, 
					    mprData(el->values[j].data, 
						    el->values[j].length));
			}
		}
		mprCreateProperty(&var, el->name, &val);
	}

	/* add the dn if it is not already specified */
	if (mprGetProperty(&var, "dn", 0) == 0) {
		val = mprCreateStringVar(msg->dn, 1);
		mprCreateProperty(&var, "dn", &val);
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

	res = mprCreateObjVar(name?name:"(NULL)", MPR_DEFAULT_HASH_SIZE);
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
	if (v->type != MPR_TYPE_STRING) return NULL;
	return v->string;
}

/*
  turn a MprVar integer variable into an int
 */
int mprToInt(const struct MprVar *v)
{
	if (v->type != MPR_TYPE_INT) return 0;
	return v->integer;
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
  turn a NTSTATUS into a MprVar object with lots of funky properties
*/
struct MprVar mprNTSTATUS(NTSTATUS status)
{
	struct MprVar res, val;

	res = mprCreateObjVar("ntstatus", MPR_DEFAULT_HASH_SIZE);

	val = mprCreateStringVar(nt_errstr(status), 1);
	mprCreateProperty(&res, "errstr", &val);

	val = mprCreateIntegerVar(NT_STATUS_V(status));
	mprCreateProperty(&res, "v", &val);

	val = mprCreateBoolVar(NT_STATUS_IS_OK(status));
	mprCreateProperty(&res, "is_ok", &val);

	val = mprCreateBoolVar(NT_STATUS_IS_ERR(status));
	mprCreateProperty(&res, "is_err", &val);

	return res;
}

/*
  turn a WERROR into a MprVar object with lots of funky properties
*/
struct MprVar mprWERROR(WERROR status)
{
	struct MprVar res, val;

	res = mprCreateObjVar("werror", MPR_DEFAULT_HASH_SIZE);

	val = mprCreateStringVar(win_errstr(status), 1);
	mprCreateProperty(&res, "errstr", &val);

	val = mprCreateIntegerVar(W_ERROR_V(status));
	mprCreateProperty(&res, "v", &val);

	val = mprCreateBoolVar(W_ERROR_IS_OK(status));
	mprCreateProperty(&res, "is_ok", &val);

	val = mprCreateBoolVar(True);
	mprCreateProperty(&res, "is_err", &val);

	return res;
}


/*
  set a pointer in a existing MprVar
*/
void mprSetPtr(struct MprVar *v, const char *propname, const void *p)
{
	struct MprVar val = mprCreatePtrVar(discard_const(p), NULL);
	mprCreateProperty(v, propname, &val);
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
