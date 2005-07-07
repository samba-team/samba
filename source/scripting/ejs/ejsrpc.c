/* 
   Unix SMB/CIFS implementation.

   provide interfaces to rpc calls from ejs scripts

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
#include "scripting/ejs/ejsrpc.h"

NTSTATUS ejs_pull_rpc(int eid, const char *callname, 
		      struct MprVar *v, void *ptr, ejs_pull_function_t ejs_pull)
{
	struct ejs_rpc *ejs = talloc(ptr, struct ejs_rpc);	
	NT_STATUS_HAVE_NO_MEMORY(ejs);
	ejs->eid = eid;
	ejs->callname = callname;
	return ejs_pull(ejs, v, ptr);
}


NTSTATUS ejs_push_rpc(int eid, const char *callname, 
		      struct MprVar *v, const void *ptr, ejs_push_function_t ejs_push)
{
	struct ejs_rpc *ejs = talloc(ptr, struct ejs_rpc);
	NT_STATUS_HAVE_NO_MEMORY(ejs);
	ejs->eid = eid;
	ejs->callname = callname;
	return ejs_push(ejs, v, ptr);
}


/*
  panic in the ejs wrapper code
 */
NTSTATUS ejs_panic(struct ejs_rpc *ejs, const char *why)
{
	ejsSetErrorMsg(ejs->eid, "rpc_call '%s' failed - %s", ejs->callname, why);
	return NT_STATUS_INTERNAL_ERROR;
}

/*
  find a mpr component, allowing for sub objects, using the '.' convention
*/
static struct MprVar *mprGetVar(struct MprVar *v, const char *name)
{
	const char *p = strchr(name, '.');
	char *objname;
	struct MprVar *v2;
	if (p == NULL) {
		return mprGetProperty(v, name, NULL);
	}
	objname = talloc_strndup(mprMemCtx(), name, p-name);
	if (objname == NULL) {
		return NULL;
	}
	v2 = mprGetProperty(v, objname, NULL);
	if (v2 == NULL) {
		talloc_free(objname);
		return NULL;
	}
	v2 = mprGetVar(v2, p+1);
	talloc_free(objname);
	return v2;
}


/*
  set a mpr component, allowing for sub objects, using the '.' convention
*/
static NTSTATUS mprSetVar(struct MprVar *v, const char *name, struct MprVar val)
{
	const char *p = strchr(name, '.');
	char *objname;
	struct MprVar *v2;
	NTSTATUS status;
	if (p == NULL) {
		v2 = mprSetProperty(v, name, &val);
		if (v2 == NULL) {
			return NT_STATUS_INVALID_PARAMETER_MIX;
		}
		return NT_STATUS_OK;
	}
	objname = talloc_strndup(mprMemCtx(), name, p-name);
	if (objname == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	v2 = mprGetProperty(v, objname, NULL);
	if (v2 == NULL) {
		struct MprVar val2 = mprCreateObjVar(objname, MPR_DEFAULT_HASH_SIZE);
		v2 = mprCreateProperty(v, objname, &val2);
	}
	status = mprSetVar(v2, p+1, val);
	talloc_free(objname);
	return status;
}


/*
  start the ejs pull process for a structure
*/
NTSTATUS ejs_pull_struct_start(struct ejs_rpc *ejs, struct MprVar **v, const char *name)
{
	*v = mprGetProperty(*v, name, NULL);
	if (*v == NULL) {
		return NT_STATUS_INVALID_PARAMETER;
	}
	return NT_STATUS_OK;
}


/*
  start the ejs push process for a structure
*/
NTSTATUS ejs_push_struct_start(struct ejs_rpc *ejs, struct MprVar **v, const char *name)
{
	struct MprVar s = mprCreateObjVar(name, MPR_DEFAULT_HASH_SIZE);
	*v = mprSetProperty(*v, name, &s);
	if (*v == NULL) {
		return NT_STATUS_INVALID_PARAMETER;
	}
	return NT_STATUS_OK;
}

/*
  pull a uint8 from a mpr variable to a C element
*/
NTSTATUS ejs_pull_uint8(struct ejs_rpc *ejs, 
			struct MprVar *v, const char *name, uint8_t *r)
{
	struct MprVar *var;
	var = mprGetVar(v, name);
	if (var == NULL) {
		return NT_STATUS_INVALID_PARAMETER_MIX;
	}
	*r = mprVarToInteger(var);
	return NT_STATUS_OK;
	
}

NTSTATUS ejs_push_uint8(struct ejs_rpc *ejs, 
			struct MprVar *v, const char *name, const uint8_t *r)
{
	return mprSetVar(v, name, mprCreateIntegerVar(*r));
}

/*
  pull a uint16 from a mpr variable to a C element
*/
NTSTATUS ejs_pull_uint16(struct ejs_rpc *ejs, 
			 struct MprVar *v, const char *name, uint16_t *r)
{
	struct MprVar *var;
	var = mprGetVar(v, name);
	if (var == NULL) {
		return NT_STATUS_INVALID_PARAMETER_MIX;
	}
	*r = mprVarToInteger(var);
	return NT_STATUS_OK;
	
}

NTSTATUS ejs_push_uint16(struct ejs_rpc *ejs, 
			 struct MprVar *v, const char *name, const uint16_t *r)
{
	return mprSetVar(v, name, mprCreateIntegerVar(*r));
}

/*
  pull a uint32 from a mpr variable to a C element
*/
NTSTATUS ejs_pull_uint32(struct ejs_rpc *ejs, 
			 struct MprVar *v, const char *name, uint32_t *r)
{
	struct MprVar *var;
	var = mprGetVar(v, name);
	if (var == NULL) {
		return NT_STATUS_INVALID_PARAMETER_MIX;
	}
	*r = mprVarToInteger(var);
	return NT_STATUS_OK;
}

NTSTATUS ejs_push_uint32(struct ejs_rpc *ejs, 
			 struct MprVar *v, const char *name, const uint32_t *r)
{
	return mprSetVar(v, name, mprCreateIntegerVar(*r));
}

NTSTATUS ejs_pull_hyper(struct ejs_rpc *ejs, 
			struct MprVar *v, const char *name, uint64_t *r)
{
	struct MprVar *var;
	var = mprGetVar(v, name);
	if (var == NULL) {
		return NT_STATUS_INVALID_PARAMETER_MIX;
	}
	*r = mprVarToInteger(var);
	return NT_STATUS_OK;
}

NTSTATUS ejs_push_hyper(struct ejs_rpc *ejs, 
			struct MprVar *v, const char *name, const uint64_t *r)
{
	return mprSetVar(v, name, mprCreateIntegerVar(*r));
}


/*
  pull a enum from a mpr variable to a C element
  a enum is just treating as an unsigned integer at this level
*/
NTSTATUS ejs_pull_enum(struct ejs_rpc *ejs, 
		       struct MprVar *v, const char *name, unsigned *r)
{
	struct MprVar *var;
	var = mprGetVar(v, name);
	if (var == NULL) {
		return NT_STATUS_INVALID_PARAMETER_MIX;
	}
	*r = mprVarToInteger(var);
	return NT_STATUS_OK;
	
}

NTSTATUS ejs_push_enum(struct ejs_rpc *ejs, 
		       struct MprVar *v, const char *name, const unsigned *r)
{
	return mprSetVar(v, name, mprCreateIntegerVar(*r));
}


/*
  pull an array of elements
*/
NTSTATUS ejs_pull_array(struct ejs_rpc *ejs, 
			struct MprVar *v, const char *name, uint32_t length,
			size_t elsize, void **r, ejs_pull_t ejs_pull)
{
	int i;
	char *data;

	NDR_CHECK(ejs_pull_struct_start(ejs, &v, name));

	(*r) = talloc_array_size(ejs, elsize, length);
	NT_STATUS_HAVE_NO_MEMORY(*r);

	data = *r;

	for (i=0;i<length;i++) {
		char *id = talloc_asprintf(ejs, "%u", i);
		NT_STATUS_HAVE_NO_MEMORY(id);
		NDR_CHECK(ejs_pull(ejs, v, id, (i*elsize)+data));
		talloc_free(id);
	}
	return NT_STATUS_OK;
}


/*
  push an array of elements
*/
NTSTATUS ejs_push_array(struct ejs_rpc *ejs, 
			struct MprVar *v, const char *name, uint32_t length,
			size_t elsize, void *r, ejs_push_t ejs_push)
{
	int i;
	char *data;

	NDR_CHECK(ejs_push_struct_start(ejs, &v, name));

	data = r;

	for (i=0;i<length;i++) {
		char *id = talloc_asprintf(ejs, "%u", i);
		NT_STATUS_HAVE_NO_MEMORY(id);
		NDR_CHECK(ejs_push(ejs, v, id, (i*elsize)+data));
		talloc_free(id);
	}
	return mprSetVar(v, "length", mprCreateIntegerVar(i));
}
			

/*
  pull a string
*/
NTSTATUS ejs_pull_string(struct ejs_rpc *ejs, 
			 struct MprVar *v, const char *name, const char **s)
{
	struct MprVar *var;
	var = mprGetVar(v, name);
	if (var == NULL) {
		return NT_STATUS_INVALID_PARAMETER_MIX;
	}
	*s = mprToString(var);
	return NT_STATUS_OK;
}

/*
  push a string
*/
NTSTATUS ejs_push_string(struct ejs_rpc *ejs, 
			 struct MprVar *v, const char *name, const char *s)
{
	return mprSetVar(v, name, mprCreateStringVar(s, True));
}
