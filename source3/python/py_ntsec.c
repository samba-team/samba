/* 
   Python wrappers for DCERPC/SMB client routines.

   Copyright (C) Tim Potter, 2002
   
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
#include "Python.h"

#include "python/py_common.h"

/* Convert a SID to a Python dict */

BOOL py_from_SID(PyObject **obj, DOM_SID *sid)
{
	fstring sidstr;

	if (!sid) {
		Py_INCREF(Py_None);
		*obj = Py_None;
		return True;
	}

	if (!sid_to_string(sidstr, sid))
		return False;

	*obj = PyString_FromString(sidstr);

	return True;
}

BOOL py_to_SID(DOM_SID *sid, PyObject *obj)
{
	BOOL result;

	if (!PyString_Check(obj))
		return False;

	result = string_to_sid(sid, PyString_AsString(obj));

	if (result)
		DEBUG(0, ("py: got sid %s\n", PyString_AsString(obj)));

	return result;
}

BOOL py_from_ACE(PyObject **dict, SEC_ACE *ace)
{
	PyObject *obj;

	if (!ace) {
		Py_INCREF(Py_None);
		*dict = Py_None;
		return True;
	}

	*dict = PyDict_New();

	PyDict_SetItemString(*dict, "type", PyInt_FromLong(ace->type));
	PyDict_SetItemString(*dict, "flags", PyInt_FromLong(ace->flags));
	PyDict_SetItemString(*dict, "mask", PyInt_FromLong(ace->info.mask));

	if (py_from_SID(&obj, &ace->trustee))
		PyDict_SetItemString(*dict, "trustee", obj);

	return True;
}

BOOL py_to_ACE(SEC_ACE *ace, PyObject *dict)
{
	PyObject *obj;
	uint8 ace_type, ace_flags;
	DOM_SID trustee;
	SEC_ACCESS sec_access;

	if (!PyDict_Check(dict))
		return False;

	if (!(obj = PyDict_GetItemString(dict, "type")) ||
	    !PyInt_Check(obj))
		return False;

	ace_type = PyInt_AsLong(obj);

	DEBUG(0, ("py: got ace_type %d\n", ace_type));

	if (!(obj = PyDict_GetItemString(dict, "flags")) ||
	    !PyInt_Check(obj))
		return False;

	ace_flags = PyInt_AsLong(obj);

	DEBUG(0, ("py: got ace_flags %d\n", ace_flags));

	if (!(obj = PyDict_GetItemString(dict, "trustee")) ||
	    !PyString_Check(obj))
		return False;

	if (!py_to_SID(&trustee, obj))
		return False;

	DEBUG(0, ("py: got trustee\n"));

	if (!(obj = PyDict_GetItemString(dict, "mask")) ||
	    !PyInt_Check(obj))
		return False;

	sec_access.mask = PyInt_AsLong(obj);

	DEBUG(0, ("py: got mask 0x%08x\n", sec_access.mask));

	init_sec_ace(ace, &trustee, ace_type, sec_access, ace_flags);

	return True;
}

BOOL py_from_ACL(PyObject **dict, SEC_ACL *acl)
{
	PyObject *ace_list;
	int i;

	if (!acl) {
		Py_INCREF(Py_None);
		*dict = Py_None;
		return True;
	}

	*dict = PyDict_New();

	PyDict_SetItemString(*dict, "revision", PyInt_FromLong(acl->revision));

	ace_list = PyList_New(acl->num_aces);

	for (i = 0; i < acl->num_aces; i++) {
		PyObject *obj;

		if (py_from_ACE(&obj, &acl->ace[i]))
			PyList_SetItem(ace_list, i, obj);
	}

	PyDict_SetItemString(*dict, "ace_list", ace_list);

	return True;
}

BOOL py_to_ACL(SEC_ACL *acl, PyObject *dict, TALLOC_CTX *mem_ctx)
{
	PyObject *obj;
	uint32 i;

	if (!(obj = PyDict_GetItemString(dict, "revision")) ||
	    !PyInt_Check(obj))
		return False;

	acl->revision = PyInt_AsLong(obj);

	DEBUG(0, ("py: got revision %d\n", acl->revision));

	if (!(obj = PyDict_GetItemString(dict, "ace_list")) ||
	    !PyList_Check(obj)) 
		return False;
	
	acl->num_aces = PyList_Size(obj);

	DEBUG(0, ("py: got num_aces %d\n", acl->num_aces));

	acl->ace = talloc(mem_ctx, acl->num_aces * sizeof(SEC_ACE));

	for (i = 0; i < acl->num_aces; i++) {
		PyObject *py_ace = PyList_GetItem(obj, i);

		if (!py_to_ACE(acl->ace, py_ace))
			return False;

		DEBUG(0, ("py: got ace %d\n", i));
	}

	return True;
}

BOOL py_from_SECDESC(PyObject **dict, SEC_DESC *sd)
{
	PyObject *obj;

	*dict = PyDict_New();

	PyDict_SetItemString(*dict, "revision", PyInt_FromLong(sd->revision));

	if (py_from_SID(&obj, sd->owner_sid))
		PyDict_SetItemString(*dict, "owner_sid", obj);

	if (py_from_SID(&obj, sd->grp_sid))
		PyDict_SetItemString(*dict, "group_sid", obj);

	if (py_from_ACL(&obj, sd->dacl))
		PyDict_SetItemString(*dict, "dacl", obj);

	if (py_from_ACL(&obj, sd->sacl))
		PyDict_SetItemString(*dict, "sacl", obj);

	return True;
}

BOOL py_to_SECDESC(SEC_DESC **sd, PyObject *dict, TALLOC_CTX *mem_ctx)
{
	PyObject *obj;
	uint16 revision;
	DOM_SID owner_sid, group_sid;
	SEC_ACL sacl, dacl;
	size_t sd_size;
	BOOL got_dacl = False, got_sacl = False;

	ZERO_STRUCT(dacl); ZERO_STRUCT(sacl);
	ZERO_STRUCT(owner_sid); ZERO_STRUCT(group_sid);

	if (!(obj = PyDict_GetItemString(dict, "revision")))
		return False;

	revision = PyInt_AsLong(obj);

	if (!(obj = PyDict_GetItemString(dict, "owner_sid")))
		return False;

	if (!py_to_SID(&owner_sid, obj))
		return False;

	if (!(obj = PyDict_GetItemString(dict, "group_sid")))
		return False;

	if (!py_to_SID(&group_sid, obj))
		return False;

	if ((obj = PyDict_GetItemString(dict, "dacl"))) {

		if (!py_to_ACL(&dacl, obj, mem_ctx))
			return False;

		got_dacl = True;
	}

	DEBUG(0, ("py: got dacl\n"));

	if ((obj = PyDict_GetItemString(dict, "sacl"))) {
		if (obj != Py_None) {

			if (!py_to_ACL(&sacl, obj, mem_ctx))
				return False;

			got_sacl = True;
		}
	}

	DEBUG(0, ("py: got sacl\n"));

	*sd = make_sec_desc(mem_ctx, revision, &owner_sid, &group_sid,
			    got_sacl ? &sacl : NULL, 
			    got_dacl ? &dacl : NULL, &sd_size);
	
	return True;
}
