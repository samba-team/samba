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

BOOL py_to_SID(DOM_SID *sid, PyObject *dict)
{
	return False;
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
	return False;
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

BOOL py_to_ACL(SEC_ACL *acl, PyObject *dict)
{
	return False;
}

BOOL py_from_SECDESC(PyObject **dict, SEC_DESC *sd)
{
	PyObject *obj;

	*dict = PyDict_New();

	PyDict_SetItemString(*dict, "revision", PyInt_FromLong(sd->revision));
	PyDict_SetItemString(*dict, "type", PyInt_FromLong(sd->type));

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

BOOL py_to_SECDESC(SEC_DESC *sd, PyObject *dict)
{
	return False;
}
