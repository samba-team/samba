/* 
   Unix SMB/CIFS implementation.

   Python wrapper for winbind client functions.

   Copyright (C) Tim Potter      2002
   
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

#include "py_common.h"

/* 
 * Exceptions raised by this module 
 */

PyObject *winbind_error;	/* A winbind call returned WINBINDD_ERROR */

/* Prototypes from common.h */

NSS_STATUS winbindd_request(int req_type, 
			    struct winbindd_request *request,
			    struct winbindd_response *response);

/*
 * Name <-> SID conversion
 */

/* Convert a name to a sid */

static PyObject *py_name_to_sid(PyObject *self, PyObject *args)

{
	struct winbindd_request request;
	struct winbindd_response response;
	PyObject *result;
	char *name, *p, *sep;

	if (!PyArg_ParseTuple(args, "s", &name))
		return NULL;

	ZERO_STRUCT(request);
	ZERO_STRUCT(response);

	sep = lp_winbind_separator();

	if ((p = strchr(name, sep[0]))) {
		*p = 0;
		fstrcpy(request.data.name.dom_name, name);
		fstrcpy(request.data.name.name, p + 1);
	} else {
		fstrcpy(request.data.name.dom_name, lp_workgroup());
		fstrcpy(request.data.name.name, name);
	}

	if (winbindd_request(WINBINDD_LOOKUPNAME, &request, &response)  
	    != NSS_STATUS_SUCCESS) {
		PyErr_SetString(winbind_error, "lookup failed");
		return NULL;
	}

	result = PyString_FromString(response.data.sid.sid);

	return result;
}

/* Convert a sid to a name */

static PyObject *py_sid_to_name(PyObject *self, PyObject *args)
{
	struct winbindd_request request;
	struct winbindd_response response;
	PyObject *result;
	char *sid, *name;

	if (!PyArg_ParseTuple(args, "s", &sid))
		return NULL;

	ZERO_STRUCT(request);
	ZERO_STRUCT(response);

	fstrcpy(request.data.sid, sid);

	if (winbindd_request(WINBINDD_LOOKUPSID, &request, &response)  
	    != NSS_STATUS_SUCCESS) {
		PyErr_SetString(winbind_error, "lookup failed");
		return NULL;
	}

	/* FIXME: use actual winbind separator */

	asprintf(&name, "%s%c%s", response.data.name.dom_name,
		 '\\', response.data.name.name);

	result = PyString_FromString(name);

	free(name);

	return result;
}

/*
 * Enumerate users/groups
 */

/* Enumerate domain users */

static PyObject *py_enum_domain_users(PyObject *self, PyObject *args)
{
	struct winbindd_response response;
	PyObject *result;

	if (!PyArg_ParseTuple(args, ""))
		return NULL;

	ZERO_STRUCT(response);

	if (winbindd_request(WINBINDD_LIST_USERS, NULL, &response) 
	    != NSS_STATUS_SUCCESS) {
		PyErr_SetString(winbind_error, "lookup failed");
		return NULL;		
	}

	result = PyList_New(0);

	if (response.extra_data) {
		char *extra_data = response.extra_data;
		fstring name;

		while (next_token(&extra_data, name, ",", sizeof(fstring)))
			PyList_Append(result, PyString_FromString(name));
	}

	return result;
}

/* Enumerate domain groups */

static PyObject *py_enum_domain_groups(PyObject *self, PyObject *args)
{
	struct winbindd_response response;
	PyObject *result = NULL;

	if (!PyArg_ParseTuple(args, ""))
		return NULL;

	ZERO_STRUCT(response);

	if (winbindd_request(WINBINDD_LIST_GROUPS, NULL, &response) 
	    != NSS_STATUS_SUCCESS) {
		PyErr_SetString(winbind_error, "lookup failed");
		return NULL;		
	}

	result = PyList_New(0);

	if (response.extra_data) {
		char *extra_data = response.extra_data;
		fstring name;

		while (next_token(&extra_data, name, ",", sizeof(fstring)))
			PyList_Append(result, PyString_FromString(name));
	}

	return result;
}

/*
 * Miscellaneous domain related
 */

/* Enumerate domain groups */

static PyObject *py_enum_trust_dom(PyObject *self, PyObject *args)
{
	struct winbindd_response response;
	PyObject *result = NULL;

	if (!PyArg_ParseTuple(args, ""))
		return NULL;

	ZERO_STRUCT(response);

	if (winbindd_request(WINBINDD_LIST_TRUSTDOM, NULL, &response) 
	    != NSS_STATUS_SUCCESS) {
		PyErr_SetString(winbind_error, "lookup failed");
		return NULL;		
	}

	result = PyList_New(0);

	if (response.extra_data) {
		char *extra_data = response.extra_data;
		fstring name;

		while (next_token(&extra_data, name, ",", sizeof(fstring)))
			PyList_Append(result, PyString_FromString(name));
	}

	return result;
}

/* Check machine account password */

static PyObject *py_check_secret(PyObject *self, PyObject *args)
{
	struct winbindd_response response;

	if (!PyArg_ParseTuple(args, ""))
		return NULL;

	ZERO_STRUCT(response);

	if (winbindd_request(WINBINDD_CHECK_MACHACC, NULL, &response) 
	    != NSS_STATUS_SUCCESS) {
		PyErr_SetString(winbind_error, "lookup failed");
		return NULL;		
	}

	return PyInt_FromLong(response.data.num_entries);
}

/*
 * Return a dictionary consisting of all the winbind related smb.conf
 * parameters.  This is stored in the module object.
 */

static PyObject *py_config_dict(void)
{
	PyObject *result;
	uid_t ulow, uhi;
	gid_t glow, ghi;
	
	if (!(result = PyDict_New()))
		return NULL;

	/* Various string parameters */

	PyDict_SetItemString(result, "workgroup", 
			     PyString_FromString(lp_workgroup()));

	PyDict_SetItemString(result, "separator", 
			     PyString_FromString(lp_winbind_separator()));

	PyDict_SetItemString(result, "template_homedir", 
			     PyString_FromString(lp_template_homedir()));

	PyDict_SetItemString(result, "template_shell", 
			     PyString_FromString(lp_template_shell()));

	/* Winbind uid/gid range */

	if (lp_winbind_uid(&ulow, &uhi)) {
		PyDict_SetItemString(result, "uid_low", PyInt_FromLong(ulow));
		PyDict_SetItemString(result, "uid_high", PyInt_FromLong(uhi));
	}

	if (lp_winbind_gid(&glow, &ghi)) {
		PyDict_SetItemString(result, "gid_low", PyInt_FromLong(glow));
		PyDict_SetItemString(result, "gid_high", PyInt_FromLong(ghi));
	}

	return result;
}

/*
 * ID mapping
 */

/* Convert a uid to a SID */

static PyObject *py_uid_to_sid(PyObject *self, PyObject *args)
{
	struct winbindd_request request;
	struct winbindd_response response;
	int id;

	if (!PyArg_ParseTuple(args, "i", &id))
		return NULL;

	ZERO_STRUCT(request);
	ZERO_STRUCT(response);

	request.data.uid = id;

	if (winbindd_request(WINBINDD_UID_TO_SID, &request, &response) 
	    != NSS_STATUS_SUCCESS) {
		PyErr_SetString(winbind_error, "lookup failed");
		return NULL;		
	}

	return PyString_FromString(response.data.sid.sid);
}

/* Convert a gid to a SID */

static PyObject *py_gid_to_sid(PyObject *self, PyObject *args)
{
	struct winbindd_request request;
	struct winbindd_response response;
	int id;

	if (!PyArg_ParseTuple(args, "i", &id))
		return NULL;

	ZERO_STRUCT(request);
	ZERO_STRUCT(response);

	request.data.gid = id;

	if (winbindd_request(WINBINDD_GID_TO_SID, &request, &response) 
	    != NSS_STATUS_SUCCESS) {
		PyErr_SetString(winbind_error, "lookup failed");
		return NULL;		
	}

	return PyString_FromString(response.data.sid.sid);
}

/* Convert a sid to a uid */

static PyObject *py_sid_to_uid(PyObject *self, PyObject *args)
{
	struct winbindd_request request;
	struct winbindd_response response;
	char *sid;

	if (!PyArg_ParseTuple(args, "s", &sid))
		return NULL;

	ZERO_STRUCT(request);
	ZERO_STRUCT(response);

	fstrcpy(request.data.sid, sid);

	if (winbindd_request(WINBINDD_SID_TO_UID, &request, &response) 
	    != NSS_STATUS_SUCCESS) {
		PyErr_SetString(winbind_error, "lookup failed");
		return NULL;		
	}

	return PyInt_FromLong(response.data.uid);
}

/* Convert a sid to a gid */

static PyObject *py_sid_to_gid(PyObject *self, PyObject *args)
{
	struct winbindd_request request;
	struct winbindd_response response;
	char *sid;

	if (!PyArg_ParseTuple(args, "s", &sid))
		return NULL;

	ZERO_STRUCT(request);
	ZERO_STRUCT(response);

	fstrcpy(request.data.sid, sid);

	if (winbindd_request(WINBINDD_SID_TO_GID, &request, &response) 
	    != NSS_STATUS_SUCCESS) {
		PyErr_SetString(winbind_error, "lookup failed");
		return NULL;		
	}
	
	return PyInt_FromLong(response.data.gid);
}

/*
 * Method dispatch table
 */

static PyMethodDef winbind_methods[] = {

	/* Name <-> SID conversion */

	{ "name_to_sid", py_name_to_sid, METH_VARARGS,
	  "Convert a name to a sid" },

	{ "sid_to_name", py_sid_to_name, METH_VARARGS,
	  "Convert a sid to a name" },

	/* Enumerate users/groups */

	{ "enum_domain_users", py_enum_domain_users, METH_VARARGS,
	  "Enumerate domain users" },

	{ "enum_domain_groups", py_enum_domain_groups, METH_VARARGS,
	  "Enumerate domain groups" },

	/* ID mapping */

	{ "uid_to_sid", py_uid_to_sid, METH_VARARGS,
	  "Convert a uid to a SID" },

	{ "gid_to_sid", py_gid_to_sid, METH_VARARGS,
	  "Convert a gid to a SID" },

	{ "sid_to_uid", py_sid_to_uid, METH_VARARGS,
	  "Convert a uid to a SID" },

	{ "sid_to_gid", py_sid_to_gid, METH_VARARGS,
	  "Convert a gid to a SID" },

	/* Miscellaneous */

	{ "check_secret", py_check_secret, METH_VARARGS,
	  "Check machine account password" },

	{ "enum_trust_dom", py_enum_trust_dom, METH_VARARGS,
	  "Enumerate trusted domains" },

	{ NULL }
};

static struct winbind_const {
	char *name;
	uint32 value;
} winbind_const_vals[] = {

	/* Well known RIDs */
	
	{ "DOMAIN_USER_RID_ADMIN", DOMAIN_USER_RID_ADMIN },
	{ "DOMAIN_USER_RID_GUEST", DOMAIN_USER_RID_GUEST },
	{ "DOMAIN_GROUP_RID_ADMINS", DOMAIN_GROUP_RID_ADMINS },
	{ "DOMAIN_GROUP_RID_USERS", DOMAIN_GROUP_RID_USERS },
	{ "DOMAIN_GROUP_RID_GUESTS", DOMAIN_GROUP_RID_GUESTS },
	
	{ NULL }
};

static void const_init(PyObject *dict)
{
	struct winbind_const *tmp;
	PyObject *obj;

	for (tmp = winbind_const_vals; tmp->name; tmp++) {
		obj = PyInt_FromLong(tmp->value);
		PyDict_SetItemString(dict, tmp->name, obj);
		Py_DECREF(obj);
	}
}

/*
 * Module initialisation 
 */

void initwinbind(void)
{
	PyObject *module, *dict;

	/* Initialise module */

	module = Py_InitModule("winbind", winbind_methods);
	dict = PyModule_GetDict(module);

	winbind_error = PyErr_NewException("winbind.error", NULL, NULL);
	PyDict_SetItemString(dict, "error", winbind_error);

	/* Do samba initialisation */

	py_samba_init();

	/* Initialise constants */

	const_init(dict);

	/* Insert configuration dictionary */

	PyDict_SetItemString(dict, "config", py_config_dict());
}
