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

	asprintf(&name, "%s%s%s", response.data.name.dom_name,
		 lp_winbind_separator(), response.data.name.name);

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
 * PAM authentication functions
 */

/* Plaintext authentication */

static PyObject *py_auth_plaintext(PyObject *self, PyObject *args)
{
	struct winbindd_request request;
	struct winbindd_response response;
	char *username, *password;

	if (!PyArg_ParseTuple(args, "ss", &username, &password))
		return NULL;

	ZERO_STRUCT(request);
	ZERO_STRUCT(response);

	fstrcpy(request.data.auth.user, username);
	fstrcpy(request.data.auth.pass, password);

	if (winbindd_request(WINBINDD_PAM_AUTH, &request, &response) 
	    != NSS_STATUS_SUCCESS) {
		PyErr_SetString(winbind_error, "lookup failed");
		return NULL;		
	}
	
	return PyInt_FromLong(response.data.auth.nt_status);
}

/* Challenge/response authentication */

static PyObject *py_auth_crap(PyObject *self, PyObject *args)
{
	struct winbindd_request request;
	struct winbindd_response response;
	char *username, *password;

	if (!PyArg_ParseTuple(args, "ss", &username, &password))
		return NULL;

	ZERO_STRUCT(request);
	ZERO_STRUCT(response);

	fstrcpy(request.data.auth_crap.user, username);

	generate_random_buffer(request.data.auth_crap.chal, 8, False);
        
        SMBencrypt((uchar *)password, request.data.auth_crap.chal, 
                   (uchar *)request.data.auth_crap.lm_resp);
        SMBNTencrypt((uchar *)password, request.data.auth_crap.chal,
                     (uchar *)request.data.auth_crap.nt_resp);

        request.data.auth_crap.lm_resp_len = 24;
        request.data.auth_crap.nt_resp_len = 24;

	if (winbindd_request(WINBINDD_PAM_AUTH_CRAP, &request, &response) 
	    != NSS_STATUS_SUCCESS) {
		PyErr_SetString(winbind_error, "lookup failed");
		return NULL;		
	}
	
	return PyInt_FromLong(response.data.auth.nt_status);
}

/*
 * Method dispatch table
 */

static PyMethodDef winbind_methods[] = {

	/* Name <-> SID conversion */

	{ "name_to_sid", py_name_to_sid, METH_VARARGS,
	  "name_to_sid(s) -> string

Return the SID for a name.

Example:

>>> winbind.name_to_sid('FOO/Administrator')
'S-1-5-21-406022937-1377575209-526660263-500' " },

	{ "sid_to_name", py_sid_to_name, METH_VARARGS,
	  "sid_to_name(s) -> string

Return the name for a SID.

Example:

>>> import winbind
>>> winbind.sid_to_name('S-1-5-21-406022937-1377575209-526660263-500')
'FOO/Administrator' " },

	/* Enumerate users/groups */

	{ "enum_domain_users", py_enum_domain_users, METH_VARARGS,
	  "enum_domain_users() -> list of strings

Return a list of domain users.

Example:

>>> winbind.enum_domain_users()
['FOO/Administrator', 'FOO/anna', 'FOO/Anne Elk', 'FOO/build', 
'FOO/foo', 'FOO/foo2', 'FOO/foo3', 'FOO/Guest', 'FOO/user1', 
'FOO/whoops-ptang'] " },

	{ "enum_domain_groups", py_enum_domain_groups, METH_VARARGS,
	  "enum_domain_groups() -> list of strings

Return a list of domain groups.

Example:

>>> winbind.enum_domain_groups()
['FOO/cows', 'FOO/Domain Admins', 'FOO/Domain Guests', 
'FOO/Domain Users'] " },

	/* ID mapping */

	{ "uid_to_sid", py_uid_to_sid, METH_VARARGS,
	  "uid_to_sid(int) -> string

Return the SID for a UNIX uid.

Example:

>>> winbind.uid_to_sid(10000)   
'S-1-5-21-406022937-1377575209-526660263-500' " },

	{ "gid_to_sid", py_gid_to_sid, METH_VARARGS,
	  "gid_to_sid(int) -> string

Return the UNIX gid for a SID.

Example:

>>> winbind.gid_to_sid(10001)
'S-1-5-21-406022937-1377575209-526660263-512' " },

	{ "sid_to_uid", py_sid_to_uid, METH_VARARGS,
	  "sid_to_uid(string) -> int

Return the UNIX uid for a SID.

Example:

>>> winbind.sid_to_uid('S-1-5-21-406022937-1377575209-526660263-500')
10000 " },

	{ "sid_to_gid", py_sid_to_gid, METH_VARARGS,
	  "sid_to_gid(string) -> int

Return the UNIX gid corresponding to a SID.

Example:

>>> winbind.sid_to_gid('S-1-5-21-406022937-1377575209-526660263-512')
10001 " },

	/* Miscellaneous */

	{ "check_secret", py_check_secret, METH_VARARGS,
	  "check_secret() -> int

Check the machine trust account password.  The NT status is returned
with zero indicating success. " },

	{ "enum_trust_dom", py_enum_trust_dom, METH_VARARGS,
	  "enum_trust_dom() -> list of strings

Return a list of trusted domains.  The domain the server is a member 
of is not included.

Example:

>>> winbind.enum_trust_dom()
['NPSD-TEST2', 'SP2NDOM'] " },

	/* PAM authorisation functions */

	{ "auth_plaintext", py_auth_plaintext, METH_VARARGS,
	  "auth_plaintext(s, s) -> int

Authenticate a username and password using plaintext authentication.
The NT status code is returned with zero indicating success." },

	{ "auth_crap", py_auth_crap, METH_VARARGS,
	  "auth_crap(s, s) -> int

Authenticate a username and password using the challenge/response
protocol.  The NT status code is returned with zero indicating
success." },

	{ NULL }
};

static struct winbind_const {
	char *name;
	uint32 value;
	char *docstring;
} winbind_const_vals[] = {

	/* Well known RIDs */
	
	{ "DOMAIN_USER_RID_ADMIN", DOMAIN_USER_RID_ADMIN, 
	  "Well-known RID for Administrator user" },

	{ "DOMAIN_USER_RID_GUEST", DOMAIN_USER_RID_GUEST,
	  "Well-known RID for Guest user" },

	{ "DOMAIN_GROUP_RID_ADMINS", DOMAIN_GROUP_RID_ADMINS,
	  "Well-known RID for Domain Admins group" },

	{ "DOMAIN_GROUP_RID_USERS", DOMAIN_GROUP_RID_USERS,
	  "Well-known RID for Domain Users group" },

	{ "DOMAIN_GROUP_RID_GUESTS", DOMAIN_GROUP_RID_GUESTS,
	  "Well-known RID for Domain Guests group" }, 
	
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

static char winbind_module__doc__[] =
"A python extension to winbind client functions.";

void initwinbind(void)
{
	PyObject *module, *dict;

	/* Initialise module */

        module = Py_InitModule3("winbind", winbind_methods,
				winbind_module__doc__);

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
