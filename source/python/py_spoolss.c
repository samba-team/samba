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
#include "python/py_spoolss.h"
#include "python/py_spoolss_forms.h"

/* Exceptions this module can raise */

PyObject *spoolss_error, *spoolss_werror;

static void py_policy_hnd_dealloc(PyObject* self)
{
	PyObject_Del(self);
}



static PyMethodDef spoolss_hnd_methods[] = {

	/* Forms */

	{ "enumforms", spoolss_enumforms, METH_VARARGS | METH_KEYWORDS,
	  "Enumerate forms" },

	{ "setform", spoolss_setform, METH_VARARGS | METH_KEYWORDS,
	  "Modify properties of a form" },

	{ "addform", spoolss_addform, METH_VARARGS | METH_KEYWORDS,
	  "Insert a form" },

	{ "getform", spoolss_getform, METH_VARARGS | METH_KEYWORDS,
	  "Fetch form properties" },

	{ "deleteform", spoolss_deleteform, METH_VARARGS | METH_KEYWORDS,
	  "Delete a form" },

	{ NULL }

};
static PyObject *py_policy_hnd_getattr(PyObject *self, char *attrname)
{
	return Py_FindMethod(spoolss_hnd_methods, self, attrname);
}

static PyObject *new_policy_hnd_object(struct cli_state *cli, 
				       TALLOC_CTX *mem_ctx, POLICY_HND *pol)
{
	spoolss_policy_hnd_object *o;

	o = PyObject_New(spoolss_policy_hnd_object, &spoolss_policy_hnd_type);

	o->cli = cli;
	o->mem_ctx = mem_ctx;
	memcpy(&o->pol, pol, sizeof(POLICY_HND));

	return (PyObject*)o;
}
     
PyTypeObject spoolss_policy_hnd_type = {
	PyObject_HEAD_INIT(NULL)
	0,
	"Policy Handle",
	sizeof(spoolss_policy_hnd_object),
	0,
	py_policy_hnd_dealloc, /*tp_dealloc*/
	0,          /*tp_print*/
	py_policy_hnd_getattr,          /*tp_getattr*/
	0,          /*tp_setattr*/
	0,          /*tp_compare*/
	0,          /*tp_repr*/
	0,          /*tp_as_number*/
	0,          /*tp_as_sequence*/
	0,          /*tp_as_mapping*/
	0,          /*tp_hash */
};

/*
 * Routines to convert from python hashes to Samba structures
 */

struct pyconv py_PRINTER_INFO_0[] = {
	{ "printer_name", PY_UNISTR, offsetof(PRINTER_INFO_0, printername) },
	{ "server_name", PY_UNISTR, offsetof(PRINTER_INFO_0, servername) },

	{ "cjobs", PY_UINT32, offsetof(PRINTER_INFO_0, cjobs) },
	{ "total_jobs", PY_UINT32, offsetof(PRINTER_INFO_0, total_jobs) },
	{ "total_bytes", PY_UINT32, offsetof(PRINTER_INFO_0, total_bytes) },

	{ "year", PY_UINT16, offsetof(PRINTER_INFO_0, year) },
	{ "month", PY_UINT16, offsetof(PRINTER_INFO_0, month) },
	{ "day_of_week", PY_UINT16, offsetof(PRINTER_INFO_0, dayofweek) },
	{ "day", PY_UINT16, offsetof(PRINTER_INFO_0, day) },
	{ "hour", PY_UINT16, offsetof(PRINTER_INFO_0, hour) },
	{ "minute", PY_UINT16, offsetof(PRINTER_INFO_0, minute) },
	{ "second", PY_UINT16, offsetof(PRINTER_INFO_0, second) },
	{ "milliseconds", PY_UINT16, offsetof(PRINTER_INFO_0, milliseconds) },

	{ "global_counter", PY_UINT32, offsetof(PRINTER_INFO_0, global_counter) },
	{ "total_pages", PY_UINT32, offsetof(PRINTER_INFO_0, total_pages) },

	{ "major_version", PY_UINT16, offsetof(PRINTER_INFO_0, major_version) },
	{ "build_version", PY_UINT16, offsetof(PRINTER_INFO_0, build_version) },

	{ "unknown7", PY_UINT32, offsetof(PRINTER_INFO_0, unknown7) },
	{ "unknown8", PY_UINT32, offsetof(PRINTER_INFO_0, unknown8) },
	{ "unknown9", PY_UINT32, offsetof(PRINTER_INFO_0, unknown9) },
	{ "session_counter", PY_UINT32, offsetof(PRINTER_INFO_0, session_counter)},
	{ "unknown11", PY_UINT32, offsetof(PRINTER_INFO_0, unknown11) },
	{ "printer_errors", PY_UINT32, offsetof(PRINTER_INFO_0, printer_errors) },
	{ "unknown13", PY_UINT32, offsetof(PRINTER_INFO_0, unknown13) },
	{ "unknown14", PY_UINT32, offsetof(PRINTER_INFO_0, unknown14) },
	{ "unknown15", PY_UINT32, offsetof(PRINTER_INFO_0, unknown15) },
	{ "unknown16", PY_UINT32, offsetof(PRINTER_INFO_0, unknown16) },
	{ "change_id", PY_UINT32, offsetof(PRINTER_INFO_0, change_id) },
	{ "unknown18", PY_UINT32, offsetof(PRINTER_INFO_0, unknown18) },
	{ "status", PY_UINT32, offsetof(PRINTER_INFO_0, status) },
	{ "unknown20", PY_UINT32, offsetof(PRINTER_INFO_0, unknown20) },
	{ "c_setprinter", PY_UINT32, offsetof(PRINTER_INFO_0, c_setprinter) },
	{ "unknown22", PY_UINT32, offsetof(PRINTER_INFO_0, unknown22) },
	{ "unknown23", PY_UINT32, offsetof(PRINTER_INFO_0, unknown23) },
	{ "unknown24", PY_UINT32, offsetof(PRINTER_INFO_0, unknown24) },
	{ "unknown25", PY_UINT32, offsetof(PRINTER_INFO_0, unknown25) },
	{ "unknown26", PY_UINT32, offsetof(PRINTER_INFO_0, unknown26) },
	{ "unknown27", PY_UINT32, offsetof(PRINTER_INFO_0, unknown27) },
	{ "unknown28", PY_UINT32, offsetof(PRINTER_INFO_0, unknown28) },
	{ "unknown29", PY_UINT32, offsetof(PRINTER_INFO_0, unknown29) },

	{ NULL }
};	

struct pyconv py_PRINTER_INFO_1[] = {
	{ "printer_name", PY_UNISTR, offsetof(PRINTER_INFO_1, name) },
	{ "description", PY_UNISTR, offsetof(PRINTER_INFO_1, description) },
	{ "comment", PY_UNISTR, offsetof(PRINTER_INFO_1, comment) },
	{ "flags", PY_UINT32, offsetof(PRINTER_INFO_1, flags) },
	{ NULL }
};	

struct pyconv py_PRINTER_INFO_2[] = {
	{ "server_name", PY_UNISTR, offsetof(PRINTER_INFO_2, servername) },
	{ "printer_name", PY_UNISTR, offsetof(PRINTER_INFO_2, printername) },
	{ "share_name", PY_UNISTR, offsetof(PRINTER_INFO_2, sharename) },
	{ "port_name", PY_UNISTR, offsetof(PRINTER_INFO_2, portname) },
	{ "driver_name", PY_UNISTR, offsetof(PRINTER_INFO_2, drivername) },
	{ "comment", PY_UNISTR, offsetof(PRINTER_INFO_2, comment) },
	{ "location", PY_UNISTR, offsetof(PRINTER_INFO_2, location) },
	{ "datatype", PY_UNISTR, offsetof(PRINTER_INFO_2, datatype) },
	{ "sepfile", PY_UNISTR, offsetof(PRINTER_INFO_2, sepfile) },
	{ "print_processor", PY_UNISTR, offsetof(PRINTER_INFO_2, printprocessor) },
	{ "parameters", PY_UNISTR, offsetof(PRINTER_INFO_2, parameters) },
	{ "attributes", PY_UINT32, offsetof(PRINTER_INFO_2, attributes) },
	{ "default_priority", PY_UINT32, offsetof(PRINTER_INFO_2, defaultpriority) },
	{ "priority", PY_UINT32, offsetof(PRINTER_INFO_2, priority) },
	{ "start_time", PY_UINT32, offsetof(PRINTER_INFO_2, starttime) },
	{ "until_time", PY_UINT32, offsetof(PRINTER_INFO_2, untiltime) },
	{ "status", PY_UINT32, offsetof(PRINTER_INFO_2, status) },
	{ "cjobs", PY_UINT32, offsetof(PRINTER_INFO_2, cjobs) },
	{ "average_ppm", PY_UINT32, offsetof(PRINTER_INFO_2, averageppm) },
	{ NULL }
};	

struct pyconv py_PRINTER_INFO_3[] = {
	{ "flags", PY_UINT32, offsetof(PRINTER_INFO_3, flags) },
	{ NULL }
};	

struct pyconv py_DEVICEMODE[] = {
	{ "device_name", PY_UNISTR, offsetof(DEVICEMODE, devicename) },
	{ "spec_version", PY_UINT16, offsetof(DEVICEMODE, specversion) },
	{ "driver_version", PY_UINT16, offsetof(DEVICEMODE, driverversion) },
	{ "size", PY_UINT16, offsetof(DEVICEMODE, size) },
	{ "fields", PY_UINT16, offsetof(DEVICEMODE, fields) },
	{ "orientation", PY_UINT16, offsetof(DEVICEMODE, orientation) },
	{ "paper_size", PY_UINT16, offsetof(DEVICEMODE, papersize) },
	{ "paper_width", PY_UINT16, offsetof(DEVICEMODE, paperwidth) },
	{ "paper_length", PY_UINT16, offsetof(DEVICEMODE, paperlength) },
	{ "scale", PY_UINT16, offsetof(DEVICEMODE, scale) },
	{ "copies", PY_UINT16, offsetof(DEVICEMODE, copies) },
	{ "default_source", PY_UINT16, offsetof(DEVICEMODE, defaultsource) },
	{ "print_quality", PY_UINT16, offsetof(DEVICEMODE, printquality) },
	{ "color", PY_UINT16, offsetof(DEVICEMODE, color) },
	{ "duplex", PY_UINT16, offsetof(DEVICEMODE, duplex) },
	{ "y_resolution", PY_UINT16, offsetof(DEVICEMODE, yresolution) },
	{ "tt_option", PY_UINT16, offsetof(DEVICEMODE, ttoption) },
	{ "collate", PY_UINT16, offsetof(DEVICEMODE, collate) },
	{ "form_name", PY_UNISTR, offsetof(DEVICEMODE, formname) },
	{ "log_pixels", PY_UINT16, offsetof(DEVICEMODE, logpixels) },
	{ "bits_per_pel", PY_UINT32, offsetof(DEVICEMODE, bitsperpel) },
	{ "pels_width", PY_UINT32, offsetof(DEVICEMODE, pelswidth) },
	{ "pels_height", PY_UINT32, offsetof(DEVICEMODE, pelsheight) },
	{ "display_flags", PY_UINT32, offsetof(DEVICEMODE, displayflags) },
	{ "display_frequency", PY_UINT32, offsetof(DEVICEMODE, displayfrequency) },
	{ "icm_method", PY_UINT32, offsetof(DEVICEMODE, icmmethod) },
	{ "icm_intent", PY_UINT32, offsetof(DEVICEMODE, icmintent) },
	{ "media_type", PY_UINT32, offsetof(DEVICEMODE, mediatype) },
	{ "dither_type", PY_UINT32, offsetof(DEVICEMODE, dithertype) },
	{ "reserved1", PY_UINT32, offsetof(DEVICEMODE, reserved1) },
	{ "reserved2", PY_UINT32, offsetof(DEVICEMODE, reserved2) },
	{ "panning_width", PY_UINT32, offsetof(DEVICEMODE, panningwidth) },
	{ "panning_height", PY_UINT32, offsetof(DEVICEMODE, panningheight) },
	{ NULL }
};

struct pyconv py_DRIVER_INFO_1[] = {
	{ "name", PY_UNISTR, offsetof(DRIVER_INFO_1, name) },
	{ NULL }
};

struct pyconv py_DRIVER_INFO_2[] = {
	{ "version", PY_UINT32, offsetof(DRIVER_INFO_2, version) },
	{ "name", PY_UNISTR, offsetof(DRIVER_INFO_2, name) },
	{ "architecture", PY_UNISTR, offsetof(DRIVER_INFO_2, architecture) },
	{ "driver_path", PY_UNISTR, offsetof(DRIVER_INFO_2, driverpath) },
	{ "data_file", PY_UNISTR, offsetof(DRIVER_INFO_2, datafile) },
	{ "config_file", PY_UNISTR, offsetof(DRIVER_INFO_2, configfile) },
	{ NULL }
};

struct pyconv py_DRIVER_INFO_3[] = {
	{ "version", PY_UINT32, offsetof(DRIVER_INFO_3, version) },
	{ "name", PY_UNISTR, offsetof(DRIVER_INFO_3, name) },
	{ "architecture", PY_UNISTR, offsetof(DRIVER_INFO_3, architecture) },
	{ "driver_path", PY_UNISTR, offsetof(DRIVER_INFO_3, driverpath) },
	{ "data_file", PY_UNISTR, offsetof(DRIVER_INFO_3, datafile) },
	{ "config_file", PY_UNISTR, offsetof(DRIVER_INFO_3, configfile) },
	{ "help_file", PY_UNISTR, offsetof(DRIVER_INFO_3, helpfile) },
	/* dependentfiles */
	{ "monitor_name", PY_UNISTR, offsetof(DRIVER_INFO_3, monitorname) },
	{ "default_datatype", PY_UNISTR, offsetof(DRIVER_INFO_3, defaultdatatype) },
	{ NULL }
};

struct pyconv py_DRIVER_INFO_6[] = {
	{ "version", PY_UINT32, offsetof(DRIVER_INFO_6, version) },
	{ "name", PY_UNISTR, offsetof(DRIVER_INFO_6, name) },
	{ "architecture", PY_UNISTR, offsetof(DRIVER_INFO_6, architecture) },
	{ "driver_path", PY_UNISTR, offsetof(DRIVER_INFO_6, driverpath) },
	{ "data_file", PY_UNISTR, offsetof(DRIVER_INFO_6, datafile) },
	{ "config_file", PY_UNISTR, offsetof(DRIVER_INFO_6, configfile) },
	{ "help_file", PY_UNISTR, offsetof(DRIVER_INFO_6, helpfile) },
	/* dependentfiles */
	{ "monitor_name", PY_UNISTR, offsetof(DRIVER_INFO_6, monitorname) },
	{ "default_datatype", PY_UNISTR, offsetof(DRIVER_INFO_6, defaultdatatype) },
	/* driver_date */

	{ "padding", PY_UINT32, offsetof(DRIVER_INFO_6, padding) },
	{ "driver_version_low", PY_UINT32, offsetof(DRIVER_INFO_6, driver_version_low) },
	{ "driver_version_high", PY_UINT32, offsetof(DRIVER_INFO_6, driver_version_high) },
	{ "mfg_name", PY_UNISTR, offsetof(DRIVER_INFO_6, mfgname) },
	{ "oem_url", PY_UNISTR, offsetof(DRIVER_INFO_6, oem_url) },
	{ "hardware_id", PY_UNISTR, offsetof(DRIVER_INFO_6, hardware_id) },
	{ "provider", PY_UNISTR, offsetof(DRIVER_INFO_6, provider) },
	
	{ NULL }
};

static void fstr_pull(fstring str, UNISTR *uni)
{
	rpcstr_pull(str, uni->buffer, sizeof(fstring), 0, STR_TERMINATE);
}

/* Convert a structure to a Python dict */

PyObject *from_struct(void *s, struct pyconv *conv)
{
	PyObject *obj, *item;
	int i;

	obj = PyDict_New();

	for (i = 0; conv[i].name; i++) {
		switch (conv[i].type) {
		case PY_UNISTR: {
			UNISTR *u = (UNISTR *)((char *)s + conv[i].offset);
			fstring s = "";

			if (u->buffer)
				fstr_pull(s, u);

			item = PyString_FromString(s);
			PyDict_SetItemString(obj, conv[i].name, item);

			break;
		}
		case PY_UINT32: {
			uint32 *u = (uint32 *)((char *)s + conv[i].offset);

			item = PyInt_FromLong(*u);
			PyDict_SetItemString(obj, conv[i].name, item);
			
			break;
		}
		case PY_UINT16: {
			uint16 *u = (uint16 *)((char *)s + conv[i].offset);

			item = PyInt_FromLong(*u);
			PyDict_SetItemString(obj, conv[i].name, item);

			break;
		}
		default:
			break;
		}
	}

	return obj;
}

/* Convert a Python dict to a structure */

void to_struct(void *s, PyObject *dict, struct pyconv *conv)
{
	int i;

	for (i = 0; conv[i].name; i++) {
		PyObject *obj;
		
		obj = PyDict_GetItemString(dict, conv[i].name);
		
		switch (conv[i].type) {
		case PY_UNISTR: {
			UNISTR *u = (UNISTR *)((char *)s + conv[i].offset);
			char *s = "";

			if (obj && PyString_Check(obj))
				s = PyString_AsString(obj);

			init_unistr(u, s);
			
			break;
		}
		case PY_UINT32: {
			uint32 *u = (uint32 *)((char *)s + conv[i].offset);

			if (obj && PyInt_Check(obj)) 
				*u = PyInt_AsLong(obj);
			else
				*u = 0;

			break;
		}
		case PY_UINT16: {
			uint16 *u = (uint16 *)((char *)s + conv[i].offset);

			if (obj && PyInt_Check(obj)) 
				*u = PyInt_AsLong(obj);
			else
				*u = 0;

			break;
		}
		default:
			break;
		}
	}
}

/* Return a cli_state struct opened on the SPOOLSS pipe.  If credentials
   are passed use them. */

typedef struct cli_state *(cli_pipe_fn)(
	struct cli_state *cli, char *system_name,
	struct ntuser_creds *creds);

static struct cli_state *open_pipe_creds(char *system_name, PyObject *creds, 
					 cli_pipe_fn *connect_fn,
					 struct cli_state *cli)
{
	struct ntuser_creds nt_creds;

	if (!cli) {
		cli = (struct cli_state *)malloc(sizeof(struct cli_state));
		if (!cli)
			return NULL;
	}

	ZERO_STRUCTP(cli);

	/* Extract credentials from the python dictionary and initialise
	   the ntuser_creds struct from them. */

	ZERO_STRUCT(nt_creds);
	nt_creds.pwd.null_pwd = True;

	if (creds) {
		char *username, *password, *domain;
		PyObject *username_obj, *password_obj, *domain_obj;

		/* Check credentials passed are valid.  This means the
		   username, domain and password keys must exist and be
		   string objects. */

		username_obj = PyDict_GetItemString(creds, "username");
		domain_obj = PyDict_GetItemString(creds, "domain");
		password_obj = PyDict_GetItemString(creds, "password");

		if (!username_obj || !domain_obj || !password_obj) {
		error:
			PyErr_SetString(spoolss_error, "invalid credentials");
			return NULL;
		}

		if (!PyString_Check(username_obj) || 
		    !PyString_Check(domain_obj) || 
		    !PyString_Check(password_obj))
			goto error;

		username = PyString_AsString(username_obj);
		domain = PyString_AsString(domain_obj);
		password = PyString_AsString(password_obj);

		if (!username || !domain || !password)
			goto error;

		/* Initialise nt_creds structure with passed creds */

		fstrcpy(nt_creds.user_name, username);
		fstrcpy(nt_creds.domain, domain);

		if (lp_encrypted_passwords())
			pwd_make_lm_nt_16(&nt_creds.pwd, password);
		else
			pwd_set_cleartext(&nt_creds.pwd, password);

		nt_creds.pwd.null_pwd = False;
	}

	/* Now try to connect */

	connect_fn(cli, system_name, &nt_creds);

	return cli;
}

/* Open a printer */

static PyObject *spoolss_openprinter(PyObject *self, PyObject *args,
				     PyObject *kw)
{
	char *full_name, *computer_name = NULL;
	TALLOC_CTX *mem_ctx;
	POLICY_HND hnd;
	WERROR werror;
	PyObject *result = NULL, *creds = NULL;
	static char *kwlist[] = { "printername", "creds", "access", NULL };
	uint32 desired_access = MAXIMUM_ALLOWED_ACCESS;
	struct cli_state *cli;

	if (!PyArg_ParseTupleAndKeywords(
		args, kw, "s|O!i", kwlist, &full_name, &PyDict_Type, &creds,
		&desired_access)) {

		goto done;
	}

	/* FIXME: Return name format exception for names without a UNC
	   prefix */ 

	computer_name = strdup(full_name + 2);

	if (strchr(computer_name, '\\')) {
		char *c = strchr(computer_name, '\\');
		*c = 0;
	}

	if (!(cli = open_pipe_creds(computer_name, creds, 
				    cli_spoolss_initialise, NULL))) {
		fprintf(stderr, "could not initialise cli state\n");
		goto done;
	}

	if (!(mem_ctx = talloc_init())) {
		fprintf(stderr, "unable to initialise talloc context\n");
		goto done;
	}

	werror = cli_spoolss_open_printer_ex(
		cli, mem_ctx, full_name, "", desired_access, computer_name, 
		"", &hnd);

	if (!W_ERROR_IS_OK(werror)) {
		cli_shutdown(cli);
		SAFE_FREE(cli);
		PyErr_SetObject(spoolss_werror,
				PyInt_FromLong(W_ERROR_V(werror)));
		goto done;
	}

	result = new_policy_hnd_object(cli, mem_ctx, &hnd);

 done:
	SAFE_FREE(computer_name);

	return result;
}

/* Close a printer */

static PyObject *spoolss_closeprinter(PyObject *self, PyObject *args)
{
	PyObject *po;
	spoolss_policy_hnd_object *hnd;
	WERROR result;

	/* Parse parameters */

	if (!PyArg_ParseTuple(args, "O!", &spoolss_policy_hnd_type, &po))
		return NULL;

	hnd = (spoolss_policy_hnd_object *)po;

	/* Call rpc function */

	result = cli_spoolss_close_printer(hnd->cli, hnd->mem_ctx, &hnd->pol);

	/* Cleanup samba stuf */

	cli_shutdown(hnd->cli);
	talloc_destroy(hnd->mem_ctx);

	/* Return value */

	Py_INCREF(Py_None);
	return Py_None;	
}

/* Fetch printer driver */

static PyObject *spoolss_getprinterdriver(PyObject *self, PyObject *args,
					  PyObject *kw)
{
	PyObject *po;
	spoolss_policy_hnd_object *hnd;
	WERROR werror;
	PyObject *result;
	PRINTER_DRIVER_CTR ctr;
	int level = 1;
	uint32 needed;
	char *arch = "Windows NT x86";
	static char *kwlist[] = {"hnd", "level", "arch", NULL};

	/* Parse parameters */

	if (!PyArg_ParseTupleAndKeywords(args, kw, "O!|is", kwlist, 
					 &spoolss_policy_hnd_type, &po, &level, &arch))
		return NULL;

	hnd = (spoolss_policy_hnd_object *)po;

	/* Call rpc function */

	werror = cli_spoolss_getprinterdriver(
		hnd->cli, hnd->mem_ctx, 0, &needed, &hnd->pol, level,
		arch, &ctr);

	if (W_ERROR_V(werror) == ERRinsufficientbuffer)
		werror = cli_spoolss_getprinterdriver(
			hnd->cli, hnd->mem_ctx, needed, NULL, &hnd->pol,
			level, arch, &ctr);

	/* Return value */
	
	result = Py_None;

	if (W_ERROR_IS_OK(werror)) {
		switch (level) {
		case 1:
			result = from_struct(&ctr.info1, py_DRIVER_INFO_1);
			break;
		case 2: 
			result = from_struct(&ctr.info2, py_DRIVER_INFO_2);
			break;
		case 6:
			result = from_struct(&ctr.info6, py_DRIVER_INFO_6);
			break;
		default:
			result = Py_None;
			break;
		}
	}
	
	Py_INCREF(result);
	return result;
}

/* Enumerate printer drivers */

static PyObject *spoolss_enumprinterdrivers(PyObject *self, PyObject *args,
					    PyObject *kw)
{
	PyObject *po;
	spoolss_policy_hnd_object *hnd;
	WERROR werror;
	PyObject *result;
	PRINTER_DRIVER_CTR ctr;
	int level = 1, i;
	uint32 needed, num_drivers;
	char *arch = "Windows NT x86";
	static char *kwlist[] = {"hnd", "level", "arch", NULL};

	/* Parse parameters */

	if (!PyArg_ParseTupleAndKeywords(args, kw, "O!|is", kwlist, 
					 &spoolss_policy_hnd_type, &po, &level, &arch))
		return NULL;
	
	hnd = (spoolss_policy_hnd_object *)po;
	
	/* Call rpc function */
	
	werror = cli_spoolss_enumprinterdrivers(
		hnd->cli, hnd->mem_ctx, 0, &needed, level, arch,
		&num_drivers, &ctr);

	if (W_ERROR_V(werror) == ERRinsufficientbuffer)
		werror = cli_spoolss_enumprinterdrivers(
			hnd->cli, hnd->mem_ctx, needed, NULL, level, arch, 
			&num_drivers, &ctr);

	/* Return value */
	
	result = Py_None;

	if (!W_ERROR_IS_OK(werror))
		goto done;

	switch (level) {
	case 1:
		result = PyList_New(num_drivers);
		
		for (i = 0; i < num_drivers; i++) {
			PyObject *value;
			
			value = from_struct(&ctr.info1, py_DRIVER_INFO_1);
			PyList_SetItem(result, i, value);
		}
		
		break;
	case 2: 
		result = PyList_New(num_drivers);

		for(i = 0; i < num_drivers; i++) {
			PyObject *value;

			value = from_struct(&ctr.info2, py_DRIVER_INFO_2);
			PyList_SetItem(result, i, value);
		}

		break;
	case 6: 
		result = PyList_New(num_drivers);

		for(i = 0; i < num_drivers; i++) {
			PyObject *value;

			value = from_struct(&ctr.info2, py_DRIVER_INFO_6);
			PyList_SetItem(result, i, value);
		}

		break;
	default:
		result = Py_None;
		break;
	}
	
 done:
	Py_INCREF(result);
	return result;
}

/* Convert a security descriptor to a Python dict */

static PyObject *PySID_FromSID(DOM_SID *sid)
{
	fstring sidstr;

	if (!sid) {
		Py_INCREF(Py_None);
		return Py_None;
	}

	if (sid_to_string(sidstr, sid))
		return PyString_FromString(sidstr);

	Py_INCREF(Py_None);
	return Py_None;	
}

static PyObject *PyACE_FromACE(SEC_ACE *ace)
{
	PyObject *obj;

	if (!ace) {
		Py_INCREF(Py_None);
		return Py_None;
	}

	obj = PyDict_New();

	PyDict_SetItemString(obj, "type", PyInt_FromLong(ace->type));
	PyDict_SetItemString(obj, "flags", PyInt_FromLong(ace->flags));
	PyDict_SetItemString(obj, "mask", PyInt_FromLong(ace->info.mask));

	PyDict_SetItemString(obj, "trustee", PySID_FromSID(&ace->trustee));

	return obj;
}

static PyObject *PyACL_FromACL(SEC_ACL *acl)
{
	PyObject *obj, *ace_list;
	int i;

	if (!acl) {
		Py_INCREF(Py_None);
		return Py_None;
	}

	obj = PyDict_New();

	PyDict_SetItemString(obj, "revision", PyInt_FromLong(acl->revision));

	ace_list = PyList_New(acl->num_aces);

	for (i = 0; i < acl->num_aces; i++)
		PyList_SetItem(ace_list, i, PyACE_FromACE(&acl->ace[i]));

	PyDict_SetItemString(obj, "ace_list", ace_list);

	return obj;
}

static PyObject *PySECDESC_FromSECDESC(SEC_DESC *sd)
{
	PyObject *obj = PyDict_New();

	PyDict_SetItemString(obj, "revision", PyInt_FromLong(sd->revision));
	PyDict_SetItemString(obj, "type", PyInt_FromLong(sd->type));

	PyDict_SetItemString(obj, "owner_sid", PySID_FromSID(sd->owner_sid));
	PyDict_SetItemString(obj, "group_sid", PySID_FromSID(sd->grp_sid));

	PyDict_SetItemString(obj, "dacl", PyACL_FromACL(sd->dacl));
	PyDict_SetItemString(obj, "sacl", PyACL_FromACL(sd->sacl));

	return obj;
}

PyObject *PyDEVICEMODE_FromDEVICEMODE(DEVICEMODE *devmode)
{
	PyObject *obj;

	obj = from_struct(devmode, py_DEVICEMODE);

	PyDict_SetItemString(obj, "private",
			     PyString_FromStringAndSize(devmode->private, 
							devmode->driverextra));

	return obj;
}

/* Fetch printer information */

static PyObject *spoolss_getprinter(PyObject *self, PyObject *args,
				    PyObject *kw)
{
	PyObject *po;
	spoolss_policy_hnd_object *hnd;
	WERROR werror;
	PyObject *result;
	PRINTER_INFO_CTR ctr;
	int level = 1;
	uint32 needed;
	static char *kwlist[] = {"hnd", "level", NULL};

	/* Parse parameters */

	if (!PyArg_ParseTupleAndKeywords(args, kw, "O!|i", kwlist, 
					 &spoolss_policy_hnd_type, &po, &level))
		return NULL;
	
	hnd = (spoolss_policy_hnd_object *)po;
	
	/* Call rpc function */
	
	werror = cli_spoolss_getprinter(
		hnd->cli, hnd->mem_ctx, 0, &needed, &hnd->pol, level, &ctr);

	if (W_ERROR_V(werror) == ERRinsufficientbuffer)
		werror = cli_spoolss_getprinter(
			hnd->cli, hnd->mem_ctx, needed, NULL, &hnd->pol,
			level, &ctr);

	/* Return value */

	result = Py_None;

	if (!W_ERROR_IS_OK(werror))
		goto done;

	switch (level) {

	case 0:
		result = from_struct(ctr.printers_0, py_PRINTER_INFO_0);

		break;

	case 1:
		result = from_struct(ctr.printers_1, py_PRINTER_INFO_1);

		break;

	case 2:
		result = from_struct(ctr.printers_2, py_PRINTER_INFO_2);

		PyDict_SetItemString(result, "security_descriptor", 
				     PySECDESC_FromSECDESC(
					     ctr.printers_2->secdesc));
		
		PyDict_SetItemString(result, "device_mode",
				     PyDEVICEMODE_FromDEVICEMODE(
					     ctr.printers_2->devmode));

		break;

	case 3:
		result = from_struct(ctr.printers_3, py_PRINTER_INFO_3);

		PyDict_SetItemString(result, "security_descriptor",
				     PySECDESC_FromSECDESC(
					     ctr.printers_3->secdesc));
		break;

	default:
		result = Py_None;
		break;
	}
 done:
	Py_INCREF(result);
	return result;
}

/* Set printer information */

static PyObject *spoolss_setprinter(PyObject *self, PyObject *args,
				    PyObject *kw)
{
	PyObject *po;
	spoolss_policy_hnd_object *hnd;
	WERROR werror;
	PyObject *result, *info;
	PRINTER_INFO_CTR ctr;
	int level = 1;
	static char *kwlist[] = { "hnd", "dict", "level", NULL };
	union {
		PRINTER_INFO_0 printers_0;
		PRINTER_INFO_1 printers_1;
		PRINTER_INFO_2 printers_2;
		PRINTER_INFO_3 printers_3;
		PRINTER_INFO_4 printers_4;
		PRINTER_INFO_5 printers_5;
	} pinfo;

	/* Parse parameters */

	if (!PyArg_ParseTupleAndKeywords(args, kw, "O!O!|i", kwlist, 
					 &spoolss_policy_hnd_type, &po, 
					 &PyDict_Type, &info, &level))
		return NULL;
	
	hnd = (spoolss_policy_hnd_object *)po;
	
	/* Fill in printer info */

	ZERO_STRUCT(ctr);

	switch (level) {
	case 1:
		ctr.printers_1 = &pinfo.printers_1;
		to_struct(&pinfo.printers_1, info, py_PRINTER_INFO_1);
		break;
	default:
	}

	/* Call rpc function */
	
	werror = cli_spoolss_setprinter(hnd->cli, hnd->mem_ctx, &hnd->pol,
					level, &ctr, 0);

	/* Return value */

	result = Py_None;

	if (!W_ERROR_IS_OK(werror))
		goto done;

 done:
	Py_INCREF(result);
	return result;
}

/* Enumerate printers */

static PyObject *spoolss_enumprinters(PyObject *self, PyObject *args,
				      PyObject *kw)
{
	WERROR werror;
	PyObject *result, *creds = NULL;
	PRINTER_INFO_CTR ctr;
	int level = 1, flags = PRINTER_ENUM_LOCAL, i;
	uint32 needed, num_printers;
	static char *kwlist[] = {"server", "name", "level", "flags", 
				 "creds", NULL};
	TALLOC_CTX *mem_ctx = NULL;
	struct cli_state *cli = NULL;
	char *server, *name = NULL;

	/* Parse parameters */

	if (!PyArg_ParseTupleAndKeywords(args, kw, "s|siiO!", kwlist, 
					 &server, &name, &level, &flags, 
					 &PyDict_Type, &creds))
		return NULL;
	
	if (server[0] == '\\' && server[1] == '\\')
		server += 2;

	mem_ctx = talloc_init();
	cli = open_pipe_creds(server, creds, cli_spoolss_initialise, NULL);

	/* Call rpc function */
	
	werror = cli_spoolss_enum_printers(
		cli, mem_ctx, 0, &needed, flags, level,
		&num_printers, &ctr);

	if (W_ERROR_V(werror) == ERRinsufficientbuffer)
		werror = cli_spoolss_enum_printers(
			cli, mem_ctx, needed, NULL, flags, level,
			&num_printers, &ctr);

	/* Return value */
	
	result = Py_None;

	if (!W_ERROR_IS_OK(werror))
		goto done;

	result = PyList_New(num_printers);

	switch (level) {
	case 0: 
		for (i = 0; i < num_printers; i++) {
			PyObject *value;

			value = from_struct (
				&ctr.printers_0[i], py_PRINTER_INFO_0);

			PyList_SetItem(result, i, value);
		}

		break;
	case 1:
		for(i = 0; i < num_printers; i++) {
			PyObject *value;

			value = from_struct(
				&ctr.printers_1[i], py_PRINTER_INFO_1);

			PyList_SetItem(result, i, value);
		}
		
		break;
	case 2:
		for(i = 0; i < num_printers; i++) {
			PyObject *value;

			value = from_struct(
				&ctr.printers_2[i], py_PRINTER_INFO_2);

			PyList_SetItem(result, i, value);
		}
		
		break;
	case 3:
		for(i = 0; i < num_printers; i++) {
			PyObject *value;

			value = from_struct(
				&ctr.printers_3[i], py_PRINTER_INFO_3);

			PyList_SetItem(result, i, value);
		}
		
		break;
	}

 done:
	Py_INCREF(result);
	return result;
}

/* 
 * Method dispatch table
 */

#include "python/py_spoolss_forms.h"

static PyMethodDef spoolss_methods[] = {

	/* Open/close printer handles */
	
	{ "openprinter", spoolss_openprinter, METH_VARARGS | METH_KEYWORDS, 
	  "Open printer" },
	
	{ "closeprinter", spoolss_closeprinter, METH_VARARGS, 
	  "Close printer" },

	/* Printer drivers */

	{ "getprinterdriver", spoolss_getprinterdriver, 
	  METH_VARARGS | METH_KEYWORDS, "Fetch printer driver" },

	{ "enumprinterdrivers", spoolss_enumprinterdrivers,
	  METH_VARARGS | METH_KEYWORDS, "Enumerate printer drivers" },

	{ "getprinter", spoolss_getprinter, METH_VARARGS | METH_KEYWORDS,
	  "Fetch printer information" },

	{ "setprinter", spoolss_setprinter, METH_VARARGS | METH_KEYWORDS,
	  "Set printer information" },

	{ "enumprinters", spoolss_enumprinters, METH_VARARGS | METH_KEYWORDS,
	  "Enumerate printers" },

	{ NULL }
};

/* Initialise constants */

struct spoolss_const {
	char *name;
	uint32 value;
} spoolss_const_vals[] = {
	
	/* Access permissions */

	{ "MAXIMUM_ALLOWED_ACCESS", MAXIMUM_ALLOWED_ACCESS },
	{ "SERVER_ALL_ACCESS", SERVER_ALL_ACCESS },
	{ "PRINTER_ALL_ACCESS", PRINTER_ALL_ACCESS },

	/* Printer enumeration flags */

	{ "PRINTER_ENUM_DEFAULT", PRINTER_ENUM_DEFAULT },
	{ "PRINTER_ENUM_LOCAL", PRINTER_ENUM_LOCAL },
	{ "PRINTER_ENUM_CONNECTIONS", PRINTER_ENUM_CONNECTIONS },
	{ "PRINTER_ENUM_FAVORITE", PRINTER_ENUM_FAVORITE },
	{ "PRINTER_ENUM_NAME", PRINTER_ENUM_NAME },
	{ "PRINTER_ENUM_REMOTE", PRINTER_ENUM_REMOTE },
	{ "PRINTER_ENUM_SHARED", PRINTER_ENUM_SHARED },
	{ "PRINTER_ENUM_NETWORK", PRINTER_ENUM_NETWORK },

	{ NULL },
};

static void const_init(PyObject *dict)
{
	struct spoolss_const *tmp;
	PyObject *obj;

	for (tmp = spoolss_const_vals; tmp->name; tmp++) {
		obj = PyInt_FromLong(tmp->value);
		PyDict_SetItemString(dict, tmp->name, obj);
		Py_DECREF(obj);
	}
}

/* Module initialisation */

void initspoolss(void)
{
	PyObject *module, *dict;

	/* Initialise module */

	module = Py_InitModule("spoolss", spoolss_methods);
	dict = PyModule_GetDict(module);

	/* Make spools_error global an exception we can raise when an error
	   occurs. */

	spoolss_error = PyErr_NewException("spoolss.error", NULL, NULL);
	PyDict_SetItemString(dict, "error", spoolss_error);

	spoolss_werror = PyErr_NewException("spoolss.werror", NULL, NULL);
	PyDict_SetItemString(dict, "werror", spoolss_werror);

	/* Initialise policy handle object */

	spoolss_policy_hnd_type.ob_type = &PyType_Type;

	/* Initialise constants */

	const_init(dict);

	/* Do samba initialisation */

	py_samba_init();
}
