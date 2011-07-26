/*
   Unix SMB/CIFS implementation.

   Copyright (C) Amitay Isaacs 2011

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <Python.h>
#include <tevent.h>
#include <pytalloc.h>
#include "includes.h"
#include "param/param.h"
#include "param/pyparam.h"
#include "system/dir.h"
#include "lib/events/events.h"
#include "auth/credentials/credentials.h"
#include "auth/credentials/pycredentials.h"
#include "auth/gensec/gensec.h"
#include "libcli/libcli.h"
#include "libcli/raw/libcliraw.h"
#include "libcli/raw/raw_proto.h"
#include "libcli/resolve/resolve.h"
#include "libcli/util/pyerrors.h"
#include "libcli/smb_composite/smb_composite.h"
#include "libcli/security/security_descriptor.h"
#include "librpc/rpc/pyrpc_util.h"

#ifndef Py_RETURN_NONE
#define Py_RETURN_NONE	return Py_INCREF(Py_None), Py_None
#endif

staticforward PyTypeObject PySMB;

void initsmb(void);

struct smb_private_data {
	struct loadparm_context *lp_ctx;
	struct cli_credentials *creds;
	struct tevent_context *ev_ctx;
	struct smbcli_tree *tree;
};


static void dos_format(char *s)
{
	string_replace(s, '/', '\\');
}


static struct smbcli_tree *do_smb_connect(TALLOC_CTX *mem_ctx, struct smb_private_data *spdata,
			const char *hostname, const char *service)
{
	struct smb_composite_connect io;
	NTSTATUS status;

	gensec_init();

	io.in.dest_host = hostname;

	io.in.dest_ports = lpcfg_smb_ports(spdata->lp_ctx);
	io.in.socket_options = lpcfg_socket_options(spdata->lp_ctx);
	io.in.gensec_settings = lpcfg_gensec_settings(mem_ctx, spdata->lp_ctx);

	io.in.called_name = lpcfg_netbios_name(spdata->lp_ctx);
	io.in.workgroup = lpcfg_workgroup(spdata->lp_ctx);

	lpcfg_smbcli_options(spdata->lp_ctx, &io.in.options);
	lpcfg_smbcli_session_options(spdata->lp_ctx, &io.in.session_options);

	io.in.service = service;
	io.in.service_type = NULL;

	io.in.credentials = spdata->creds;
	io.in.fallback_to_anonymous = false;

	status = smb_composite_connect(&io, mem_ctx,
					lpcfg_resolve_context(spdata->lp_ctx),
					spdata->ev_ctx);
	PyErr_NTSTATUS_IS_ERR_RAISE(status);

	return io.out.tree;
}


static PyObject * py_smb_loadfile(py_talloc_Object *self, PyObject *args)
{
	struct smb_composite_loadfile io;
	const char *filename;
	NTSTATUS status;
	struct smb_private_data *spdata;

	if (!PyArg_ParseTuple(args, "s", &filename)) {
		return NULL;
	}

	io.in.fname = filename;

	spdata = self->ptr;
	status = smb_composite_loadfile(spdata->tree, self->talloc_ctx, &io);
	PyErr_NTSTATUS_IS_ERR_RAISE(status);

	return Py_BuildValue("s#", io.out.data, io.out.size);
}


static PyObject * py_smb_savefile(py_talloc_Object *self, PyObject *args)
{
	struct smb_composite_savefile io;
	const char *filename;
	char *data;
	NTSTATUS status;
	struct smb_private_data *spdata;

	if (!PyArg_ParseTuple(args, "ss", &filename, &data)) {
		return NULL;
	}

	io.in.fname = filename;
	io.in.data = (unsigned char *)data;
	io.in.size = strlen(data);

	spdata = self->ptr;
	status = smb_composite_savefile(spdata->tree, &io);
	PyErr_NTSTATUS_IS_ERR_RAISE(status);

	Py_RETURN_NONE;
}

static void py_smb_list_callback(struct clilist_file_info *f, const char *mask, void *state)
{
	PyObject *py_dirlist;
	PyObject *dict;

	if(!ISDOT(f->name) && !ISDOTDOT(f->name)) {
		py_dirlist = (PyObject *)state;

		dict = PyDict_New();
		if(dict) {
			PyDict_SetItemString(dict, "name", PyString_FromString(f->name));
			PyDict_SetItemString(dict, "short_name", PyString_FromString(f->short_name));
			PyDict_SetItemString(dict, "size", PyLong_FromUnsignedLongLong(f->size));
			PyDict_SetItemString(dict, "attrib", PyInt_FromLong(f->attrib));
			PyDict_SetItemString(dict, "mtime", PyInt_FromLong(f->mtime));

			PyList_Append(py_dirlist, dict);
		}
	}
}


static PyObject *py_smb_list(py_talloc_Object *self, PyObject *args, PyObject *kwargs)
{
	struct smb_private_data *spdata;
	PyObject *py_dirlist;
	const char *kwnames[] = { "directory", "mask", "attribs", NULL };
	char *base_dir;
	char *user_mask = NULL;
	uint16_t attribute = 0;
	char *mask;

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "z|sH",
					discard_const_p(char *, kwnames),
					&base_dir, &user_mask, &attribute)) {
		return NULL;
	}

	if (attribute == 0) {
		attribute = FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_HIDDEN |
				FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_DIRECTORY |
				FILE_ATTRIBUTE_ARCHIVE;
	}

	if (user_mask == NULL) {
		mask = talloc_asprintf(self->talloc_ctx, "%s\\*", base_dir);
	} else {
		mask = talloc_asprintf(self->talloc_ctx, "%s\\%s", base_dir, user_mask);
	}
	dos_format(mask);

	spdata = self->ptr;

	if((py_dirlist = PyList_New(0)) == NULL) {
		PyErr_NoMemory();
		return NULL;
	}

	smbcli_list(spdata->tree, mask, attribute, py_smb_list_callback, (void *)py_dirlist);

	talloc_free(mask);

	return py_dirlist;
}

static PyObject *py_smb_getacl(py_talloc_Object *self, PyObject *args, PyObject *kwargs)
{
	NTSTATUS status;
	union smb_fileinfo io;
	struct smb_private_data *spdata;
	const char *filename;

	if (!PyArg_ParseTuple(args, "s", &filename)) {
		return NULL;
	}

	spdata = self->ptr;

	io.query_secdesc.level = RAW_FILEINFO_SEC_DESC;
	io.query_secdesc.in.file.path = filename;
	io.query_secdesc.in.secinfo_flags = 0;

	status = smb_raw_query_secdesc(spdata->tree, self->talloc_ctx, &io);
	PyErr_NTSTATUS_IS_ERR_RAISE(status);

	return py_return_ndr_struct("samba.dcerpc.security", "descriptor",
				self->talloc_ctx, io.query_secdesc.out.sd);
}


static PyObject *py_smb_setacl(py_talloc_Object *self, PyObject *args, PyObject *kwargs)
{
	NTSTATUS status;
	union smb_setfileinfo io;
	struct smb_private_data *spdata;
	const char *filename;
	PyObject *py_sd;
	struct security_descriptor *sd;

	if (!PyArg_ParseTuple(args, "sO", &filename, &py_sd)) {
		return NULL;
	}

	spdata = self->ptr;

	sd = py_talloc_get_type(py_sd, struct security_descriptor);
	if (!sd) {
		PyErr_Format(PyExc_TypeError,
				"Expected dcerpc.security.descriptor for security_descriptor argument, got %s", talloc_get_name(py_talloc_get_ptr(py_sd)));
		return NULL;
	}

	io.set_secdesc.level = RAW_SFILEINFO_SEC_DESC;
	io.set_secdesc.in.file.path = filename;
	io.set_secdesc.in.secinfo_flags = 0;
	io.set_secdesc.in.sd = sd;

	status = smb_raw_set_secdesc(spdata->tree, &io);
	PyErr_NTSTATUS_IS_ERR_RAISE(status);

	Py_RETURN_NONE;
}


static PyMethodDef py_smb_methods[] = {
	{ "loadfile", (PyCFunction)py_smb_loadfile, METH_VARARGS,
		"Read contents of a file" },
	{ "savefile", (PyCFunction)py_smb_savefile, METH_VARARGS,
		"Write contents to a file" },
	{ "list", (PyCFunction)py_smb_list, METH_VARARGS|METH_KEYWORDS,
		"List contents of a directory" },
	{ "get_acl", (PyCFunction)py_smb_getacl, METH_VARARGS,
		"Get security descriptor for a file" },
	{ "set_acl", (PyCFunction)py_smb_setacl, METH_VARARGS,
		"Set security descriptor for a file" },
	{ NULL },
};


static PyObject *py_smb_new(PyTypeObject *type, PyObject *args, PyObject *kwargs)
{
	PyObject *py_creds = Py_None;
	PyObject *py_lp = Py_None;
	const char *kwnames[] = { "hostname", "service", "creds", "lp", NULL };
	const char *hostname = NULL;
	const char *service = NULL;
	py_talloc_Object *smb;
	struct smb_private_data *spdata;

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "zz|OO",
					discard_const_p(char *, kwnames),
					&hostname, &service, &py_creds, &py_lp)) {
		return NULL;
	}

	smb = (py_talloc_Object *)type->tp_alloc(type, 0);
	if (smb == NULL) {
		PyErr_NoMemory();
		return NULL;
	}
	smb->talloc_ctx = talloc_new(NULL);
	if (smb->talloc_ctx == NULL) {
		PyErr_NoMemory();
		return NULL;
	}

	spdata = talloc_zero(smb->talloc_ctx, struct smb_private_data);
	if (spdata == NULL) {
		PyErr_NoMemory();
		Py_DECREF(smb);
		return NULL;
	}

	spdata->lp_ctx = lpcfg_from_py_object(smb->talloc_ctx, py_lp);
	if (spdata->lp_ctx == NULL) {
		Py_DECREF(smb);
		return NULL;
	}
	spdata->creds = PyCredentials_AsCliCredentials(py_creds);
	spdata->ev_ctx = s4_event_context_init(smb->talloc_ctx);
	if (spdata->ev_ctx == NULL) {
		PyErr_NoMemory();
		Py_DECREF(smb);
		return NULL;
	}

	spdata->tree = do_smb_connect(smb->talloc_ctx, spdata, hostname, service);
	if (spdata->tree == NULL) {
		Py_DECREF(smb);
		return NULL;
	}

	smb->ptr = spdata;
	return (PyObject *)smb;
}


static PyTypeObject PySMB = {
	.tp_name = "smb.SMB",
	.tp_basicsize = sizeof(py_talloc_Object),
	.tp_new = py_smb_new,
	.tp_flags = Py_TPFLAGS_DEFAULT,
	.tp_methods = py_smb_methods,
	.tp_doc = "Create a SMB connection to <hostname> using <service>",
};

void initsmb(void)
{
	PyObject *m;
	PyTypeObject *talloc_type = PyTalloc_GetObjectType();
	if (talloc_type == NULL) {
		return;
	}

	PySMB.tp_base = talloc_type;

	if (PyType_Ready(&PySMB) < 0) {
		return;
	}

	m = Py_InitModule3("smb", NULL, "SMB File I/O support");
	if (m == NULL) {
	    return;
	}

	Py_INCREF(&PySMB);
	PyModule_AddObject(m, "SMB", (PyObject *)&PySMB);

#define ADD_FLAGS(val)	PyModule_AddObject(m, #val, PyInt_FromLong(val))

	ADD_FLAGS(FILE_ATTRIBUTE_READONLY);
	ADD_FLAGS(FILE_ATTRIBUTE_HIDDEN);
	ADD_FLAGS(FILE_ATTRIBUTE_SYSTEM);
	ADD_FLAGS(FILE_ATTRIBUTE_VOLUME);
	ADD_FLAGS(FILE_ATTRIBUTE_DIRECTORY);
	ADD_FLAGS(FILE_ATTRIBUTE_ARCHIVE);
	ADD_FLAGS(FILE_ATTRIBUTE_DEVICE);
	ADD_FLAGS(FILE_ATTRIBUTE_NORMAL);
	ADD_FLAGS(FILE_ATTRIBUTE_TEMPORARY);
	ADD_FLAGS(FILE_ATTRIBUTE_SPARSE);
	ADD_FLAGS(FILE_ATTRIBUTE_REPARSE_POINT);
	ADD_FLAGS(FILE_ATTRIBUTE_COMPRESSED);
	ADD_FLAGS(FILE_ATTRIBUTE_OFFLINE);
	ADD_FLAGS(FILE_ATTRIBUTE_NONINDEXED);
	ADD_FLAGS(FILE_ATTRIBUTE_ENCRYPTED);
	ADD_FLAGS(FILE_ATTRIBUTE_ALL_MASK);
}
