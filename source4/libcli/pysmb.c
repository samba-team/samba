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
#include "system/filesys.h"
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


/*
 * Connect to SMB share using smb_full_connection
 */
static NTSTATUS do_smb_connect(TALLOC_CTX *mem_ctx, struct smb_private_data *spdata,
			const char *hostname, const char *service, struct smbcli_tree **tree)
{
	struct smbcli_state *smb_state;
	NTSTATUS status;
	struct smbcli_options options;
	struct smbcli_session_options session_options;

	*tree = NULL;

	gensec_init();

	smb_state = smbcli_state_init(mem_ctx);

	lpcfg_smbcli_options(spdata->lp_ctx, &options);
	lpcfg_smbcli_session_options(spdata->lp_ctx, &session_options);

	status = smbcli_full_connection(mem_ctx, &smb_state, hostname, 
					lpcfg_smb_ports(spdata->lp_ctx),
					service, 
					NULL,
					lpcfg_socket_options(spdata->lp_ctx),
					spdata->creds,
					lpcfg_resolve_context(spdata->lp_ctx),
					spdata->ev_ctx,
					&options,
					&session_options,
					lpcfg_gensec_settings(mem_ctx, spdata->lp_ctx));

	if (NT_STATUS_IS_OK(status)) {
		*tree = smb_state->tree;
	}

	return status;
}


/*
 * Read SMB file and return the contents of the file as python string
 */
static PyObject * py_smb_loadfile(pytalloc_Object *self, PyObject *args)
{
	struct smb_composite_loadfile io;
	const char *filename;
	NTSTATUS status;
	struct smb_private_data *spdata;

	if (!PyArg_ParseTuple(args, "s:loadfile", &filename)) {
		return NULL;
	}

	ZERO_STRUCT(io);

	io.in.fname = filename;

	spdata = self->ptr;
	status = smb_composite_loadfile(spdata->tree, self->talloc_ctx, &io);
	PyErr_NTSTATUS_IS_ERR_RAISE(status);

	return Py_BuildValue("s#", io.out.data, io.out.size);
}

/*
 * Create a SMB file with given string as the contents
 */
static PyObject * py_smb_savefile(pytalloc_Object *self, PyObject *args)
{
	struct smb_composite_savefile io;
	const char *filename;
	char *data;
	NTSTATUS status;
	struct smb_private_data *spdata;

	if (!PyArg_ParseTuple(args, "ss:savefile", &filename, &data)) {
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

/*
 * Callback function to accumulate directory contents in a python list
 */
static void py_smb_list_callback(struct clilist_file_info *f, const char *mask, void *state)
{
	PyObject *py_dirlist;
	PyObject *dict;

	if(!ISDOT(f->name) && !ISDOTDOT(f->name)) {
		py_dirlist = (PyObject *)state;

		dict = PyDict_New();
		if(dict) {
			PyDict_SetItemString(dict, "name", PyString_FromString(f->name));
			
			/* Windows does not always return short_name */
			if (f->short_name) {
				PyDict_SetItemString(dict, "short_name", PyString_FromString(f->short_name));
			} else {
				PyDict_SetItemString(dict, "short_name", Py_None);
			}

			PyDict_SetItemString(dict, "size", PyLong_FromUnsignedLongLong(f->size));
			PyDict_SetItemString(dict, "attrib", PyInt_FromLong(f->attrib));
			PyDict_SetItemString(dict, "mtime", PyInt_FromLong(f->mtime));

			PyList_Append(py_dirlist, dict);
		}
	}
}

/*
 * List the directory contents for specified directory (Ignore '.' and '..' dirs)
 */
static PyObject *py_smb_list(pytalloc_Object *self, PyObject *args, PyObject *kwargs)
{
	struct smb_private_data *spdata;
	PyObject *py_dirlist;
	const char *kwnames[] = { "directory", "mask", "attribs", NULL };
	char *base_dir;
	char *user_mask = NULL;
	char *mask;
	uint16_t attribute = FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_DIRECTORY
				| FILE_ATTRIBUTE_ARCHIVE;

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "z|sH:list",
					discard_const_p(char *, kwnames),
					&base_dir, &user_mask, &attribute)) {
		return NULL;
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

/*
 * Create a directory
 */
static PyObject *py_smb_mkdir(pytalloc_Object *self, PyObject *args)
{
	NTSTATUS status;
	const char *dirname;
	struct smb_private_data *spdata;

	if (!PyArg_ParseTuple(args, "s:mkdir", &dirname)) {
		return NULL;
	}

	spdata = self->ptr;	
	status = smbcli_mkdir(spdata->tree, dirname);
	PyErr_NTSTATUS_IS_ERR_RAISE(status);

	Py_RETURN_NONE;
}

/*
 * Remove a directory
 */
static PyObject *py_smb_rmdir(pytalloc_Object *self, PyObject *args)
{
	NTSTATUS status;
	const char *dirname;
	struct smb_private_data *spdata;

	if (!PyArg_ParseTuple(args, "s:rmdir", &dirname)) {
		return NULL;
	}

	spdata = self->ptr;	
	status = smbcli_rmdir(spdata->tree, dirname);
	PyErr_NTSTATUS_IS_ERR_RAISE(status);

	Py_RETURN_NONE;
}

/*
 * Remove a directory and all its contents
 */
static PyObject *py_smb_deltree(pytalloc_Object *self, PyObject *args)
{
	int status;
	const char *dirname;
	struct smb_private_data *spdata;

	if (!PyArg_ParseTuple(args, "s:deltree", &dirname)) {
		return NULL;
	}

	spdata = self->ptr;
	status = smbcli_deltree(spdata->tree, dirname);
	if (status <= 0) {
		return NULL;
	}

	Py_RETURN_NONE;
}

/*
 * Check existence of a path
 */
static PyObject *py_smb_chkpath(pytalloc_Object *self, PyObject *args)
{
	NTSTATUS status;
	const char *path;
	struct smb_private_data *spdata;

	if (!PyArg_ParseTuple(args, "s:chkpath", &path)) {
		return NULL;
	}

	spdata = self->ptr;	
	status = smbcli_chkpath(spdata->tree, path);

	if (NT_STATUS_IS_OK(status)) {
		Py_RETURN_TRUE;
	}

	Py_RETURN_FALSE;
}

/*
 * Read ACL on a given file/directory as a security descriptor object
 */
static PyObject *py_smb_getacl(pytalloc_Object *self, PyObject *args, PyObject *kwargs)
{
	NTSTATUS status;
	union smb_open io;
	union smb_fileinfo fio;
	struct smb_private_data *spdata;
	const char *filename;
	uint32_t sinfo = 0;
	int access_mask = SEC_FLAG_MAXIMUM_ALLOWED;
	int fnum;

	if (!PyArg_ParseTuple(args, "s|Ii:get_acl", &filename, &sinfo, &access_mask)) {
		return NULL;
	}

	ZERO_STRUCT(io);

	spdata = self->ptr;	

	io.generic.level = RAW_OPEN_NTCREATEX;
	io.ntcreatex.in.root_fid.fnum = 0;
	io.ntcreatex.in.flags = 0;
	io.ntcreatex.in.access_mask = access_mask;
	io.ntcreatex.in.create_options = 0;
	io.ntcreatex.in.file_attr = FILE_ATTRIBUTE_NORMAL;
	io.ntcreatex.in.share_access = NTCREATEX_SHARE_ACCESS_READ | 
					NTCREATEX_SHARE_ACCESS_WRITE;
	io.ntcreatex.in.alloc_size = 0;
	io.ntcreatex.in.open_disposition = NTCREATEX_DISP_OPEN;
	io.ntcreatex.in.impersonation = NTCREATEX_IMPERSONATION_ANONYMOUS;
	io.ntcreatex.in.security_flags = 0;
	io.ntcreatex.in.fname = filename;
	
	status = smb_raw_open(spdata->tree, self->talloc_ctx, &io);
	PyErr_NTSTATUS_IS_ERR_RAISE(status);

	fnum = io.ntcreatex.out.file.fnum;

	ZERO_STRUCT(fio);

	fio.query_secdesc.level = RAW_FILEINFO_SEC_DESC;
	fio.query_secdesc.in.file.fnum = fnum;
	if (sinfo)
		fio.query_secdesc.in.secinfo_flags = sinfo;
	else
		fio.query_secdesc.in.secinfo_flags = SECINFO_OWNER |
						SECINFO_GROUP |
						SECINFO_DACL |
						SECINFO_PROTECTED_DACL |
						SECINFO_UNPROTECTED_DACL |
						SECINFO_SACL |
						SECINFO_PROTECTED_SACL |
						SECINFO_UNPROTECTED_SACL;

	status = smb_raw_query_secdesc(spdata->tree, self->talloc_ctx, &fio);
	smbcli_close(spdata->tree, fnum);

	PyErr_NTSTATUS_IS_ERR_RAISE(status);

	return py_return_ndr_struct("samba.dcerpc.security", "descriptor",
				self->talloc_ctx, fio.query_secdesc.out.sd);
}

/*
 * Set ACL on file/directory using given security descriptor object
 */
static PyObject *py_smb_setacl(pytalloc_Object *self, PyObject *args, PyObject *kwargs)
{
	NTSTATUS status;
	union smb_open io;
	union smb_setfileinfo fio;
	struct smb_private_data *spdata;
	const char *filename;
	PyObject *py_sd;
	struct security_descriptor *sd;
	uint32_t sinfo = 0;
	int fnum;

	if (!PyArg_ParseTuple(args, "sO|I:get_acl", &filename, &py_sd, &sinfo)) {
		return NULL;
	}

	spdata = self->ptr;

	sd = pytalloc_get_type(py_sd, struct security_descriptor);
	if (!sd) {
		PyErr_Format(PyExc_TypeError, 
			"Expected dcerpc.security.descriptor as argument, got %s", 
			talloc_get_name(pytalloc_get_ptr(py_sd)));
		return NULL;
	}

	ZERO_STRUCT(io);

	spdata = self->ptr;	

	io.generic.level = RAW_OPEN_NTCREATEX;
	io.ntcreatex.in.root_fid.fnum = 0;
	io.ntcreatex.in.flags = 0;
	io.ntcreatex.in.access_mask = SEC_FLAG_MAXIMUM_ALLOWED;
	io.ntcreatex.in.create_options = 0;
	io.ntcreatex.in.file_attr = FILE_ATTRIBUTE_NORMAL;
	io.ntcreatex.in.share_access = NTCREATEX_SHARE_ACCESS_READ | 
					NTCREATEX_SHARE_ACCESS_WRITE;
	io.ntcreatex.in.alloc_size = 0;
	io.ntcreatex.in.open_disposition = NTCREATEX_DISP_OPEN;
	io.ntcreatex.in.impersonation = NTCREATEX_IMPERSONATION_ANONYMOUS;
	io.ntcreatex.in.security_flags = 0;
	io.ntcreatex.in.fname = filename;
	
	status = smb_raw_open(spdata->tree, self->talloc_ctx, &io);
	PyErr_NTSTATUS_IS_ERR_RAISE(status);

	fnum = io.ntcreatex.out.file.fnum;

	ZERO_STRUCT(fio);

	fio.set_secdesc.level = RAW_SFILEINFO_SEC_DESC;
	fio.set_secdesc.in.file.fnum = fnum;
	if (sinfo)
		fio.set_secdesc.in.secinfo_flags = sinfo;
	else
		fio.set_secdesc.in.secinfo_flags = SECINFO_OWNER |
						SECINFO_GROUP |
						SECINFO_DACL |
						SECINFO_PROTECTED_DACL |
						SECINFO_UNPROTECTED_DACL |
						SECINFO_SACL |
						SECINFO_PROTECTED_SACL |
						SECINFO_UNPROTECTED_SACL;

	fio.set_secdesc.in.sd = sd;

	status = smb_raw_set_secdesc(spdata->tree, &fio);
	smbcli_close(spdata->tree, fnum);

	PyErr_NTSTATUS_IS_ERR_RAISE(status);

	Py_RETURN_NONE;
}

/*
 * Open the file with the parameters passed in and return an object if OK
 */
static PyObject *py_open_file(pytalloc_Object *self, PyObject *args, PyObject *kwargs)
{
	NTSTATUS status;
	union smb_open io;
	struct smb_private_data *spdata;
	const char *filename;
	uint32_t access_mask = SEC_FLAG_MAXIMUM_ALLOWED;
	uint32_t share_access = NTCREATEX_SHARE_ACCESS_READ |
				NTCREATEX_SHARE_ACCESS_WRITE;
        uint32_t open_disposition = NTCREATEX_DISP_OPEN;
        uint32_t create_options = 0;
	TALLOC_CTX *mem_ctx;
	int fnum;

	if (!PyArg_ParseTuple(args, "s|iiii:open_file", 
				&filename, 
				&access_mask,
				&share_access,
				&open_disposition,
				&create_options)) {
		return NULL;
	}

	ZERO_STRUCT(io);

	spdata = self->ptr;	

	mem_ctx = talloc_new(NULL);

	io.generic.level = RAW_OPEN_NTCREATEX;
	io.ntcreatex.in.root_fid.fnum = 0;
	io.ntcreatex.in.flags = 0;
	io.ntcreatex.in.access_mask = access_mask;
	io.ntcreatex.in.create_options = create_options;
	io.ntcreatex.in.file_attr = FILE_ATTRIBUTE_NORMAL;
	io.ntcreatex.in.share_access = share_access;
	io.ntcreatex.in.alloc_size = 0;
	io.ntcreatex.in.open_disposition = open_disposition;
	io.ntcreatex.in.impersonation = NTCREATEX_IMPERSONATION_ANONYMOUS;
	io.ntcreatex.in.security_flags = 0;
	io.ntcreatex.in.fname = filename;
	
	status = smb_raw_open(spdata->tree, mem_ctx, &io);
	talloc_free(mem_ctx);

	PyErr_NTSTATUS_IS_ERR_RAISE(status);

	fnum = io.ntcreatex.out.file.fnum;

	return Py_BuildValue("i", fnum);
}

/*
 * Close the file based on the fnum passed in
 */
static PyObject *py_close_file(pytalloc_Object *self, PyObject *args, PyObject *kwargs)
{
	struct smb_private_data *spdata;
	int fnum;

	if (!PyArg_ParseTuple(args, "i:close_file", &fnum)) {
		return NULL;
	}

	spdata = self->ptr;	

	/*
	 * Should check the status ...
	 */
	smbcli_close(spdata->tree, fnum);

	Py_RETURN_NONE;
}

static PyMethodDef py_smb_methods[] = {
	{ "loadfile", (PyCFunction)py_smb_loadfile, METH_VARARGS,
		"loadfile(path) -> file contents as a string\n\n \
		Read contents of a file." },
	{ "savefile", (PyCFunction)py_smb_savefile, METH_VARARGS,
		"savefile(path, str) -> None\n\n \
		Write string str to file." },
	{ "list", (PyCFunction)py_smb_list, METH_VARARGS|METH_KEYWORDS,
		"list(path) -> directory contents as a dictionary\n\n \
		List contents of a directory. The keys are, \n \
		\tname: Long name of the directory item\n \
		\tshort_name: Short name of the directory item\n \
		\tsize: File size in bytes\n \
		\tattrib: Attributes\n \
		\tmtime: Modification time\n" },
	{ "mkdir", (PyCFunction)py_smb_mkdir, METH_VARARGS,
		"mkdir(path) -> None\n\n \
		Create a directory." },
	{ "rmdir", (PyCFunction)py_smb_rmdir, METH_VARARGS,
		"rmdir(path) -> None\n\n \
		Delete a directory." },
	{ "deltree", (PyCFunction)py_smb_deltree, METH_VARARGS,
		"deltree(path) -> None\n\n \
		Delete a directory and all its contents." },
	{ "chkpath", (PyCFunction)py_smb_chkpath, METH_VARARGS,
		"chkpath(path) -> True or False\n\n \
		Return true if path exists, false otherwise." },
	{ "get_acl", (PyCFunction)py_smb_getacl, METH_VARARGS,
		"get_acl(path[, security_info=0]) -> security_descriptor object\n\n \
		Get security descriptor for file." },
	{ "set_acl", (PyCFunction)py_smb_setacl, METH_VARARGS,
		"set_acl(path, security_descriptor[, security_info=0]) -> None\n\n \
		Set security descriptor for file." },
	{ "open_file", (PyCFunction)py_open_file, METH_VARARGS,
		"open_file(path, access_mask[, share_access[, open_disposition[, create_options]]] -> fnum\n\n \
		Open a file. Throws NTSTATUS exceptions on errors." },
	{ "close_file", (PyCFunction)py_close_file, METH_VARARGS,
		"close_file(fnum) -> None\n\n \
		Close the file based on fnum."},
	{ NULL },
};

static PyObject *py_smb_new(PyTypeObject *type, PyObject *args, PyObject *kwargs)
{
	PyObject *py_creds = Py_None;
	PyObject *py_lp = Py_None;
	const char *kwnames[] = { "hostname", "service", "creds", "lp", NULL };
	const char *hostname = NULL;
	const char *service = NULL;
	pytalloc_Object *smb;
	struct smb_private_data *spdata;
	NTSTATUS status;

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "zz|OO",
					discard_const_p(char *, kwnames),
					&hostname, &service, &py_creds, &py_lp)) {
		return NULL;
	}

	smb = (pytalloc_Object *)type->tp_alloc(type, 0);
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

	status = do_smb_connect(smb->talloc_ctx, spdata, hostname, service, &spdata->tree);
	PyErr_NTSTATUS_IS_ERR_RAISE(status);
	if (spdata->tree == NULL) {
		Py_DECREF(smb);
		return NULL;
	}

	smb->ptr = spdata;
	return (PyObject *)smb;
}

static PyTypeObject PySMB = {
	.tp_name = "smb.SMB",
	.tp_basicsize = sizeof(pytalloc_Object),
	.tp_new = py_smb_new,
	.tp_flags = Py_TPFLAGS_DEFAULT,
	.tp_methods = py_smb_methods,
	.tp_doc = "SMB(hostname, service[, creds[, lp]]) -> SMB connection object\n",

};

void initsmb(void)
{
	PyObject *m;
	PyTypeObject *talloc_type = pytalloc_GetObjectType();
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
