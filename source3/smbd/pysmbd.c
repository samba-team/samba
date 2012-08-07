/*
   Unix SMB/CIFS implementation.
   Set NT and POSIX ACLs and other VFS operations from Python 
   
   Copyrigyt (C) Andrew Bartlett 2012
   Copyright (C) Jeremy Allison 1994-2009.
   Copyright (C) Andreas Gruenbacher 2002.
   Copyright (C) Simo Sorce <idra@samba.org> 2009.
   Copyright (C) Simo Sorce 2002
   Copyright (C) Eric Lorimer 2002

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

#include "includes.h"
#include "smbd/smbd.h"
#include <Python.h>
#include "libcli/util/pyerrors.h"
#include "librpc/rpc/pyrpc_util.h"
#include <pytalloc.h>
#include "system/filesys.h"

extern const struct generic_mapping file_generic_mapping;

#undef  DBGC_CLASS
#define DBGC_CLASS DBGC_ACLS

static NTSTATUS set_sys_acl_no_snum(const char *fname,
				     SMB_ACL_TYPE_T acltype,
				     SMB_ACL_T theacl)
{
	connection_struct *conn;
	NTSTATUS status = NT_STATUS_OK;
	int ret;

	conn = talloc_zero(NULL, connection_struct);
	if (conn == NULL) {
		DEBUG(0, ("talloc failed\n"));
		return NT_STATUS_NO_MEMORY;
	}

	if (!(conn->params = talloc(conn, struct share_params))) {
		DEBUG(0,("get_nt_acl_no_snum: talloc() failed!\n"));
		TALLOC_FREE(conn);
		return NT_STATUS_NO_MEMORY;
	}

	conn->params->service = -1;

	set_conn_connectpath(conn, "/");

	smbd_vfs_init(conn);

	ret = SMB_VFS_SYS_ACL_SET_FILE( conn, fname, acltype, theacl);
	if (ret != 0) {
		status = map_nt_error_from_unix_common(ret);
		DEBUG(0,("set_nt_acl_no_snum: fset_nt_acl returned zero.\n"));
	}

	conn_free(conn);

	return status;
}

static NTSTATUS set_nt_acl_no_snum(const char *fname,
				   uint32 security_info_sent, const struct security_descriptor *sd)
{
	TALLOC_CTX *frame = talloc_stackframe();
	connection_struct *conn;
	NTSTATUS status = NT_STATUS_OK;
	files_struct *fsp;
	struct smb_filename *smb_fname = NULL;
	int flags;

	conn = talloc_zero(frame, connection_struct);
	if (conn == NULL) {
		DEBUG(0, ("talloc failed\n"));
		return NT_STATUS_NO_MEMORY;
	}

	if (!(conn->params = talloc(conn, struct share_params))) {
		DEBUG(0,("get_nt_acl_no_snum: talloc() failed!\n"));
		TALLOC_FREE(frame);
		return NT_STATUS_NO_MEMORY;
	}

	conn->params->service = -1;

	set_conn_connectpath(conn, "/");

	smbd_vfs_init(conn);

	fsp = talloc_zero(frame, struct files_struct);
	if (fsp == NULL) {
		TALLOC_FREE(frame);
		return NT_STATUS_NO_MEMORY;
	}
	fsp->fh = talloc(fsp, struct fd_handle);
	if (fsp->fh == NULL) {
		TALLOC_FREE(frame);
		return NT_STATUS_NO_MEMORY;
	}
	fsp->conn = conn;

	status = create_synthetic_smb_fname_split(fsp, fname, NULL,
						  &smb_fname);
	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(frame);
		return status;
	}

	fsp->fsp_name = smb_fname;

#ifdef O_DIRECTORY
	flags = O_RDONLY|O_DIRECTORY;
#else
	/* POSIX allows us to open a directory with O_RDONLY. */
	flags = O_RDONLY;
#endif

	fsp->fh->fd = SMB_VFS_OPEN(conn, smb_fname, fsp, O_RDWR, 00400);
	if (fsp->fh->fd == -1 && errno == EISDIR) {
		fsp->fh->fd = SMB_VFS_OPEN(conn, smb_fname, fsp, flags, 00400);
	}
	if (fsp->fh->fd == -1) {
		printf("open: error=%d (%s)\n", errno, strerror(errno));
		TALLOC_FREE(frame);
		return NT_STATUS_UNSUCCESSFUL;
	}

	status = SMB_VFS_FSET_NT_ACL( fsp, security_info_sent, sd);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0,("set_nt_acl_no_snum: fset_nt_acl returned %s.\n", nt_errstr(status)));
	}

	conn_free(conn);
	TALLOC_FREE(frame);

	return status;
}


static SMB_ACL_T make_simple_acl(uid_t uid, gid_t gid)
{
	mode_t mode = SMB_ACL_READ|SMB_ACL_WRITE;
	mode_t mode0 = 0;

	SMB_ACL_ENTRY_T entry;
	SMB_ACL_T acl = sys_acl_init(4);

	if (!acl) {
		return NULL;
	}

	if (sys_acl_create_entry(&acl, &entry) != 0) {
		sys_acl_free_acl(acl);
		return NULL;
	}

	if (sys_acl_set_tag_type(entry, SMB_ACL_USER_OBJ) != 0) {
		sys_acl_free_acl(acl);
		return NULL;
	}

	if (sys_acl_set_permset(entry, &mode) != 0) {
		sys_acl_free_acl(acl);
		return NULL;
	}

	if (sys_acl_create_entry(&acl, &entry) != 0) {
		sys_acl_free_acl(acl);
		return NULL;
	}

	if (sys_acl_set_tag_type(entry, SMB_ACL_GROUP_OBJ) != 0) {
		sys_acl_free_acl(acl);
		return NULL;
	}

	if (sys_acl_set_permset(entry, &mode) != 0) {
		sys_acl_free_acl(acl);
		return NULL;
	}

	if (sys_acl_create_entry(&acl, &entry) != 0) {
		sys_acl_free_acl(acl);
		return NULL;
	}

	if (sys_acl_set_tag_type(entry, SMB_ACL_OTHER) != 0) {
		sys_acl_free_acl(acl);
		return NULL;
	}

	if (sys_acl_set_permset(entry, &mode0) != 0) {
		sys_acl_free_acl(acl);
		return NULL;
	}

	if (sys_acl_create_entry(&acl, &entry) != 0) {
		sys_acl_free_acl(acl);
		return NULL;
	}

	if (sys_acl_set_tag_type(entry, SMB_ACL_GROUP) != 0) {
		sys_acl_free_acl(acl);
		return NULL;
	}

	if (sys_acl_set_qualifier(entry, &gid) != 0) {
		sys_acl_free_acl(acl);
		return NULL;
	}

	if (sys_acl_set_permset(entry, &mode) != 0) {
		sys_acl_free_acl(acl);
		return NULL;
	}

	if (sys_acl_create_entry(&acl, &entry) != 0) {
		sys_acl_free_acl(acl);
		return NULL;
	}

	if (sys_acl_set_tag_type(entry, SMB_ACL_MASK) != 0) {
		sys_acl_free_acl(acl);
		return NULL;
	}

	if (sys_acl_set_permset(entry, &mode0) != 0) {
		sys_acl_free_acl(acl);
		return NULL;
	}
	return acl;
}

/*
  set a simple ACL on a file, as a test
 */
static PyObject *py_smbd_set_simple_acl(PyObject *self, PyObject *args)
{
	NTSTATUS status;
	char *fname;
	int uid, gid;
	SMB_ACL_T acl;
	TALLOC_CTX *frame;

	if (!PyArg_ParseTuple(args, "sii", &fname, &uid, &gid))
		return NULL;

	acl = make_simple_acl(uid, gid);

	frame = talloc_stackframe();

	status = set_sys_acl_no_snum(fname, SMB_ACL_TYPE_ACCESS, acl);
	sys_acl_free_acl(acl);

	TALLOC_FREE(frame);

	PyErr_NTSTATUS_IS_ERR_RAISE(status);

	Py_RETURN_NONE;
}

/*
  check if we have ACL support
 */
static PyObject *py_smbd_have_posix_acls(PyObject *self, PyObject *args)
{
#ifdef HAVE_POSIX_ACLS
	return PyBool_FromLong(true);
#else
	return PyBool_FromLong(false);
#endif
}

/*
  set a simple ACL on a file, as a test
 */
static PyObject *py_smbd_set_nt_acl(PyObject *self, PyObject *args)
{
	NTSTATUS status;
	char *fname;
	int security_info_sent;
	PyObject *py_sd;
	struct security_descriptor *sd;

	if (!PyArg_ParseTuple(args, "siO", &fname, &security_info_sent, &py_sd))
		return NULL;

	if (!py_check_dcerpc_type(py_sd, "samba.dcerpc.security", "descriptor")) {
		return NULL;
	}

	sd = pytalloc_get_type(py_sd, struct security_descriptor);

	status = set_nt_acl_no_snum(fname, security_info_sent, sd);
	PyErr_NTSTATUS_IS_ERR_RAISE(status);

	Py_RETURN_NONE;
}

/*
  set a simple ACL on a file, as a test
 */
static PyObject *py_smbd_get_nt_acl(PyObject *self, PyObject *args)
{
	char *fname;
	int security_info_sent;
	PyObject *py_sd;
	struct security_descriptor *sd;
	TALLOC_CTX *tmp_ctx = talloc_new(NULL);

	if (!PyArg_ParseTuple(args, "si", &fname, &security_info_sent))
		return NULL;
	
	sd = get_nt_acl_no_snum(tmp_ctx, fname);

	py_sd = py_return_ndr_struct("samba.dcerpc.security", "security_descriptor", sd, sd);

	talloc_free(tmp_ctx);

	return py_sd;
}

static PyMethodDef py_smbd_methods[] = {
	{ "have_posix_acls",
		(PyCFunction)py_smbd_have_posix_acls, METH_VARARGS,
		NULL },
	{ "set_simple_acl",
		(PyCFunction)py_smbd_set_simple_acl, METH_VARARGS,
		NULL },
	{ "set_nt_acl",
		(PyCFunction)py_smbd_set_nt_acl, METH_VARARGS,
		NULL },
	{ "get_nt_acl",
		(PyCFunction)py_smbd_get_nt_acl, METH_VARARGS,
		NULL },
	{ NULL }
};

void initsmbd(void);
void initsmbd(void)
{
	PyObject *m;

	m = Py_InitModule3("smbd", py_smbd_methods,
			   "Python bindings for the smbd file server.");
	if (m == NULL)
		return;

}
