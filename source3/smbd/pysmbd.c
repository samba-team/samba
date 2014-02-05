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

static int conn_free_wrapper(connection_struct *conn)
{
	conn_free(conn);
	return 0;
};

static connection_struct *get_conn(TALLOC_CTX *mem_ctx, const char *service)
{
	connection_struct *conn;
	TALLOC_CTX *frame = talloc_stackframe();
	int snum = -1;
	NTSTATUS status;

	if (!posix_locking_init(false)) {
		PyErr_NoMemory();
		TALLOC_FREE(frame);
		return NULL;
	}

	if (service) {
		snum = lp_servicenumber(service);
		if (snum == -1) {
			TALLOC_FREE(frame);
			PyErr_SetString(PyExc_RuntimeError, "unknown service");
			return NULL;
		}
	}

	status = create_conn_struct(mem_ctx, NULL, NULL, &conn, snum, "/",
					    NULL);
	PyErr_NTSTATUS_IS_ERR_RAISE(status);

	TALLOC_FREE(frame);
	/* Ignore read-only and share restrictions */
	conn->read_only = false;
	conn->share_access = SEC_RIGHTS_FILE_ALL;
	talloc_set_destructor(conn, conn_free_wrapper);
	return conn;
}

static int set_sys_acl_conn(const char *fname,
				 SMB_ACL_TYPE_T acltype,
				 SMB_ACL_T theacl, connection_struct *conn)
{
	int ret;
	mode_t saved_umask;

	TALLOC_CTX *frame = talloc_stackframe();

	/* we want total control over the permissions on created files,
	   so set our umask to 0 */
	saved_umask = umask(0);

	ret = SMB_VFS_SYS_ACL_SET_FILE( conn, fname, acltype, theacl);

	umask(saved_umask);

	TALLOC_FREE(frame);
	return ret;
}

static NTSTATUS set_nt_acl_conn(const char *fname,
				uint32 security_info_sent, const struct security_descriptor *sd,
				connection_struct *conn)
{
	TALLOC_CTX *frame = talloc_stackframe();
	NTSTATUS status = NT_STATUS_OK;
	files_struct *fsp;
	struct smb_filename *smb_fname = NULL;
	int flags, ret;
	mode_t saved_umask;

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

	/* we want total control over the permissions on created files,
	   so set our umask to 0 */
	saved_umask = umask(0);

	smb_fname = synthetic_smb_fname_split(fsp, fname, NULL);
	if (smb_fname == NULL) {
		TALLOC_FREE(frame);
		umask(saved_umask);
		return NT_STATUS_NO_MEMORY;
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
		umask(saved_umask);
		return NT_STATUS_UNSUCCESSFUL;
	}

	ret = SMB_VFS_FSTAT(fsp, &smb_fname->st);
	if (ret == -1) {
		/* If we have an fd, this stat should succeed. */
		DEBUG(0,("Error doing fstat on open file %s "
			"(%s)\n",
			smb_fname_str_dbg(smb_fname),
			strerror(errno) ));
		TALLOC_FREE(frame);
		umask(saved_umask);
		return map_nt_error_from_unix(errno);
	}

	fsp->file_id = vfs_file_id_from_sbuf(conn, &smb_fname->st);
	fsp->vuid = UID_FIELD_INVALID;
	fsp->file_pid = 0;
	fsp->can_lock = True;
	fsp->can_read = True;
	fsp->can_write = True;
	fsp->print_file = NULL;
	fsp->modified = False;
	fsp->sent_oplock_break = NO_BREAK_SENT;
	fsp->is_directory = S_ISDIR(smb_fname->st.st_ex_mode);

	status = SMB_VFS_FSET_NT_ACL( fsp, security_info_sent, sd);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0,("set_nt_acl_no_snum: fset_nt_acl returned %s.\n", nt_errstr(status)));
	}

	SMB_VFS_CLOSE(fsp);

	conn_free(conn);
	TALLOC_FREE(frame);

	umask(saved_umask);
	return status;
}

static NTSTATUS get_nt_acl_conn(TALLOC_CTX *mem_ctx,
				const char *fname,
				connection_struct *conn,
				uint32 security_info_wanted,
				struct security_descriptor **sd)
{
	TALLOC_CTX *frame = talloc_stackframe();
	NTSTATUS status = SMB_VFS_GET_NT_ACL( conn, fname, security_info_wanted,
				     mem_ctx, sd);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0,("get_nt_acl_conn: get_nt_acl returned %s.\n", nt_errstr(status)));
	}

	TALLOC_FREE(frame);

	return status;
}


static SMB_ACL_T make_simple_acl(gid_t gid, mode_t chmod_mode)
{
	TALLOC_CTX *frame = talloc_stackframe();

	mode_t mode = SMB_ACL_READ|SMB_ACL_WRITE|SMB_ACL_EXECUTE;

	mode_t mode_user = (chmod_mode & 0700) >> 6;
	mode_t mode_group = (chmod_mode & 070) >> 3;
	mode_t mode_other = chmod_mode &  07;
	SMB_ACL_ENTRY_T entry;
	SMB_ACL_T acl = sys_acl_init(frame);

	if (!acl) {
		return NULL;
	}

	if (sys_acl_create_entry(&acl, &entry) != 0) {
		TALLOC_FREE(frame);
		return NULL;
	}

	if (sys_acl_set_tag_type(entry, SMB_ACL_USER_OBJ) != 0) {
		TALLOC_FREE(frame);
		return NULL;
	}

	if (sys_acl_set_permset(entry, &mode_user) != 0) {
		TALLOC_FREE(frame);
		return NULL;
	}

	if (sys_acl_create_entry(&acl, &entry) != 0) {
		TALLOC_FREE(frame);
		return NULL;
	}

	if (sys_acl_set_tag_type(entry, SMB_ACL_GROUP_OBJ) != 0) {
		TALLOC_FREE(frame);
		return NULL;
	}

	if (sys_acl_set_permset(entry, &mode_group) != 0) {
		TALLOC_FREE(frame);
		return NULL;
	}

	if (sys_acl_create_entry(&acl, &entry) != 0) {
		TALLOC_FREE(frame);
		return NULL;
	}

	if (sys_acl_set_tag_type(entry, SMB_ACL_OTHER) != 0) {
		TALLOC_FREE(frame);
		return NULL;
	}

	if (sys_acl_set_permset(entry, &mode_other) != 0) {
		TALLOC_FREE(frame);
		return NULL;
	}

	if (gid != -1) {
		if (sys_acl_create_entry(&acl, &entry) != 0) {
			TALLOC_FREE(frame);
			return NULL;
		}

		if (sys_acl_set_tag_type(entry, SMB_ACL_GROUP) != 0) {
			TALLOC_FREE(frame);
			return NULL;
		}

		if (sys_acl_set_qualifier(entry, &gid) != 0) {
			TALLOC_FREE(frame);
			return NULL;
		}

		if (sys_acl_set_permset(entry, &mode_group) != 0) {
			TALLOC_FREE(frame);
			return NULL;
		}
	}

	if (sys_acl_create_entry(&acl, &entry) != 0) {
		TALLOC_FREE(frame);
		return NULL;
	}

	if (sys_acl_set_tag_type(entry, SMB_ACL_MASK) != 0) {
		TALLOC_FREE(frame);
		return NULL;
	}

	if (sys_acl_set_permset(entry, &mode) != 0) {
		TALLOC_FREE(frame);
		return NULL;
	}
	return acl;
}

/*
  set a simple ACL on a file, as a test
 */
static PyObject *py_smbd_set_simple_acl(PyObject *self, PyObject *args, PyObject *kwargs)
{
	const char * const kwnames[] = { "fname", "mode", "gid", "service", NULL };
	char *fname, *service = NULL;
	int ret;
	int mode, gid = -1;
	SMB_ACL_T acl;
	TALLOC_CTX *frame;
	connection_struct *conn;

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "si|iz",
					 discard_const_p(char *, kwnames),
					 &fname, &mode, &gid, &service))
		return NULL;

	acl = make_simple_acl(gid, mode);

	frame = talloc_stackframe();

	conn = get_conn(frame, service);
	if (!conn) {
		return NULL;
	}

	ret = set_sys_acl_conn(fname, SMB_ACL_TYPE_ACCESS, acl, conn);
	TALLOC_FREE(acl);

	if (ret != 0) {
		TALLOC_FREE(frame);
		errno = ret;
		return PyErr_SetFromErrno(PyExc_OSError);
	}

	TALLOC_FREE(frame);

	Py_RETURN_NONE;
}

/*
  chown a file
 */
static PyObject *py_smbd_chown(PyObject *self, PyObject *args, PyObject *kwargs)
{
	const char * const kwnames[] = { "fname", "uid", "gid", "service", NULL };
	connection_struct *conn;
	int ret;

	char *fname, *service = NULL;
	int uid, gid;
	TALLOC_CTX *frame;
	mode_t saved_umask;

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "sii|z",
					 discard_const_p(char *, kwnames),
					 &fname, &uid, &gid, &service))
		return NULL;

	frame = talloc_stackframe();

	conn = get_conn(frame, service);
	if (!conn) {
		return NULL;
	}

	/* we want total control over the permissions on created files,
	   so set our umask to 0 */
	saved_umask = umask(0);

	ret = SMB_VFS_CHOWN( conn, fname, uid, gid);
	if (ret != 0) {
		umask(saved_umask);
		TALLOC_FREE(frame);
		errno = ret;
		return PyErr_SetFromErrno(PyExc_OSError);
	}

	umask(saved_umask);

	TALLOC_FREE(frame);

	Py_RETURN_NONE;
}

/*
  unlink a file
 */
static PyObject *py_smbd_unlink(PyObject *self, PyObject *args, PyObject *kwargs)
{
	const char * const kwnames[] = { "fname", "service", NULL };
	connection_struct *conn;
	int ret;
	struct smb_filename *smb_fname = NULL;
	char *fname, *service = NULL;
	TALLOC_CTX *frame;

	frame = talloc_stackframe();

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "s|z",
					 discard_const_p(char *, kwnames),
					 &fname, &service)) {
		TALLOC_FREE(frame);
		return NULL;
	}

	conn = get_conn(frame, service);
	if (!conn) {
		TALLOC_FREE(frame);
		return NULL;
	}

	smb_fname = synthetic_smb_fname_split(frame, fname, NULL);
	if (smb_fname == NULL) {
		TALLOC_FREE(frame);
		return PyErr_NoMemory();
	}

	ret = SMB_VFS_UNLINK(conn, smb_fname);
	if (ret != 0) {
		TALLOC_FREE(frame);
		errno = ret;
		return PyErr_SetFromErrno(PyExc_OSError);
	}

	TALLOC_FREE(frame);

	Py_RETURN_NONE;
}

/*
  check if we have ACL support
 */
static PyObject *py_smbd_have_posix_acls(PyObject *self)
{
#ifdef HAVE_POSIX_ACLS
	return PyBool_FromLong(true);
#else
	return PyBool_FromLong(false);
#endif
}

/*
  set the NT ACL on a file
 */
static PyObject *py_smbd_set_nt_acl(PyObject *self, PyObject *args, PyObject *kwargs)
{
	const char * const kwnames[] = { "fname", "security_info_sent", "sd", "service", NULL };
	NTSTATUS status;
	char *fname, *service = NULL;
	int security_info_sent;
	PyObject *py_sd;
	struct security_descriptor *sd;
	connection_struct *conn;
	TALLOC_CTX *frame;

	frame = talloc_stackframe();

	if (!PyArg_ParseTupleAndKeywords(args, kwargs,
					 "siO|z", discard_const_p(char *, kwnames),
					 &fname, &security_info_sent, &py_sd, &service)) {
		TALLOC_FREE(frame);
		return NULL;
	}

	if (!py_check_dcerpc_type(py_sd, "samba.dcerpc.security", "descriptor")) {
		TALLOC_FREE(frame);
		return NULL;
	}

	conn = get_conn(frame, service);
	if (!conn) {
		TALLOC_FREE(frame);
		return NULL;
	}

	sd = pytalloc_get_type(py_sd, struct security_descriptor);

	status = set_nt_acl_conn(fname, security_info_sent, sd, conn);
	TALLOC_FREE(frame);
	PyErr_NTSTATUS_IS_ERR_RAISE(status);

	Py_RETURN_NONE;
}

/*
  Return the NT ACL on a file
 */
static PyObject *py_smbd_get_nt_acl(PyObject *self, PyObject *args, PyObject *kwargs)
{
	const char * const kwnames[] = { "fname", "security_info_wanted", "service", NULL };
	char *fname, *service = NULL;
	int security_info_wanted;
	PyObject *py_sd;
	struct security_descriptor *sd;
	TALLOC_CTX *tmp_ctx = talloc_new(NULL);
	connection_struct *conn;
	NTSTATUS status;

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "si|z", discard_const_p(char *, kwnames),
					 &fname, &security_info_wanted, &service)) {
		TALLOC_FREE(tmp_ctx);
		return NULL;
	}

	conn = get_conn(tmp_ctx, service);
	if (!conn) {
		TALLOC_FREE(tmp_ctx);
		return NULL;
	}

	status = get_nt_acl_conn(tmp_ctx, fname, conn, security_info_wanted, &sd);
	PyErr_NTSTATUS_IS_ERR_RAISE(status);

	py_sd = py_return_ndr_struct("samba.dcerpc.security", "descriptor", sd, sd);

	TALLOC_FREE(tmp_ctx);

	return py_sd;
}

/*
  set the posix (or similar) ACL on a file
 */
static PyObject *py_smbd_set_sys_acl(PyObject *self, PyObject *args, PyObject *kwargs)
{
	const char * const kwnames[] = { "fname", "acl_type", "acl", "service", NULL };
	TALLOC_CTX *frame = talloc_stackframe();
	int ret;
	char *fname, *service = NULL;
	PyObject *py_acl;
	struct smb_acl_t *acl;
	int acl_type;
	connection_struct *conn;

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "siO|z",
					 discard_const_p(char *, kwnames),
					 &fname, &acl_type, &py_acl, &service)) {
		TALLOC_FREE(frame);
		return NULL;
	}

	if (!py_check_dcerpc_type(py_acl, "samba.dcerpc.smb_acl", "t")) {
		TALLOC_FREE(frame);
		return NULL;
	}

	conn = get_conn(frame, service);
	if (!conn) {
		TALLOC_FREE(frame);
		return NULL;
	}

	acl = pytalloc_get_type(py_acl, struct smb_acl_t);

	ret = set_sys_acl_conn(fname, acl_type, acl, conn);
	if (ret != 0) {
		TALLOC_FREE(frame);
		errno = ret;
		return PyErr_SetFromErrno(PyExc_OSError);
	}

	TALLOC_FREE(frame);
	Py_RETURN_NONE;
}

/*
  Return the posix (or similar) ACL on a file
 */
static PyObject *py_smbd_get_sys_acl(PyObject *self, PyObject *args, PyObject *kwargs)
{
	const char * const kwnames[] = { "fname", "acl_type", "service", NULL };
	char *fname;
	PyObject *py_acl;
	struct smb_acl_t *acl;
	int acl_type;
	TALLOC_CTX *frame = talloc_stackframe();
	TALLOC_CTX *tmp_ctx = talloc_new(NULL);
	connection_struct *conn;
	char *service = NULL;
	if (!tmp_ctx) {
		PyErr_NoMemory();
		return NULL;
	}

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "si|z",
					 discard_const_p(char *, kwnames),
					 &fname, &acl_type, &service)) {
		TALLOC_FREE(frame);
		TALLOC_FREE(tmp_ctx);
		return NULL;
	}

	conn = get_conn(frame, service);
	if (!conn) {
		TALLOC_FREE(frame);
		TALLOC_FREE(tmp_ctx);
		return NULL;
	}

	acl = SMB_VFS_SYS_ACL_GET_FILE( conn, fname, acl_type, tmp_ctx);
	if (!acl) {
		TALLOC_FREE(frame);
		TALLOC_FREE(tmp_ctx);
		return PyErr_SetFromErrno(PyExc_OSError);
	}

	py_acl = py_return_ndr_struct("samba.dcerpc.smb_acl", "t", acl, acl);

	TALLOC_FREE(frame);
	TALLOC_FREE(tmp_ctx);

	return py_acl;
}

static PyMethodDef py_smbd_methods[] = {
	{ "have_posix_acls",
		(PyCFunction)py_smbd_have_posix_acls, METH_NOARGS,
		NULL },
	{ "set_simple_acl",
		(PyCFunction)py_smbd_set_simple_acl, METH_VARARGS|METH_KEYWORDS,
		NULL },
	{ "set_nt_acl",
		(PyCFunction)py_smbd_set_nt_acl, METH_VARARGS|METH_KEYWORDS,
		NULL },
	{ "get_nt_acl",
		(PyCFunction)py_smbd_get_nt_acl, METH_VARARGS|METH_KEYWORDS,
		NULL },
	{ "get_sys_acl",
		(PyCFunction)py_smbd_get_sys_acl, METH_VARARGS|METH_KEYWORDS,
		NULL },
	{ "set_sys_acl",
		(PyCFunction)py_smbd_set_sys_acl, METH_VARARGS|METH_KEYWORDS,
		NULL },
	{ "chown",
		(PyCFunction)py_smbd_chown, METH_VARARGS|METH_KEYWORDS,
		NULL },
	{ "unlink",
		(PyCFunction)py_smbd_unlink, METH_VARARGS|METH_KEYWORDS,
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
