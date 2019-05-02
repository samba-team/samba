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

#include <Python.h>
#include "includes.h"
#include "python/py3compat.h"
#include "python/modules.h"
#include "smbd/smbd.h"
#include "libcli/util/pyerrors.h"
#include "librpc/rpc/pyrpc_util.h"
#include <pytalloc.h>
#include "system/filesys.h"
#include "passdb.h"
#include "secrets.h"
#include "auth.h"

extern const struct generic_mapping file_generic_mapping;

#undef  DBGC_CLASS
#define DBGC_CLASS DBGC_ACLS

#ifdef O_DIRECTORY
#define DIRECTORY_FLAGS O_RDONLY|O_DIRECTORY
#else
/* POSIX allows us to open a directory with O_RDONLY. */
#define DIRECTORY_FLAGS O_RDONLY
#endif


static connection_struct *get_conn_tos(
	const char *service,
	const struct auth_session_info *session_info)
{
	struct conn_struct_tos *c = NULL;
	int snum = -1;
	NTSTATUS status;

	if (!posix_locking_init(false)) {
		PyErr_NoMemory();
		return NULL;
	}

	if (service) {
		snum = lp_servicenumber(service);
		if (snum == -1) {
			PyErr_SetString(PyExc_RuntimeError, "unknown service");
			return NULL;
		}
	}

	status = create_conn_struct_tos(NULL,
					snum,
					"/",
					session_info,
					&c);
	PyErr_NTSTATUS_IS_ERR_RAISE(status);

	/* Ignore read-only and share restrictions */
	c->conn->read_only = false;
	c->conn->share_access = SEC_RIGHTS_FILE_ALL;
	return c->conn;
}

static int set_sys_acl_conn(const char *fname,
				 SMB_ACL_TYPE_T acltype,
				 SMB_ACL_T theacl, connection_struct *conn)
{
	int ret;
	struct smb_filename *smb_fname = NULL;

	TALLOC_CTX *frame = talloc_stackframe();

	smb_fname = synthetic_smb_fname_split(frame,
					fname,
					lp_posix_pathnames());
	if (smb_fname == NULL) {
		TALLOC_FREE(frame);
		return -1;
	}

	ret = SMB_VFS_SYS_ACL_SET_FILE( conn, smb_fname, acltype, theacl);

	TALLOC_FREE(frame);
	return ret;
}


static NTSTATUS init_files_struct(TALLOC_CTX *mem_ctx,
				  const char *fname,
				  struct connection_struct *conn,
				  int flags,
				  struct files_struct **_fsp)
{
	struct smb_filename *smb_fname = NULL;
	int ret;
	mode_t saved_umask;
	struct files_struct *fsp;

	fsp = talloc_zero(mem_ctx, struct files_struct);
	if (fsp == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	fsp->fh = talloc(fsp, struct fd_handle);
	if (fsp->fh == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	fsp->conn = conn;

	smb_fname = synthetic_smb_fname_split(fsp,
					      fname,
					      lp_posix_pathnames());
	if (smb_fname == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	fsp->fsp_name = smb_fname;

	/*
	 * we want total control over the permissions on created files,
	 * so set our umask to 0 (this matters if flags contains O_CREAT)
	 */
	saved_umask = umask(0);

	fsp->fh->fd = SMB_VFS_OPEN(conn, smb_fname, fsp, flags, 00644);

	umask(saved_umask);

	if (fsp->fh->fd == -1) {
		int err = errno;
		if (err == ENOENT) {
			return NT_STATUS_OBJECT_NAME_NOT_FOUND;
		}
		return NT_STATUS_INVALID_PARAMETER;
	}

	ret = SMB_VFS_FSTAT(fsp, &smb_fname->st);
	if (ret == -1) {
		/* If we have an fd, this stat should succeed. */
		DEBUG(0,("Error doing fstat on open file %s (%s)\n",
			 smb_fname_str_dbg(smb_fname),
			 strerror(errno) ));
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

	*_fsp = fsp;

	return NT_STATUS_OK;
}

static NTSTATUS set_nt_acl_conn(const char *fname,
				uint32_t security_info_sent, const struct security_descriptor *sd,
				connection_struct *conn)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct files_struct *fsp = NULL;
	NTSTATUS status = NT_STATUS_OK;

	/* first, try to open it as a file with flag O_RDWR */
	status = init_files_struct(frame,
				   fname,
				   conn,
				   O_RDWR,
				   &fsp);
	if (!NT_STATUS_IS_OK(status) && errno == EISDIR) {
		/* if fail, try to open as dir */
		status = init_files_struct(frame,
					   fname,
					   conn,
					   DIRECTORY_FLAGS,
					   &fsp);
	}

	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("init_files_struct failed: %s\n",
			nt_errstr(status));
		if (fsp != NULL) {
			SMB_VFS_CLOSE(fsp);
		}
		TALLOC_FREE(frame);
		return status;
	}

	status = SMB_VFS_FSET_NT_ACL(fsp, security_info_sent, sd);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0,("set_nt_acl_no_snum: fset_nt_acl returned %s.\n", nt_errstr(status)));
	}

	SMB_VFS_CLOSE(fsp);

	TALLOC_FREE(frame);
	return status;
}

static NTSTATUS get_nt_acl_conn(TALLOC_CTX *mem_ctx,
				const char *fname,
				connection_struct *conn,
				uint32_t security_info_wanted,
				struct security_descriptor **sd)
{
	TALLOC_CTX *frame = talloc_stackframe();
	NTSTATUS status;
	struct smb_filename *smb_fname = synthetic_smb_fname(talloc_tos(),
					fname,
					NULL,
					NULL,
					lp_posix_pathnames() ?
						SMB_FILENAME_POSIX_PATH : 0);

	if (smb_fname == NULL) {
		TALLOC_FREE(frame);
		return NT_STATUS_NO_MEMORY;
	}

	status = SMB_VFS_GET_NT_ACL(conn,
				smb_fname,
				security_info_wanted,
				mem_ctx,
				sd);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0,("get_nt_acl_conn: get_nt_acl returned %s.\n", nt_errstr(status)));
	}

	TALLOC_FREE(frame);

	return status;
}

static int set_acl_entry_perms(SMB_ACL_ENTRY_T entry, mode_t perm_mask)
{
	SMB_ACL_PERMSET_T perms = NULL;

	if (sys_acl_get_permset(entry, &perms) != 0) {
		return -1;
	}

	if (sys_acl_clear_perms(perms) != 0) {
		return -1;
	}

	if ((perm_mask & SMB_ACL_READ) != 0 &&
	    sys_acl_add_perm(perms, SMB_ACL_READ) != 0) {
		return -1;
	}

	if ((perm_mask & SMB_ACL_WRITE) != 0 &&
	    sys_acl_add_perm(perms, SMB_ACL_WRITE) != 0) {
		return -1;
	}

	if ((perm_mask & SMB_ACL_EXECUTE) != 0 &&
	    sys_acl_add_perm(perms, SMB_ACL_EXECUTE) != 0) {
		return -1;
	}

	if (sys_acl_set_permset(entry, perms) != 0) {
		return -1;
	}

	return 0;
}

static SMB_ACL_T make_simple_acl(TALLOC_CTX *mem_ctx,
			gid_t gid,
			mode_t chmod_mode)
{
	mode_t mode = SMB_ACL_READ|SMB_ACL_WRITE|SMB_ACL_EXECUTE;

	mode_t mode_user = (chmod_mode & 0700) >> 6;
	mode_t mode_group = (chmod_mode & 070) >> 3;
	mode_t mode_other = chmod_mode &  07;
	SMB_ACL_ENTRY_T entry;
	SMB_ACL_T acl = sys_acl_init(mem_ctx);

	if (!acl) {
		return NULL;
	}

	if (sys_acl_create_entry(&acl, &entry) != 0) {
		TALLOC_FREE(acl);
		return NULL;
	}

	if (sys_acl_set_tag_type(entry, SMB_ACL_USER_OBJ) != 0) {
		TALLOC_FREE(acl);
		return NULL;
	}

	if (set_acl_entry_perms(entry, mode_user) != 0) {
		TALLOC_FREE(acl);
		return NULL;
	}

	if (sys_acl_create_entry(&acl, &entry) != 0) {
		TALLOC_FREE(acl);
		return NULL;
	}

	if (sys_acl_set_tag_type(entry, SMB_ACL_GROUP_OBJ) != 0) {
		TALLOC_FREE(acl);
		return NULL;
	}

	if (set_acl_entry_perms(entry, mode_group) != 0) {
		TALLOC_FREE(acl);
		return NULL;
	}

	if (sys_acl_create_entry(&acl, &entry) != 0) {
		TALLOC_FREE(acl);
		return NULL;
	}

	if (sys_acl_set_tag_type(entry, SMB_ACL_OTHER) != 0) {
		TALLOC_FREE(acl);
		return NULL;
	}

	if (set_acl_entry_perms(entry, mode_other) != 0) {
		TALLOC_FREE(acl);
		return NULL;
	}

	if (gid != -1) {
		if (sys_acl_create_entry(&acl, &entry) != 0) {
			TALLOC_FREE(acl);
			return NULL;
		}

		if (sys_acl_set_tag_type(entry, SMB_ACL_GROUP) != 0) {
			TALLOC_FREE(acl);
			return NULL;
		}

		if (sys_acl_set_qualifier(entry, &gid) != 0) {
			TALLOC_FREE(acl);
			return NULL;
		}

		if (set_acl_entry_perms(entry, mode_group) != 0) {
			TALLOC_FREE(acl);
			return NULL;
		}
	}

	if (sys_acl_create_entry(&acl, &entry) != 0) {
		TALLOC_FREE(acl);
		return NULL;
	}

	if (sys_acl_set_tag_type(entry, SMB_ACL_MASK) != 0) {
		TALLOC_FREE(acl);
		return NULL;
	}

	if (set_acl_entry_perms(entry, mode) != 0) {
		TALLOC_FREE(acl);
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

	frame = talloc_stackframe();

	acl = make_simple_acl(frame, gid, mode);
	if (acl == NULL) {
		TALLOC_FREE(frame);
		return NULL;
	}

	conn = get_conn_tos(service, NULL);
	if (!conn) {
		TALLOC_FREE(frame);
		return NULL;
	}

	ret = set_sys_acl_conn(fname, SMB_ACL_TYPE_ACCESS, acl, conn);

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
	struct smb_filename *smb_fname = NULL;

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "sii|z",
					 discard_const_p(char *, kwnames),
					 &fname, &uid, &gid, &service))
		return NULL;

	frame = talloc_stackframe();

	conn = get_conn_tos(service, NULL);
	if (!conn) {
		TALLOC_FREE(frame);
		return NULL;
	}

	smb_fname = synthetic_smb_fname(talloc_tos(),
					fname,
					NULL,
					NULL,
					lp_posix_pathnames() ?
						SMB_FILENAME_POSIX_PATH : 0);
	if (smb_fname == NULL) {
		TALLOC_FREE(frame);
		errno = ENOMEM;
		return PyErr_SetFromErrno(PyExc_OSError);
	}

	ret = SMB_VFS_CHOWN(conn, smb_fname, uid, gid);
	if (ret != 0) {
		TALLOC_FREE(frame);
		errno = ret;
		return PyErr_SetFromErrno(PyExc_OSError);
	}

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

	conn = get_conn_tos(service, NULL);
	if (!conn) {
		TALLOC_FREE(frame);
		return NULL;
	}

	smb_fname = synthetic_smb_fname_split(frame,
					fname,
					lp_posix_pathnames());
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
static PyObject *py_smbd_have_posix_acls(PyObject *self,
		PyObject *Py_UNUSED(ignored))
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
	const char * const kwnames[] = {
		"fname", "security_info_sent", "sd",
		"service", "session_info", NULL };

	NTSTATUS status;
	char *fname, *service = NULL;
	int security_info_sent;
	PyObject *py_sd;
	struct security_descriptor *sd;
	PyObject *py_session = Py_None;
	struct auth_session_info *session_info = NULL;
	connection_struct *conn;
	TALLOC_CTX *frame;

	frame = talloc_stackframe();

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "siO|zO",
				         discard_const_p(char *, kwnames),
					 &fname, &security_info_sent, &py_sd,
					 &service, &py_session)) {
		TALLOC_FREE(frame);
		return NULL;
	}

	if (!py_check_dcerpc_type(py_sd, "samba.dcerpc.security", "descriptor")) {
		TALLOC_FREE(frame);
		return NULL;
	}

	if (py_session != Py_None) {
		if (!py_check_dcerpc_type(py_session,
					  "samba.dcerpc.auth",
					  "session_info")) {
			TALLOC_FREE(frame);
			return NULL;
		}
		session_info = pytalloc_get_type(py_session,
						 struct auth_session_info);
		if (!session_info) {
			PyErr_Format(PyExc_TypeError,
				     "Expected auth_session_info for session_info argument got %s",
				     talloc_get_name(pytalloc_get_ptr(py_session)));
			return NULL;
		}
	}

	conn = get_conn_tos(service, session_info);
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
	const char * const kwnames[] = { "fname",
					 "security_info_wanted",
					 "service",
					 "session_info",
					 NULL };
	char *fname, *service = NULL;
	int security_info_wanted;
	PyObject *py_sd;
	struct security_descriptor *sd;
	TALLOC_CTX *frame = talloc_stackframe();
	PyObject *py_session = Py_None;
	struct auth_session_info *session_info = NULL;
	connection_struct *conn;
	NTSTATUS status;
	int ret = 1;

	ret = PyArg_ParseTupleAndKeywords(args,
					  kwargs,
					  "si|zO",
					  discard_const_p(char *, kwnames),
					  &fname,
					  &security_info_wanted,
					  &service,
					  &py_session);
	if (!ret) {
		TALLOC_FREE(frame);
		return NULL;
	}

	if (py_session != Py_None) {
		if (!py_check_dcerpc_type(py_session,
					  "samba.dcerpc.auth",
					  "session_info")) {
			TALLOC_FREE(frame);
			return NULL;
		}
		session_info = pytalloc_get_type(py_session,
						 struct auth_session_info);
		if (!session_info) {
			PyErr_Format(
				PyExc_TypeError,
				"Expected auth_session_info for "
				"session_info argument got %s",
				talloc_get_name(pytalloc_get_ptr(py_session)));
			return NULL;
		}
	}

	conn = get_conn_tos(service, session_info);
	if (!conn) {
		TALLOC_FREE(frame);
		return NULL;
	}

	status = get_nt_acl_conn(frame, fname, conn, security_info_wanted, &sd);
	PyErr_NTSTATUS_IS_ERR_RAISE(status);

	py_sd = py_return_ndr_struct("samba.dcerpc.security", "descriptor", sd, sd);

	TALLOC_FREE(frame);

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

	conn = get_conn_tos(service, NULL);
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
	connection_struct *conn;
	char *service = NULL;
	struct smb_filename *smb_fname = NULL;

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "si|z",
					 discard_const_p(char *, kwnames),
					 &fname, &acl_type, &service)) {
		TALLOC_FREE(frame);
		return NULL;
	}

	conn = get_conn_tos(service, NULL);
	if (!conn) {
		TALLOC_FREE(frame);
		return NULL;
	}

	smb_fname = synthetic_smb_fname_split(frame,
					fname,
					lp_posix_pathnames());
	if (smb_fname == NULL) {
		TALLOC_FREE(frame);
		return NULL;
	}
	acl = SMB_VFS_SYS_ACL_GET_FILE( conn, smb_fname, acl_type, frame);
	if (!acl) {
		TALLOC_FREE(frame);
		return PyErr_SetFromErrno(PyExc_OSError);
	}

	py_acl = py_return_ndr_struct("samba.dcerpc.smb_acl", "t", acl, acl);

	TALLOC_FREE(frame);

	return py_acl;
}

static PyObject *py_smbd_mkdir(PyObject *self, PyObject *args, PyObject *kwargs)
{
	const char * const kwnames[] = { "fname", "service", NULL };
	char *fname, *service = NULL;
	TALLOC_CTX *frame = talloc_stackframe();
	struct connection_struct *conn = NULL;
	struct smb_filename *smb_fname = NULL;
	int ret;
	mode_t saved_umask;

	if (!PyArg_ParseTupleAndKeywords(args,
					 kwargs,
					 "s|z",
					 discard_const_p(char *,
							 kwnames),
					 &fname,
					 &service)) {
		TALLOC_FREE(frame);
		return NULL;
	}

	conn = get_conn_tos(service, NULL);
	if (!conn) {
		TALLOC_FREE(frame);
		return NULL;
	}

	smb_fname = synthetic_smb_fname(talloc_tos(),
					fname,
					NULL,
					NULL,
					lp_posix_pathnames() ?
					SMB_FILENAME_POSIX_PATH : 0);

	if (smb_fname == NULL) {
		TALLOC_FREE(frame);
		return NULL;
	}

	/* we want total control over the permissions on created files,
	   so set our umask to 0 */
	saved_umask = umask(0);

	ret = SMB_VFS_MKDIR(conn, smb_fname, 00755);

	umask(saved_umask);

	if (ret == -1) {
		DBG_ERR("mkdir error=%d (%s)\n", errno, strerror(errno));
		TALLOC_FREE(frame);
		return NULL;
	}

	TALLOC_FREE(frame);
	Py_RETURN_NONE;
}


/*
  Create an empty file
 */
static PyObject *py_smbd_create_file(PyObject *self, PyObject *args, PyObject *kwargs)
{
	const char * const kwnames[] = { "fname", "service", NULL };
	char *fname, *service = NULL;
	TALLOC_CTX *frame = talloc_stackframe();
	struct connection_struct *conn = NULL;
	struct files_struct *fsp = NULL;
	NTSTATUS status;

	if (!PyArg_ParseTupleAndKeywords(args,
					 kwargs,
					 "s|z",
					 discard_const_p(char *,
							 kwnames),
					 &fname,
					 &service)) {
		TALLOC_FREE(frame);
		return NULL;
	}

	conn = get_conn_tos(service, NULL);
	if (!conn) {
		TALLOC_FREE(frame);
		return NULL;
	}

	status = init_files_struct(frame,
				   fname,
				   conn,
				   O_CREAT|O_EXCL|O_RDWR,
				   &fsp);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("init_files_struct failed: %s\n",
			nt_errstr(status));
	}

	TALLOC_FREE(frame);
	Py_RETURN_NONE;
}


static PyMethodDef py_smbd_methods[] = {
	{ "have_posix_acls",
		(PyCFunction)py_smbd_have_posix_acls, METH_NOARGS,
		NULL },
	{ "set_simple_acl",
		PY_DISCARD_FUNC_SIG(PyCFunction, py_smbd_set_simple_acl),
		METH_VARARGS|METH_KEYWORDS,
		NULL },
	{ "set_nt_acl",
		PY_DISCARD_FUNC_SIG(PyCFunction, py_smbd_set_nt_acl),
		METH_VARARGS|METH_KEYWORDS,
		NULL },
	{ "get_nt_acl",
		PY_DISCARD_FUNC_SIG(PyCFunction, py_smbd_get_nt_acl),
		METH_VARARGS|METH_KEYWORDS,
		NULL },
	{ "get_sys_acl",
		PY_DISCARD_FUNC_SIG(PyCFunction, py_smbd_get_sys_acl),
		METH_VARARGS|METH_KEYWORDS,
		NULL },
	{ "set_sys_acl",
		PY_DISCARD_FUNC_SIG(PyCFunction, py_smbd_set_sys_acl),
		METH_VARARGS|METH_KEYWORDS,
		NULL },
	{ "chown",
		PY_DISCARD_FUNC_SIG(PyCFunction, py_smbd_chown),
		METH_VARARGS|METH_KEYWORDS,
		NULL },
	{ "unlink",
		PY_DISCARD_FUNC_SIG(PyCFunction, py_smbd_unlink),
		METH_VARARGS|METH_KEYWORDS,
		NULL },
	{ "mkdir",
		PY_DISCARD_FUNC_SIG(PyCFunction, py_smbd_mkdir),
		METH_VARARGS|METH_KEYWORDS,
		NULL },
	{ "create_file",
		PY_DISCARD_FUNC_SIG(PyCFunction, py_smbd_create_file),
		METH_VARARGS|METH_KEYWORDS,
		NULL },
	{ NULL }
};

void initsmbd(void);

static struct PyModuleDef moduledef = {
    PyModuleDef_HEAD_INIT,
    .m_name = "smbd",
    .m_doc = "Python bindings for the smbd file server.",
    .m_size = -1,
    .m_methods = py_smbd_methods,
};

MODULE_INIT_FUNC(smbd)
{
	PyObject *m = NULL;

	m = PyModule_Create(&moduledef);
	return m;
}
