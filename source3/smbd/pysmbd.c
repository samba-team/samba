/*
   Unix SMB/CIFS implementation.
   SMB NT Security Descriptor / Unix permission conversion.
   Copyright (C) Jeremy Allison 1994-2009.
   Copyright (C) Andreas Gruenbacher 2002.
   Copyright (C) Simo Sorce <idra@samba.org> 2009.

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
		DEBUG(0,("get_nt_acl_no_snum: fset_nt_acl returned zero.\n"));
	}

	conn_free(conn);

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

	if (!PyArg_ParseTuple(args, "sii", &fname, &uid, &gid))
		return NULL;

	acl = make_simple_acl(uid, gid);

	status = set_sys_acl_no_snum(fname, SMB_ACL_TYPE_ACCESS, acl);
	sys_acl_free_acl(acl);
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

static PyMethodDef py_smbd_methods[] = {
	{ "have_posix_acls",
		(PyCFunction)py_smbd_have_posix_acls, METH_VARARGS,
		NULL },
	{ "set_simple_acl",
		(PyCFunction)py_smbd_set_simple_acl, METH_VARARGS,
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
