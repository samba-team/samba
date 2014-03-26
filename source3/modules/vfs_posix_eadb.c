/*
 * Store posix-level xattrs in a tdb (posix:eadb format)
 *
 * Copyright (C) Andrew Bartlett, 2011
 *
 * Based on vfs_xattr_tdb by
 * Copyright (C) Volker Lendecke, 2007
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include "includes.h"
#include "system/filesys.h"
#include "smbd/smbd.h"
#include "librpc/gen_ndr/xattr.h"
#include "librpc/gen_ndr/ndr_xattr.h"
#include "../librpc/gen_ndr/ndr_netlogon.h"
#include "tdb_compat.h"
#include "lib/tdb_wrap/tdb_wrap.h"
#include "ntvfs/posix/posix_eadb.h"
#include "param/param.h"
#include "lib/param/loadparm.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_VFS

/*
 * Worker routine for getxattr and fgetxattr
 */

static ssize_t posix_eadb_getattr(struct tdb_wrap *db_ctx,
				 const char *fname, int fd,
				 const char *name, void *value, size_t size)
{
	ssize_t result = -1;
	NTSTATUS status;
	DATA_BLOB blob;

	DEBUG(10, ("posix_eadb_getattr called for file %s/fd %d, name %s\n",
		   fname, fd, name));

	status = pull_xattr_blob_tdb_raw(db_ctx, talloc_tos(), name, fname, fd, size, &blob);

	if (NT_STATUS_EQUAL(status, NT_STATUS_NOT_FOUND)) {
		errno = ENOATTR;
		return -1;
	}

	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(10, ("posix_eadb_fetch_attrs failed: %s\n",
			   nt_errstr(status)));
		errno = EINVAL;
		return -1;
	}

	if (blob.length > size) {
		errno = ERANGE;
		goto fail;
	}

	memcpy(value, blob.data, blob.length);
	result = blob.length;

 fail:
	return result;
}

static ssize_t posix_eadb_getxattr(struct vfs_handle_struct *handle,
				  const char *path, const char *name,
				  void *value, size_t size)
{
	struct tdb_wrap *db;

	SMB_VFS_HANDLE_GET_DATA(handle, db, struct tdb_wrap, return -1);

	return posix_eadb_getattr(db, path, -1, name, value, size);
}

static ssize_t posix_eadb_fgetxattr(struct vfs_handle_struct *handle,
				   struct files_struct *fsp,
				   const char *name, void *value, size_t size)
{
	struct tdb_wrap *db;

	SMB_VFS_HANDLE_GET_DATA(handle, db, struct tdb_wrap, return -1);

	return posix_eadb_getattr(db, fsp->fsp_name->base_name, fsp->fh->fd, name, value, size);
}

/*
 * Worker routine for setxattr and fsetxattr
 */

static int posix_eadb_setattr(struct tdb_wrap *db_ctx,
			     const char *fname, int fd, const char *name,
			     const void *value, size_t size, int flags)
{
	NTSTATUS status;
	DATA_BLOB data = data_blob_const(value, size);

	DEBUG(10, ("posix_eadb_setattr called for file %s/fd %d, name %s\n",
		   fname, fd, name));

	status = push_xattr_blob_tdb_raw(db_ctx, name, fname, fd, &data);

	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(10, ("push_xattr_blob_tdb_raw failed: %s\n",
			   nt_errstr(status)));
		return -1;
	}

	return 0;
}

static int posix_eadb_setxattr(struct vfs_handle_struct *handle,
			      const char *path, const char *name,
			      const void *value, size_t size, int flags)
{
	struct tdb_wrap *db;

	SMB_VFS_HANDLE_GET_DATA(handle, db, struct tdb_wrap, return -1);

	return posix_eadb_setattr(db, path, -1, name, value, size, flags);
}

static int posix_eadb_fsetxattr(struct vfs_handle_struct *handle,
			       struct files_struct *fsp,
			       const char *name, const void *value,
			       size_t size, int flags)
{
	struct tdb_wrap *db;

	SMB_VFS_HANDLE_GET_DATA(handle, db, struct tdb_wrap, return -1);

	return posix_eadb_setattr(db, fsp->fsp_name->base_name, fsp->fh->fd, name, value, size, flags);
}

/*
 * Worker routine for listxattr and flistxattr
 */

static ssize_t posix_eadb_listattr(struct tdb_wrap *db_ctx,
				  const char *fname, int fd, char *list,
				  size_t size)
{
	DATA_BLOB blob;
	NTSTATUS status;

	status = list_posix_eadb_raw(db_ctx, talloc_tos(), fname, fd, &blob);

	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(10, ("posix_eadb_fetch_attrs failed: %s\n",
			   nt_errstr(status)));
		errno = EINVAL;
		return -1;
	}

	if (blob.length > size) {
		errno = ERANGE;
		TALLOC_FREE(blob.data);
		return -1;
	}

	memcpy(list, blob.data, blob.length);

	TALLOC_FREE(blob.data);
	return blob.length;
}

static ssize_t posix_eadb_listxattr(struct vfs_handle_struct *handle,
				   const char *path, char *list, size_t size)
{
	struct tdb_wrap *db;

	SMB_VFS_HANDLE_GET_DATA(handle, db, struct tdb_wrap, return -1);

	return posix_eadb_listattr(db, path, -1, list, size);
}

static ssize_t posix_eadb_flistxattr(struct vfs_handle_struct *handle,
				    struct files_struct *fsp, char *list,
				    size_t size)
{
	struct tdb_wrap *db;

	SMB_VFS_HANDLE_GET_DATA(handle, db, struct tdb_wrap, return -1);

	return posix_eadb_listattr(db, fsp->fsp_name->base_name, fsp->fh->fd, list, size);
}

/*
 * Worker routine for removexattr and fremovexattr
 */

static int posix_eadb_removeattr(struct tdb_wrap *db_ctx,
				const char *fname, int fd, const char *name)
{
	NTSTATUS status;

	status = delete_posix_eadb_raw(db_ctx, name, fname, fd);

	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(10, ("delete_posix_eadb_raw failed: %s\n",
			   nt_errstr(status)));
		return -1;
	}
	return 0;
}

static int posix_eadb_removexattr(struct vfs_handle_struct *handle,
				 const char *path, const char *name)
{
	struct tdb_wrap *db;

	SMB_VFS_HANDLE_GET_DATA(handle, db, struct tdb_wrap, return -1);

	return posix_eadb_removeattr(db, path, -1, name);
}

static int posix_eadb_fremovexattr(struct vfs_handle_struct *handle,
				  struct files_struct *fsp, const char *name)
{
	struct tdb_wrap *db;

	SMB_VFS_HANDLE_GET_DATA(handle, db, struct tdb_wrap, return -1);

	return posix_eadb_removeattr(db, fsp->fsp_name->base_name, fsp->fh->fd, name);
}

/*
 * Open the tdb file upon VFS_CONNECT
 */

static bool posix_eadb_init(int snum, struct tdb_wrap **p_db)
{
	struct tdb_wrap *db;
	struct loadparm_context *lp_ctx;
	const char *eadb = lp_parm_const_string(snum, "posix", "eadb", NULL);

	if (!eadb) {
		DEBUG(0, ("Can not use vfs_posix_eadb without posix:eadb set\n"));
		return false;
	}

	lp_ctx = loadparm_init_s3(NULL, loadparm_s3_helpers());

	become_root();
	db = tdb_wrap_open(NULL, eadb, 50000,
			   lpcfg_tdb_flags(lp_ctx, TDB_DEFAULT),
			   O_RDWR|O_CREAT, 0600);

	unbecome_root();
	talloc_unlink(NULL, lp_ctx);
	/* now we know dbname is not NULL */

	if (db == NULL) {
#if defined(ENOTSUP)
		errno = ENOTSUP;
#else
		errno = ENOSYS;
#endif
		return false;
	}

	*p_db = db;
	return true;
}

/*
 * On unlink we need to delete the tdb record
 */
static int posix_eadb_unlink(vfs_handle_struct *handle,
			    const struct smb_filename *smb_fname)
{
	struct smb_filename *smb_fname_tmp = NULL;
	int ret = -1;

	struct tdb_wrap *ea_tdb;

	SMB_VFS_HANDLE_GET_DATA(handle, ea_tdb, struct tdb_wrap, return -1);

	smb_fname_tmp = cp_smb_filename(talloc_tos(), smb_fname);
	if (smb_fname_tmp == NULL) {
		errno = ENOMEM;
		return -1;
	}

	if (lp_posix_pathnames()) {
		ret = SMB_VFS_NEXT_LSTAT(handle, smb_fname_tmp);
	} else {
		ret = SMB_VFS_NEXT_STAT(handle, smb_fname_tmp);
	}
	if (ret == -1) {
		goto out;
	}

	if (smb_fname_tmp->st.st_ex_nlink == 1) {
		NTSTATUS status;

		/* Only remove record on last link to file. */

		if (tdb_transaction_start(ea_tdb->tdb) != 0) {
			ret = -1;
			goto out;
		}

		status = unlink_posix_eadb_raw(ea_tdb, smb_fname->base_name, -1);
		if (!NT_STATUS_IS_OK(status)) {
			tdb_transaction_cancel(ea_tdb->tdb);
			ret = -1;
			goto out;
		}
	}

	ret = SMB_VFS_NEXT_UNLINK(handle, smb_fname_tmp);

	if (ret == -1) {
		tdb_transaction_cancel(ea_tdb->tdb);
		goto out;
	} else {
		if (tdb_transaction_commit(ea_tdb->tdb) != 0) {
			ret = -1;
			goto out;
		}
	}

out:
	TALLOC_FREE(smb_fname_tmp);
	return ret;
}

/*
 * On rmdir we need to delete the tdb record
 */
static int posix_eadb_rmdir(vfs_handle_struct *handle, const char *path)
{
	NTSTATUS status;
	struct tdb_wrap *ea_tdb;
	int ret;

	SMB_VFS_HANDLE_GET_DATA(handle, ea_tdb, struct tdb_wrap, return -1);

	if (tdb_transaction_start(ea_tdb->tdb) != 0) {
		return -1;
	}

	status = unlink_posix_eadb_raw(ea_tdb, path, -1);
	if (!NT_STATUS_IS_OK(status)) {
		tdb_transaction_cancel(ea_tdb->tdb);
	}

	ret = SMB_VFS_NEXT_RMDIR(handle, path);

	if (ret == -1) {
		tdb_transaction_cancel(ea_tdb->tdb);
	} else {
		if (tdb_transaction_commit(ea_tdb->tdb) != 0) {
			return -1;
		}
	}

	return ret;
}

/*
 * Destructor for the VFS private data
 */

static void close_xattr_db(void **data)
{
	struct tdb_wrap **p_db = (struct tdb_wrap **)data;
	TALLOC_FREE(*p_db);
}

static int posix_eadb_connect(vfs_handle_struct *handle, const char *service,
			  const char *user)
{
	char *sname = NULL;
	int res, snum;
	struct tdb_wrap *db;

	res = SMB_VFS_NEXT_CONNECT(handle, service, user);
	if (res < 0) {
		return res;
	}

	snum = find_service(talloc_tos(), service, &sname);
	if (snum == -1 || sname == NULL) {
		/*
		 * Should not happen, but we should not fail just *here*.
		 */
		return 0;
	}

	if (!posix_eadb_init(snum, &db)) {
		DEBUG(5, ("Could not init xattr tdb\n"));
		lp_do_parameter(snum, "ea support", "False");
		return 0;
	}

	lp_do_parameter(snum, "ea support", "True");

	SMB_VFS_HANDLE_SET_DATA(handle, db, close_xattr_db,
				struct tdb_wrap, return -1);

	return 0;
}

static struct vfs_fn_pointers vfs_posix_eadb_fns = {
	.getxattr_fn = posix_eadb_getxattr,
	.fgetxattr_fn = posix_eadb_fgetxattr,
	.setxattr_fn = posix_eadb_setxattr,
	.fsetxattr_fn = posix_eadb_fsetxattr,
	.listxattr_fn = posix_eadb_listxattr,
	.flistxattr_fn = posix_eadb_flistxattr,
	.removexattr_fn = posix_eadb_removexattr,
	.fremovexattr_fn = posix_eadb_fremovexattr,
	.unlink_fn = posix_eadb_unlink,
	.rmdir_fn = posix_eadb_rmdir,
	.connect_fn = posix_eadb_connect,
};

NTSTATUS vfs_posix_eadb_init(void);
NTSTATUS vfs_posix_eadb_init(void)
{
	return smb_register_vfs(SMB_VFS_INTERFACE_VERSION, "posix_eadb",
				&vfs_posix_eadb_fns);
}
