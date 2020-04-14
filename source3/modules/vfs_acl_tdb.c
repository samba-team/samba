/*
 * Store Windows ACLs in a tdb.
 *
 * Copyright (C) Volker Lendecke, 2008
 * Copyright (C) Jeremy Allison, 2008
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
#include "smbd/smbd.h"
#include "system/filesys.h"
#include "librpc/gen_ndr/xattr.h"
#include "dbwrap/dbwrap.h"
#include "dbwrap/dbwrap_open.h"
#include "auth.h"
#include "util_tdb.h"
#include "vfs_acl_common.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_VFS

#define ACL_MODULE_NAME "acl_tdb"

static unsigned int ref_count;
static struct db_context *acl_db;

/*******************************************************************
 Open acl_db if not already open, increment ref count.
*******************************************************************/

static bool acl_tdb_init(void)
{
	char *dbname;

	if (acl_db) {
		ref_count++;
		return true;
	}

	dbname = state_path(talloc_tos(), "file_ntacls.tdb");

	if (dbname == NULL) {
		errno = ENOSYS;
		return false;
	}

	become_root();
	acl_db = db_open(NULL, dbname, 0, TDB_DEFAULT, O_RDWR|O_CREAT, 0600,
			 DBWRAP_LOCK_ORDER_1, DBWRAP_FLAG_NONE);
	unbecome_root();

	if (acl_db == NULL) {
#if defined(ENOTSUP)
		errno = ENOTSUP;
#else
		errno = ENOSYS;
#endif
		TALLOC_FREE(dbname);
		return false;
	}

	ref_count++;
	TALLOC_FREE(dbname);
	return true;
}

/*******************************************************************
 Lower ref count and close acl_db if zero.
*******************************************************************/

static void disconnect_acl_tdb(struct vfs_handle_struct *handle)
{
	SMB_VFS_NEXT_DISCONNECT(handle);
	ref_count--;
	if (ref_count == 0) {
		TALLOC_FREE(acl_db);
	}
}

/*******************************************************************
 Delete the tdb acl record for a file
*******************************************************************/

static NTSTATUS acl_tdb_delete(vfs_handle_struct *handle,
				struct db_context *db,
				SMB_STRUCT_STAT *psbuf)
{
	NTSTATUS status;
	struct file_id id = vfs_file_id_from_sbuf(handle->conn, psbuf);
	uint8_t id_buf[16];

	/* For backwards compatibility only store the dev/inode. */
	push_file_id_16((char *)id_buf, &id);

	status = dbwrap_delete(db, make_tdb_data(id_buf, sizeof(id_buf)));
	return status;
}

/*******************************************************************
 Pull a security descriptor from an fsp into a DATA_BLOB from a tdb store.
*******************************************************************/

static NTSTATUS fget_acl_blob(TALLOC_CTX *ctx,
			vfs_handle_struct *handle,
			files_struct *fsp,
			DATA_BLOB *pblob)
{
	uint8_t id_buf[16];
	TDB_DATA data;
	struct file_id id;
	struct db_context *db = acl_db;
	NTSTATUS status = NT_STATUS_OK;

	status = vfs_stat_fsp(fsp);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	id = vfs_file_id_from_sbuf(handle->conn, &fsp->fsp_name->st);

	/* For backwards compatibility only store the dev/inode. */
	push_file_id_16((char *)id_buf, &id);

	status = dbwrap_fetch(db,
			      ctx,
			      make_tdb_data(id_buf, sizeof(id_buf)),
			      &data);
	if (!NT_STATUS_IS_OK(status)) {
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}

	pblob->data = data.dptr;
	pblob->length = data.dsize;

	DBG_DEBUG("returned %u bytes from file %s\n",
		(unsigned int)data.dsize,
		fsp_str_dbg(fsp));

	if (pblob->length == 0 || pblob->data == NULL) {
		return NT_STATUS_NOT_FOUND;
	}
	return NT_STATUS_OK;
}

/*******************************************************************
 Pull a security descriptor into a DATA_BLOB from a tdb store.
*******************************************************************/

static NTSTATUS get_acl_blob_at(TALLOC_CTX *ctx,
			vfs_handle_struct *handle,
			struct files_struct *dirfsp,
			const struct smb_filename *smb_fname,
			DATA_BLOB *pblob)
{
	uint8_t id_buf[16];
	TDB_DATA data;
	struct file_id id;
	struct db_context *db = acl_db;
	NTSTATUS status = NT_STATUS_OK;
	SMB_STRUCT_STAT sbuf;
	int ret;

	ZERO_STRUCT(sbuf);

	ret = vfs_stat_smb_basename(handle->conn,
				smb_fname,
				&sbuf);
	if (ret == -1) {
		status = map_nt_error_from_unix(errno);
	}

	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	id = vfs_file_id_from_sbuf(handle->conn, &sbuf);

	/* For backwards compatibility only store the dev/inode. */
	push_file_id_16((char *)id_buf, &id);

	status = dbwrap_fetch(db,
			      ctx,
			      make_tdb_data(id_buf, sizeof(id_buf)),
			      &data);
	if (!NT_STATUS_IS_OK(status)) {
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}

	pblob->data = data.dptr;
	pblob->length = data.dsize;

	DBG_DEBUG("returned %u bytes from file %s\n",
		(unsigned int)data.dsize, smb_fname->base_name );

	if (pblob->length == 0 || pblob->data == NULL) {
		return NT_STATUS_NOT_FOUND;
	}
	return NT_STATUS_OK;
}

/*******************************************************************
 Store a DATA_BLOB into a tdb record given an fsp pointer.
*******************************************************************/

static NTSTATUS store_acl_blob_fsp(vfs_handle_struct *handle,
				files_struct *fsp,
				DATA_BLOB *pblob)
{
	uint8_t id_buf[16];
	struct file_id id;
	TDB_DATA data = { .dptr = pblob->data, .dsize = pblob->length };
	struct db_context *db = acl_db;
	NTSTATUS status;

	DEBUG(10,("store_acl_blob_fsp: storing blob length %u on file %s\n",
		  (unsigned int)pblob->length, fsp_str_dbg(fsp)));

	status = vfs_stat_fsp(fsp);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	id = vfs_file_id_from_sbuf(handle->conn, &fsp->fsp_name->st);

	/* For backwards compatibility only store the dev/inode. */
	push_file_id_16((char *)id_buf, &id);

	status = dbwrap_store(
		db, make_tdb_data(id_buf, sizeof(id_buf)), data, 0);
	return status;
}

/*********************************************************************
 On unlinkat we need to delete the tdb record (if using tdb).
*********************************************************************/

static int unlinkat_acl_tdb(vfs_handle_struct *handle,
			struct files_struct *dirfsp,
			const struct smb_filename *smb_fname,
			int flags)
{
	struct smb_filename *smb_fname_tmp = NULL;
	struct db_context *db = acl_db;
	int ret = -1;

	smb_fname_tmp = cp_smb_filename_nostream(talloc_tos(), smb_fname);
	if (smb_fname_tmp == NULL) {
		errno = ENOMEM;
		goto out;
	}

	if (smb_fname_tmp->flags & SMB_FILENAME_POSIX_PATH) {
		ret = SMB_VFS_LSTAT(handle->conn, smb_fname_tmp);
	} else {
		ret = SMB_VFS_STAT(handle->conn, smb_fname_tmp);
	}

	if (ret == -1) {
		goto out;
	}

	if (flags & AT_REMOVEDIR) {
		ret = rmdir_acl_common(handle,
				dirfsp,
				smb_fname_tmp);
	} else {
		ret = unlink_acl_common(handle,
				dirfsp,
				smb_fname_tmp,
				flags);
	}

	if (ret == -1) {
		goto out;
	}

	acl_tdb_delete(handle, db, &smb_fname_tmp->st);
 out:
	return ret;
}

/*******************************************************************
 Handle opening the storage tdb if so configured.
*******************************************************************/

static int connect_acl_tdb(struct vfs_handle_struct *handle,
				const char *service,
				const char *user)
{
	int ret = SMB_VFS_NEXT_CONNECT(handle, service, user);
	bool ok;
	struct acl_common_config *config = NULL;

	if (ret < 0) {
		return ret;
	}

	if (!acl_tdb_init()) {
		SMB_VFS_NEXT_DISCONNECT(handle);
		return -1;
	}

	ok = init_acl_common_config(handle, ACL_MODULE_NAME);
	if (!ok) {
		DBG_ERR("init_acl_common_config failed\n");
		return -1;
	}

	/* Ensure we have the parameters correct if we're
	 * using this module. */
	DEBUG(2,("connect_acl_tdb: setting 'inherit acls = true' "
		"'dos filemode = true' and "
		"'force unknown acl user = true' for service %s\n",
		service ));

	lp_do_parameter(SNUM(handle->conn), "inherit acls", "true");
	lp_do_parameter(SNUM(handle->conn), "dos filemode", "true");
	lp_do_parameter(SNUM(handle->conn), "force unknown acl user", "true");

	SMB_VFS_HANDLE_GET_DATA(handle, config,
				struct acl_common_config,
				return -1);

	if (config->ignore_system_acls) {
		mode_t create_mask = lp_create_mask(SNUM(handle->conn));
		char *create_mask_str = NULL;

		if ((create_mask & 0666) != 0666) {
			create_mask |= 0666;
			create_mask_str = talloc_asprintf(handle, "0%o",
							  create_mask);
			if (create_mask_str == NULL) {
				DBG_ERR("talloc_asprintf failed\n");
				return -1;
			}

			DBG_NOTICE("setting 'create mask = %s'\n", create_mask_str);

			lp_do_parameter (SNUM(handle->conn),
					"create mask", create_mask_str);

			TALLOC_FREE(create_mask_str);
		}

		DBG_NOTICE("setting 'directory mask = 0777', "
			   "'store dos attributes = yes' and all "
			   "'map ...' options to 'no'\n");

		lp_do_parameter(SNUM(handle->conn), "directory mask", "0777");
		lp_do_parameter(SNUM(handle->conn), "map archive", "no");
		lp_do_parameter(SNUM(handle->conn), "map hidden", "no");
		lp_do_parameter(SNUM(handle->conn), "map readonly", "no");
		lp_do_parameter(SNUM(handle->conn), "map system", "no");
		lp_do_parameter(SNUM(handle->conn), "store dos attributes",
				"yes");
	}

	return 0;
}

/*********************************************************************
 Remove a Windows ACL - we're setting the underlying POSIX ACL.
*********************************************************************/

static int sys_acl_set_file_tdb(vfs_handle_struct *handle,
			const struct smb_filename *smb_fname_in,
			SMB_ACL_TYPE_T type,
			SMB_ACL_T theacl)
{
	struct db_context *db = acl_db;
	int ret = -1;
	int saved_errno = 0;
	struct smb_filename *smb_fname = NULL;

	smb_fname = cp_smb_filename_nostream(talloc_tos(), smb_fname_in);
	if (smb_fname == NULL) {
		return -1;
	};

	ret = SMB_VFS_STAT(handle->conn, smb_fname);
	if (ret == -1) {
		saved_errno = errno;
		goto fail;
	}

	ret = SMB_VFS_NEXT_SYS_ACL_SET_FILE(handle,
						smb_fname,
						type,
						theacl);
	if (ret == -1) {
		saved_errno = errno;
		goto fail;
	}

	acl_tdb_delete(handle, db, &smb_fname->st);

fail:
	TALLOC_FREE(smb_fname);

	if (saved_errno != 0) {
		errno = saved_errno;
	}
	return ret;
}

/*********************************************************************
 Remove a Windows ACL - we're setting the underlying POSIX ACL.
*********************************************************************/

static int sys_acl_set_fd_tdb(vfs_handle_struct *handle,
                            files_struct *fsp,
                            SMB_ACL_T theacl)
{
	struct db_context *db = acl_db;
	NTSTATUS status;
	int ret;

	status = vfs_stat_fsp(fsp);
	if (!NT_STATUS_IS_OK(status)) {
		return -1;
	}

	ret = SMB_VFS_NEXT_SYS_ACL_SET_FD(handle,
						fsp,
						theacl);
	if (ret == -1) {
		return -1;
	}

	acl_tdb_delete(handle, db, &fsp->fsp_name->st);
	return 0;
}

static NTSTATUS acl_tdb_fget_nt_acl(vfs_handle_struct *handle,
				    files_struct *fsp,
				    uint32_t security_info,
				    TALLOC_CTX *mem_ctx,
				    struct security_descriptor **ppdesc)
{
	NTSTATUS status;
	status = fget_nt_acl_common(fget_acl_blob, handle, fsp,
				   security_info, mem_ctx, ppdesc);
	return status;
}

static NTSTATUS acl_tdb_get_nt_acl_at(vfs_handle_struct *handle,
				struct files_struct *dirfsp,
				const struct smb_filename *smb_fname,
				uint32_t security_info,
				TALLOC_CTX *mem_ctx,
				struct security_descriptor **ppdesc)
{
	NTSTATUS status;
	status = get_nt_acl_common_at(get_acl_blob_at,
				handle,
				dirfsp,
				smb_fname,
				security_info,
				mem_ctx,
				ppdesc);
	return status;
}


static NTSTATUS acl_tdb_fset_nt_acl(vfs_handle_struct *handle,
				    files_struct *fsp,
				    uint32_t security_info_sent,
				    const struct security_descriptor *psd)
{
	NTSTATUS status;
	status = fset_nt_acl_common(fget_acl_blob, store_acl_blob_fsp,
				    ACL_MODULE_NAME,
				    handle, fsp, security_info_sent, psd);
	return status;
}

static struct vfs_fn_pointers vfs_acl_tdb_fns = {
	.connect_fn = connect_acl_tdb,
	.disconnect_fn = disconnect_acl_tdb,
	.unlinkat_fn = unlinkat_acl_tdb,
	.chmod_fn = chmod_acl_module_common,
	.fchmod_fn = fchmod_acl_module_common,
	.fget_nt_acl_fn = acl_tdb_fget_nt_acl,
	.get_nt_acl_at_fn = acl_tdb_get_nt_acl_at,
	.fset_nt_acl_fn = acl_tdb_fset_nt_acl,
	.sys_acl_set_file_fn = sys_acl_set_file_tdb,
	.sys_acl_set_fd_fn = sys_acl_set_fd_tdb
};

static_decl_vfs;
NTSTATUS vfs_acl_tdb_init(TALLOC_CTX *ctx)
{
	return smb_register_vfs(SMB_VFS_INTERFACE_VERSION, "acl_tdb",
				&vfs_acl_tdb_fns);
}
