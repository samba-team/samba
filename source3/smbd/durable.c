/*
   Unix SMB/CIFS implementation.
   Durable Handle default VFS implementation

   Copyright (C) Stefan Metzmacher 2012
   Copyright (C) Michael Adam 2012
   Copyright (C) Volker Lendecke 2012

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
#include "system/filesys.h"
#include "smbd/smbd.h"
#include "smbd/globals.h"
#include "libcli/security/security.h"
#include "messages.h"
#include "librpc/gen_ndr/ndr_open_files.h"
#include "serverid.h"
#include "fake_file.h"

NTSTATUS vfs_default_durable_cookie(struct files_struct *fsp,
				    TALLOC_CTX *mem_ctx,
				    DATA_BLOB *cookie_blob)
{
	struct connection_struct *conn = fsp->conn;
	enum ndr_err_code ndr_err;
	struct vfs_default_durable_cookie cookie;

	if (!lp_durable_handles(SNUM(conn))) {
		return NT_STATUS_NOT_SUPPORTED;
	}

	if (lp_kernel_share_modes(SNUM(conn))) {
		/*
		 * We do not support durable handles
		 * if kernel share modes (flocks) are used
		 */
		return NT_STATUS_NOT_SUPPORTED;
	}

	if (lp_kernel_oplocks(SNUM(conn))) {
		/*
		 * We do not support durable handles
		 * if kernel oplocks are used
		 */
		return NT_STATUS_NOT_SUPPORTED;
	}

	if ((fsp->current_lock_count > 0) &&
	    lp_posix_locking(fsp->conn->params))
	{
		/*
		 * We do not support durable handles
		 * if the handle has posix locks.
		 */
		return NT_STATUS_NOT_SUPPORTED;
	}

	if (fsp->is_directory) {
		return NT_STATUS_NOT_SUPPORTED;
	}

	if (fsp->fh->fd == -1) {
		return NT_STATUS_NOT_SUPPORTED;
	}

	if (is_ntfs_stream_smb_fname(fsp->fsp_name)) {
		/*
		 * We do not support durable handles
		 * on streams for now.
		 */
		return NT_STATUS_NOT_SUPPORTED;
	}

	if (is_fake_file(fsp->fsp_name)) {
		/*
		 * We do not support durable handles
		 * on fake files.
		 */
		return NT_STATUS_NOT_SUPPORTED;
	}

	ZERO_STRUCT(cookie);
	cookie.allow_reconnect = false;
	cookie.id = fsp->file_id;
	cookie.servicepath = conn->connectpath;
	cookie.base_name = fsp->fsp_name->base_name;
	cookie.initial_allocation_size = fsp->initial_allocation_size;
	cookie.position_information = fsp->fh->position_information;
	cookie.update_write_time_triggered = fsp->update_write_time_triggered;
	cookie.update_write_time_on_close = fsp->update_write_time_on_close;
	cookie.write_time_forced = fsp->write_time_forced;
	cookie.close_write_time = fsp->close_write_time;

	cookie.stat_info.st_ex_dev = fsp->fsp_name->st.st_ex_dev;
	cookie.stat_info.st_ex_ino = fsp->fsp_name->st.st_ex_ino;
	cookie.stat_info.st_ex_mode = fsp->fsp_name->st.st_ex_mode;
	cookie.stat_info.st_ex_nlink = fsp->fsp_name->st.st_ex_nlink;
	cookie.stat_info.st_ex_uid = fsp->fsp_name->st.st_ex_uid;
	cookie.stat_info.st_ex_gid = fsp->fsp_name->st.st_ex_gid;
	cookie.stat_info.st_ex_rdev = fsp->fsp_name->st.st_ex_rdev;
	cookie.stat_info.st_ex_size = fsp->fsp_name->st.st_ex_size;
	cookie.stat_info.st_ex_atime = fsp->fsp_name->st.st_ex_atime;
	cookie.stat_info.st_ex_mtime = fsp->fsp_name->st.st_ex_mtime;
	cookie.stat_info.st_ex_ctime = fsp->fsp_name->st.st_ex_ctime;
	cookie.stat_info.st_ex_btime = fsp->fsp_name->st.st_ex_btime;
	cookie.stat_info.st_ex_calculated_birthtime = fsp->fsp_name->st.st_ex_calculated_birthtime;
	cookie.stat_info.st_ex_blksize = fsp->fsp_name->st.st_ex_blksize;
	cookie.stat_info.st_ex_blocks = fsp->fsp_name->st.st_ex_blocks;
	cookie.stat_info.st_ex_flags = fsp->fsp_name->st.st_ex_flags;
	cookie.stat_info.st_ex_mask = fsp->fsp_name->st.st_ex_mask;
	cookie.stat_info.vfs_private = fsp->fsp_name->st.vfs_private;

	ndr_err = ndr_push_struct_blob(cookie_blob, mem_ctx, &cookie,
			(ndr_push_flags_fn_t)ndr_push_vfs_default_durable_cookie);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		NTSTATUS status = ndr_map_error2ntstatus(ndr_err);
		return status;
	}

	return NT_STATUS_OK;
}

NTSTATUS vfs_default_durable_disconnect(struct files_struct *fsp,
					const DATA_BLOB old_cookie,
					TALLOC_CTX *mem_ctx,
					DATA_BLOB *new_cookie)
{
	struct connection_struct *conn = fsp->conn;
	NTSTATUS status;
	enum ndr_err_code ndr_err;
	struct vfs_default_durable_cookie cookie;
	DATA_BLOB new_cookie_blob = data_blob_null;
	struct share_mode_lock *lck;
	bool ok;

	*new_cookie = data_blob_null;

	ZERO_STRUCT(cookie);

	ndr_err = ndr_pull_struct_blob(&old_cookie, talloc_tos(), &cookie,
			(ndr_pull_flags_fn_t)ndr_pull_vfs_default_durable_cookie);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		status = ndr_map_error2ntstatus(ndr_err);
		return status;
	}

	if (strcmp(cookie.magic, VFS_DEFAULT_DURABLE_COOKIE_MAGIC) != 0) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	if (cookie.version != VFS_DEFAULT_DURABLE_COOKIE_VERSION) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	if (!file_id_equal(&fsp->file_id, &cookie.id)) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	if (!BATCH_OPLOCK_TYPE(fsp->oplock_type)) {
		return NT_STATUS_NOT_SUPPORTED;
	}

	if (fsp->num_pending_break_messages > 0) {
		return NT_STATUS_NOT_SUPPORTED;
	}

	/*
	 * For now let it be simple and do not keep
	 * delete on close files durable open
	 */
	if (fsp->initial_delete_on_close) {
		return NT_STATUS_NOT_SUPPORTED;
	}
	if (fsp->delete_on_close) {
		return NT_STATUS_NOT_SUPPORTED;
	}

	if (!VALID_STAT(fsp->fsp_name->st)) {
		return NT_STATUS_NOT_SUPPORTED;
	}

	if (!S_ISREG(fsp->fsp_name->st.st_ex_mode)) {
		return NT_STATUS_NOT_SUPPORTED;
	}

	/* Ensure any pending write time updates are done. */
	if (fsp->update_write_time_event) {
		update_write_time_handler(fsp->conn->sconn->ev_ctx,
					fsp->update_write_time_event,
					timeval_current(),
					(void *)fsp);
	}

	/*
	 * The above checks are done in mark_share_mode_disconnected() too
	 * but we want to avoid getting the lock if possible
	 */
	lck = get_existing_share_mode_lock(talloc_tos(), fsp->file_id);
	if (lck != NULL) {
		struct smb_file_time ft;

		ZERO_STRUCT(ft);

		if (fsp->write_time_forced) {
			ft.mtime = lck->data->changed_write_time;
		} else if (fsp->update_write_time_on_close) {
			if (null_timespec(fsp->close_write_time)) {
				ft.mtime = timespec_current();
			} else {
				ft.mtime = fsp->close_write_time;
			}
		}

		if (!null_timespec(ft.mtime)) {
			round_timespec(conn->ts_res, &ft.mtime);
			file_ntimes(conn, fsp->fsp_name, &ft);
		}

		ok = mark_share_mode_disconnected(lck, fsp);
		if (!ok) {
			TALLOC_FREE(lck);
		}
	}
	if (lck != NULL) {
		ok = brl_mark_disconnected(fsp);
		if (!ok) {
			TALLOC_FREE(lck);
		}
	}
	if (lck == NULL) {
		return NT_STATUS_NOT_SUPPORTED;
	}
	TALLOC_FREE(lck);

	status = vfs_stat_fsp(fsp);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	ZERO_STRUCT(cookie);
	cookie.allow_reconnect = true;
	cookie.id = fsp->file_id;
	cookie.servicepath = conn->connectpath;
	cookie.base_name = fsp->fsp_name->base_name;
	cookie.initial_allocation_size = fsp->initial_allocation_size;
	cookie.position_information = fsp->fh->position_information;
	cookie.update_write_time_triggered = fsp->update_write_time_triggered;
	cookie.update_write_time_on_close = fsp->update_write_time_on_close;
	cookie.write_time_forced = fsp->write_time_forced;
	cookie.close_write_time = fsp->close_write_time;

	cookie.stat_info.st_ex_dev = fsp->fsp_name->st.st_ex_dev;
	cookie.stat_info.st_ex_ino = fsp->fsp_name->st.st_ex_ino;
	cookie.stat_info.st_ex_mode = fsp->fsp_name->st.st_ex_mode;
	cookie.stat_info.st_ex_nlink = fsp->fsp_name->st.st_ex_nlink;
	cookie.stat_info.st_ex_uid = fsp->fsp_name->st.st_ex_uid;
	cookie.stat_info.st_ex_gid = fsp->fsp_name->st.st_ex_gid;
	cookie.stat_info.st_ex_rdev = fsp->fsp_name->st.st_ex_rdev;
	cookie.stat_info.st_ex_size = fsp->fsp_name->st.st_ex_size;
	cookie.stat_info.st_ex_atime = fsp->fsp_name->st.st_ex_atime;
	cookie.stat_info.st_ex_mtime = fsp->fsp_name->st.st_ex_mtime;
	cookie.stat_info.st_ex_ctime = fsp->fsp_name->st.st_ex_ctime;
	cookie.stat_info.st_ex_btime = fsp->fsp_name->st.st_ex_btime;
	cookie.stat_info.st_ex_calculated_birthtime = fsp->fsp_name->st.st_ex_calculated_birthtime;
	cookie.stat_info.st_ex_blksize = fsp->fsp_name->st.st_ex_blksize;
	cookie.stat_info.st_ex_blocks = fsp->fsp_name->st.st_ex_blocks;
	cookie.stat_info.st_ex_flags = fsp->fsp_name->st.st_ex_flags;
	cookie.stat_info.st_ex_mask = fsp->fsp_name->st.st_ex_mask;
	cookie.stat_info.vfs_private = fsp->fsp_name->st.vfs_private;

	ndr_err = ndr_push_struct_blob(&new_cookie_blob, mem_ctx, &cookie,
			(ndr_push_flags_fn_t)ndr_push_vfs_default_durable_cookie);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		status = ndr_map_error2ntstatus(ndr_err);
		return status;
	}

	status = fd_close(fsp);
	if (!NT_STATUS_IS_OK(status)) {
		data_blob_free(&new_cookie_blob);
		return status;
	}

	*new_cookie = new_cookie_blob;
	return NT_STATUS_OK;
}


/**
 * Check whether a cookie-stored struct info is the same
 * as a given SMB_STRUCT_STAT, as coming with the fsp.
 */
static bool vfs_default_durable_reconnect_check_stat(
				struct vfs_default_durable_stat *cookie_st,
				SMB_STRUCT_STAT *fsp_st,
				const char *name)
{
	int ret;

	if (cookie_st->st_ex_dev != fsp_st->st_ex_dev) {
		DEBUG(1, ("vfs_default_durable_reconnect (%s): "
			  "stat_ex.%s differs: "
			  "cookie:%llu != stat:%llu, "
			  "denying durable reconnect\n",
			  name,
			  "st_ex_dev",
			  (unsigned long long)cookie_st->st_ex_dev,
			  (unsigned long long)fsp_st->st_ex_dev));
		return false;
	}

	if (cookie_st->st_ex_ino != fsp_st->st_ex_ino) {
		DEBUG(1, ("vfs_default_durable_reconnect (%s): "
			  "stat_ex.%s differs: "
			  "cookie:%llu != stat:%llu, "
			  "denying durable reconnect\n",
			  name,
			  "st_ex_ino",
			  (unsigned long long)cookie_st->st_ex_ino,
			  (unsigned long long)fsp_st->st_ex_ino));
		return false;
	}

	if (cookie_st->st_ex_mode != fsp_st->st_ex_mode) {
		DEBUG(1, ("vfs_default_durable_reconnect (%s): "
			  "stat_ex.%s differs: "
			  "cookie:%llu != stat:%llu, "
			  "denying durable reconnect\n",
			  name,
			  "st_ex_mode",
			  (unsigned long long)cookie_st->st_ex_mode,
			  (unsigned long long)fsp_st->st_ex_mode));
		return false;
	}

	if (cookie_st->st_ex_nlink != fsp_st->st_ex_nlink) {
		DEBUG(1, ("vfs_default_durable_reconnect (%s): "
			  "stat_ex.%s differs: "
			  "cookie:%llu != stat:%llu, "
			  "denying durable reconnect\n",
			  name,
			  "st_ex_nlink",
			  (unsigned long long)cookie_st->st_ex_nlink,
			  (unsigned long long)fsp_st->st_ex_nlink));
		return false;
	}

	if (cookie_st->st_ex_uid != fsp_st->st_ex_uid) {
		DEBUG(1, ("vfs_default_durable_reconnect (%s): "
			  "stat_ex.%s differs: "
			  "cookie:%llu != stat:%llu, "
			  "denying durable reconnect\n",
			  name,
			  "st_ex_uid",
			  (unsigned long long)cookie_st->st_ex_uid,
			  (unsigned long long)fsp_st->st_ex_uid));
		return false;
	}

	if (cookie_st->st_ex_gid != fsp_st->st_ex_gid) {
		DEBUG(1, ("vfs_default_durable_reconnect (%s): "
			  "stat_ex.%s differs: "
			  "cookie:%llu != stat:%llu, "
			  "denying durable reconnect\n",
			  name,
			  "st_ex_gid",
			  (unsigned long long)cookie_st->st_ex_gid,
			  (unsigned long long)fsp_st->st_ex_gid));
		return false;
	}

	if (cookie_st->st_ex_rdev != fsp_st->st_ex_rdev) {
		DEBUG(1, ("vfs_default_durable_reconnect (%s): "
			  "stat_ex.%s differs: "
			  "cookie:%llu != stat:%llu, "
			  "denying durable reconnect\n",
			  name,
			  "st_ex_rdev",
			  (unsigned long long)cookie_st->st_ex_rdev,
			  (unsigned long long)fsp_st->st_ex_rdev));
		return false;
	}

	if (cookie_st->st_ex_size != fsp_st->st_ex_size) {
		DEBUG(1, ("vfs_default_durable_reconnect (%s): "
			  "stat_ex.%s differs: "
			  "cookie:%llu != stat:%llu, "
			  "denying durable reconnect\n",
			  name,
			  "st_ex_size",
			  (unsigned long long)cookie_st->st_ex_size,
			  (unsigned long long)fsp_st->st_ex_size));
		return false;
	}

	ret = timespec_compare(&cookie_st->st_ex_atime,
			       &fsp_st->st_ex_atime);
	if (ret != 0) {
		struct timeval tc, ts;
		tc = convert_timespec_to_timeval(cookie_st->st_ex_atime);
		ts = convert_timespec_to_timeval(fsp_st->st_ex_atime);

		DEBUG(1, ("vfs_default_durable_reconnect (%s): "
			  "stat_ex.%s differs: "
			  "cookie:'%s' != stat:'%s', "
			  "denying durable reconnect\n",
			  name,
			  "st_ex_atime",
			  timeval_string(talloc_tos(), &tc, true),
			  timeval_string(talloc_tos(), &ts, true)));
		return false;
	}

	ret = timespec_compare(&cookie_st->st_ex_mtime,
			       &fsp_st->st_ex_mtime);
	if (ret != 0) {
		struct timeval tc, ts;
		tc = convert_timespec_to_timeval(cookie_st->st_ex_mtime);
		ts = convert_timespec_to_timeval(fsp_st->st_ex_mtime);

		DEBUG(1, ("vfs_default_durable_reconnect (%s): "
			  "stat_ex.%s differs: "
			  "cookie:'%s' != stat:'%s', "
			  "denying durable reconnect\n",
			  name,
			  "st_ex_mtime",
			  timeval_string(talloc_tos(), &tc, true),
			  timeval_string(talloc_tos(), &ts, true)));
		return false;
	}

	ret = timespec_compare(&cookie_st->st_ex_ctime,
			       &fsp_st->st_ex_ctime);
	if (ret != 0) {
		struct timeval tc, ts;
		tc = convert_timespec_to_timeval(cookie_st->st_ex_ctime);
		ts = convert_timespec_to_timeval(fsp_st->st_ex_ctime);

		DEBUG(1, ("vfs_default_durable_reconnect (%s): "
			  "stat_ex.%s differs: "
			  "cookie:'%s' != stat:'%s', "
			  "denying durable reconnect\n",
			  name,
			  "st_ex_ctime",
			  timeval_string(talloc_tos(), &tc, true),
			  timeval_string(talloc_tos(), &ts, true)));
		return false;
	}

	ret = timespec_compare(&cookie_st->st_ex_btime,
			       &fsp_st->st_ex_btime);
	if (ret != 0) {
		struct timeval tc, ts;
		tc = convert_timespec_to_timeval(cookie_st->st_ex_btime);
		ts = convert_timespec_to_timeval(fsp_st->st_ex_btime);

		DEBUG(1, ("vfs_default_durable_reconnect (%s): "
			  "stat_ex.%s differs: "
			  "cookie:'%s' != stat:'%s', "
			  "denying durable reconnect\n",
			  name,
			  "st_ex_btime",
			  timeval_string(talloc_tos(), &tc, true),
			  timeval_string(talloc_tos(), &ts, true)));
		return false;
	}

	if (cookie_st->st_ex_calculated_birthtime !=
	    fsp_st->st_ex_calculated_birthtime)
	{
		DEBUG(1, ("vfs_default_durable_reconnect (%s): "
			  "stat_ex.%s differs: "
			  "cookie:%llu != stat:%llu, "
			  "denying durable reconnect\n",
			  name,
			  "st_ex_calculated_birthtime",
			  (unsigned long long)cookie_st->st_ex_calculated_birthtime,
			  (unsigned long long)fsp_st->st_ex_calculated_birthtime));
		return false;
	}

	if (cookie_st->st_ex_blksize != fsp_st->st_ex_blksize) {
		DEBUG(1, ("vfs_default_durable_reconnect (%s): "
			  "stat_ex.%s differs: "
			  "cookie:%llu != stat:%llu, "
			  "denying durable reconnect\n",
			  name,
			  "st_ex_blksize",
			  (unsigned long long)cookie_st->st_ex_blksize,
			  (unsigned long long)fsp_st->st_ex_blksize));
		return false;
	}

	if (cookie_st->st_ex_blocks != fsp_st->st_ex_blocks) {
		DEBUG(1, ("vfs_default_durable_reconnect (%s): "
			  "stat_ex.%s differs: "
			  "cookie:%llu != stat:%llu, "
			  "denying durable reconnect\n",
			  name,
			  "st_ex_blocks",
			  (unsigned long long)cookie_st->st_ex_blocks,
			  (unsigned long long)fsp_st->st_ex_blocks));
		return false;
	}

	if (cookie_st->st_ex_flags != fsp_st->st_ex_flags) {
		DEBUG(1, ("vfs_default_durable_reconnect (%s): "
			  "stat_ex.%s differs: "
			  "cookie:%llu != stat:%llu, "
			  "denying durable reconnect\n",
			  name,
			  "st_ex_flags",
			  (unsigned long long)cookie_st->st_ex_flags,
			  (unsigned long long)fsp_st->st_ex_flags));
		return false;
	}

	if (cookie_st->st_ex_mask != fsp_st->st_ex_mask) {
		DEBUG(1, ("vfs_default_durable_reconnect (%s): "
			  "stat_ex.%s differs: "
			  "cookie:%llu != stat:%llu, "
			  "denying durable reconnect\n",
			  name,
			  "st_ex_mask",
			  (unsigned long long)cookie_st->st_ex_mask,
			  (unsigned long long)fsp_st->st_ex_mask));
		return false;
	}

	if (cookie_st->vfs_private != fsp_st->vfs_private) {
		DEBUG(1, ("vfs_default_durable_reconnect (%s): "
			  "stat_ex.%s differs: "
			  "cookie:%llu != stat:%llu, "
			  "denying durable reconnect\n",
			  name,
			  "vfs_private",
			  (unsigned long long)cookie_st->vfs_private,
			  (unsigned long long)fsp_st->vfs_private));
		return false;
	}

	return true;
}

NTSTATUS vfs_default_durable_reconnect(struct connection_struct *conn,
				       struct smb_request *smb1req,
				       struct smbXsrv_open *op,
				       const DATA_BLOB old_cookie,
				       TALLOC_CTX *mem_ctx,
				       files_struct **result,
				       DATA_BLOB *new_cookie)
{
	struct share_mode_lock *lck;
	struct share_mode_entry *e;
	struct files_struct *fsp = NULL;
	NTSTATUS status;
	bool ok;
	int ret;
	int flags = 0;
	struct file_id file_id;
	struct smb_filename *smb_fname = NULL;
	enum ndr_err_code ndr_err;
	struct vfs_default_durable_cookie cookie;
	DATA_BLOB new_cookie_blob = data_blob_null;

	*result = NULL;
	*new_cookie = data_blob_null;

	if (!lp_durable_handles(SNUM(conn))) {
		return NT_STATUS_NOT_SUPPORTED;
	}

	/*
	 * the checks for kernel oplocks
	 * and similar things are done
	 * in the vfs_default_durable_cookie()
	 * call below.
	 */

	ZERO_STRUCT(cookie);

	ndr_err = ndr_pull_struct_blob(&old_cookie, talloc_tos(), &cookie,
			(ndr_pull_flags_fn_t)ndr_pull_vfs_default_durable_cookie);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		status = ndr_map_error2ntstatus(ndr_err);
		return status;
	}

	if (strcmp(cookie.magic, VFS_DEFAULT_DURABLE_COOKIE_MAGIC) != 0) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	if (cookie.version != VFS_DEFAULT_DURABLE_COOKIE_VERSION) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	if (!cookie.allow_reconnect) {
		return NT_STATUS_OBJECT_NAME_NOT_FOUND;
	}

	if (strcmp(cookie.servicepath, conn->connectpath) != 0) {
		return NT_STATUS_OBJECT_NAME_NOT_FOUND;
	}

	/* Create an smb_filename with stream_name == NULL. */
	status = create_synthetic_smb_fname(talloc_tos(),
					    cookie.base_name,
					    NULL, NULL,
					    &smb_fname);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	ret = SMB_VFS_LSTAT(conn, smb_fname);
	if (ret == -1) {
		status = map_nt_error_from_unix_common(errno);
		DEBUG(1, ("Unable to lstat stream: %s => %s\n",
			  smb_fname_str_dbg(smb_fname),
			  nt_errstr(status)));
		return status;
	}

	if (!S_ISREG(smb_fname->st.st_ex_mode)) {
		return NT_STATUS_OBJECT_NAME_NOT_FOUND;
	}

	file_id = vfs_file_id_from_sbuf(conn, &smb_fname->st);
	if (!file_id_equal(&cookie.id, &file_id)) {
		return NT_STATUS_OBJECT_NAME_NOT_FOUND;
	}

	/*
	 * 1. check entry in locking.tdb
	 */

	lck = get_existing_share_mode_lock(mem_ctx, file_id);
	if (lck == NULL) {
		DEBUG(5, ("vfs_default_durable_reconnect: share-mode lock "
			   "not obtained from db\n"));
		return NT_STATUS_OBJECT_NAME_NOT_FOUND;
	}

	if (lck->data->num_share_modes == 0) {
		DEBUG(1, ("vfs_default_durable_reconnect: Error: no share-mode "
			  "entry in existing share mode lock\n"));
		TALLOC_FREE(lck);
		return NT_STATUS_INTERNAL_DB_ERROR;
	}

	if (lck->data->num_share_modes > 1) {
		/*
		 * It can't be durable if there is more than one handle
		 * on the file.
		 */
		DEBUG(5, ("vfs_default_durable_reconnect: more than one "
			  "share-mode entry - can not be durable\n"));
		TALLOC_FREE(lck);
		return NT_STATUS_OBJECT_NAME_NOT_FOUND;
	}

	e = &lck->data->share_modes[0];

	if (!server_id_is_disconnected(&e->pid)) {
		DEBUG(5, ("vfs_default_durable_reconnect: denying durable "
			  "reconnect for handle that was not marked "
			  "disconnected (e.g. smbd or cluster node died)\n"));
		TALLOC_FREE(lck);
		return NT_STATUS_OBJECT_NAME_NOT_FOUND;
	}

	if (e->share_file_id != op->global->open_persistent_id) {
		DEBUG(5, ("vfs_default_durable_reconnect: denying durable "
			  "share_file_id changed %llu != %llu"
			  "(e.g. another client had opened the file)\n",
			  (unsigned long long)e->share_file_id,
			  (unsigned long long)op->global->open_persistent_id));
		TALLOC_FREE(lck);
		return NT_STATUS_OBJECT_NAME_NOT_FOUND;
	}

	if ((e->access_mask & (FILE_WRITE_DATA|FILE_APPEND_DATA)) &&
	    !CAN_WRITE(conn))
	{
		DEBUG(5, ("vfs_default_durable_reconnect: denying durable "
			  "share[%s] is not writeable anymore\n",
			  lp_servicename(talloc_tos(), SNUM(conn))));
		TALLOC_FREE(lck);
		return NT_STATUS_OBJECT_NAME_NOT_FOUND;
	}

	/*
	 * TODO:
	 * add scavenger timer functionality
	 *
	 * For now we always allow the reconnect
	 */
#if 0
	expire_time = op->global->disconnect_time;
	expire_time += NTTIME_MAGIC(op->global->durable_timeout_msec);
	if (expire < now) {
		//TODO reopen and close before telling the client...
	}
#endif

	/*
	 * 2. proceed with opening file
	 */

	status = fsp_new(conn, conn, &fsp);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("vfs_default_durable_reconnect: failed to create "
			  "new fsp: %s\n", nt_errstr(status)));
		TALLOC_FREE(lck);
		return status;
	}

	fsp->fh->private_options = e->private_options;
	fsp->fh->gen_id = smbXsrv_open_hash(op);
	fsp->file_id = file_id;
	fsp->file_pid = smb1req->smbpid;
	fsp->vuid = smb1req->vuid;
	fsp->open_time = e->time;
	fsp->access_mask = e->access_mask;
	fsp->share_access = e->share_access;
	fsp->can_read = ((fsp->access_mask & (FILE_READ_DATA)) != 0);
	fsp->can_write = ((fsp->access_mask & (FILE_WRITE_DATA|FILE_APPEND_DATA)) != 0);

	/*
	 * TODO:
	 * Do we need to store the modified flag in the DB?
	 * How to handle update_write_time and friends
	 * during a disconnected client on a durable handle?
	 */
	fsp->modified = false;
	/*
	 * no durables for directories
	 */
	fsp->is_directory = false;
	/*
	 * For normal files, can_lock == !is_directory
	 */
	fsp->can_lock = true;
	/*
	 * We do not support aio write behind for smb2
	 */
	fsp->aio_write_behind = false;
	fsp->oplock_type = e->op_type;

	fsp->initial_allocation_size = cookie.initial_allocation_size;
	fsp->fh->position_information = cookie.position_information;
	fsp->update_write_time_triggered = cookie.update_write_time_triggered;
	fsp->update_write_time_on_close = cookie.update_write_time_on_close;
	fsp->write_time_forced = cookie.write_time_forced;
	fsp->close_write_time = cookie.close_write_time;

	status = fsp_set_smb_fname(fsp, smb_fname);
	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(lck);
		fsp_free(fsp);
		DEBUG(0, ("vfs_default_durable_reconnect: "
			  "fsp_set_smb_fname failed: %s\n",
			  nt_errstr(status)));
		return status;
	}

	op->compat = fsp;
	fsp->op = op;

	e->pid = messaging_server_id(conn->sconn->msg_ctx);
	e->op_mid = smb1req->mid;
	e->share_file_id = fsp->fh->gen_id;

	ok = brl_reconnect_disconnected(fsp);
	if (!ok) {
		status = NT_STATUS_INTERNAL_ERROR;
		DEBUG(1, ("vfs_default_durable_reconnect: "
			  "failed to reopen brlocks: %s\n",
			  nt_errstr(status)));
		TALLOC_FREE(lck);
		op->compat = NULL;
		fsp_free(fsp);
		return status;
	}

	/*
	 * TODO: properly calculate open flags
	 */
	if (fsp->can_write && fsp->can_read) {
		flags = O_RDWR;
	} else if (fsp->can_write) {
		flags = O_WRONLY;
	} else if (fsp->can_read) {
		flags = O_RDONLY;
	}

	status = fd_open(conn, fsp, flags, 0 /* mode */);
	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(lck);
		DEBUG(1, ("vfs_default_durable_reconnect: failed to open "
			  "file: %s\n", nt_errstr(status)));
		op->compat = NULL;
		fsp_free(fsp);
		return status;
	}

	/*
	 * We now check the stat info stored in the cookie against
	 * the current stat data from the file we just opened.
	 * If any detail differs, we deny the durable reconnect,
	 * because in that case it is very likely that someone
	 * opened the file while the handle was disconnected,
	 * which has to be interpreted as an oplock break.
	 */

	ret = SMB_VFS_FSTAT(fsp, &fsp->fsp_name->st);
	if (ret == -1) {
		status = map_nt_error_from_unix_common(errno);
		DEBUG(1, ("Unable to fstat stream: %s => %s\n",
			  smb_fname_str_dbg(smb_fname),
			  nt_errstr(status)));
		ret = SMB_VFS_CLOSE(fsp);
		if (ret == -1) {
			DEBUG(0, ("vfs_default_durable_reconnect: "
				  "SMB_VFS_CLOSE failed (%s) - leaking file "
				  "descriptor\n", strerror(errno)));
		}
		TALLOC_FREE(lck);
		op->compat = NULL;
		fsp_free(fsp);
		return status;
	}

	if (!S_ISREG(fsp->fsp_name->st.st_ex_mode)) {
		ret = SMB_VFS_CLOSE(fsp);
		if (ret == -1) {
			DEBUG(0, ("vfs_default_durable_reconnect: "
				  "SMB_VFS_CLOSE failed (%s) - leaking file "
				  "descriptor\n", strerror(errno)));
		}
		TALLOC_FREE(lck);
		op->compat = NULL;
		fsp_free(fsp);
		return NT_STATUS_OBJECT_NAME_NOT_FOUND;
	}

	file_id = vfs_file_id_from_sbuf(conn, &fsp->fsp_name->st);
	if (!file_id_equal(&cookie.id, &file_id)) {
		ret = SMB_VFS_CLOSE(fsp);
		if (ret == -1) {
			DEBUG(0, ("vfs_default_durable_reconnect: "
				  "SMB_VFS_CLOSE failed (%s) - leaking file "
				  "descriptor\n", strerror(errno)));
		}
		TALLOC_FREE(lck);
		op->compat = NULL;
		fsp_free(fsp);
		return NT_STATUS_OBJECT_NAME_NOT_FOUND;
	}

	ok = vfs_default_durable_reconnect_check_stat(&cookie.stat_info,
						      &fsp->fsp_name->st,
						      fsp_str_dbg(fsp));
	if (!ok) {
		ret = SMB_VFS_CLOSE(fsp);
		if (ret == -1) {
			DEBUG(0, ("vfs_default_durable_reconnect: "
				  "SMB_VFS_CLOSE failed (%s) - leaking file "
				  "descriptor\n", strerror(errno)));
		}
		TALLOC_FREE(lck);
		op->compat = NULL;
		fsp_free(fsp);
		return NT_STATUS_OBJECT_NAME_NOT_FOUND;
	}

	status = set_file_oplock(fsp, e->op_type);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(1, ("vfs_default_durable_reconnect failed to set oplock "
			  "after opening file: %s\n", nt_errstr(status)));
		ret = SMB_VFS_CLOSE(fsp);
		if (ret == -1) {
			DEBUG(0, ("vfs_default_durable_reconnect: "
				  "SMB_VFS_CLOSE failed (%s) - leaking file "
				  "descriptor\n", strerror(errno)));
		}
		TALLOC_FREE(lck);
		op->compat = NULL;
		fsp_free(fsp);
		return status;
	}

	status = vfs_default_durable_cookie(fsp, mem_ctx, &new_cookie_blob);
	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(lck);
		DEBUG(1, ("vfs_default_durable_reconnect: "
			  "vfs_default_durable_cookie - %s\n",
			  nt_errstr(status)));
		op->compat = NULL;
		fsp_free(fsp);
		return status;
	}

	smb1req->chain_fsp = fsp;
	smb1req->smb2req->compat_chain_fsp = fsp;

	DEBUG(10, ("vfs_default_durable_reconnect: opened file '%s'\n",
		   fsp_str_dbg(fsp)));

	/*
	 * release the sharemode lock: this writes the changes
	 */
	lck->data->modified = true;
	TALLOC_FREE(lck);

	*result = fsp;
	*new_cookie = new_cookie_blob;

	return NT_STATUS_OK;
}
