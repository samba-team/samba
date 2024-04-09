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
#include "lib/util/server_id.h"
#include "locking/share_mode_lock.h"
#include "smbd/smbd.h"
#include "smbd/globals.h"
#include "libcli/security/security.h"
#include "messages.h"
#include "librpc/gen_ndr/ndr_open_files.h"
#include "serverid.h"
#include "fake_file.h"
#include "locking/leases_db.h"

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
		 * if file system sharemodes are used
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

	if (fsp->fsp_flags.is_directory) {
		return NT_STATUS_NOT_SUPPORTED;
	}

	if (fsp_is_alternate_stream(fsp)) {
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
	cookie.position_information = fh_get_position_information(fsp->fh);
	cookie.update_write_time_triggered =
		fsp->fsp_flags.update_write_time_triggered;
	cookie.update_write_time_on_close =
		fsp->fsp_flags.update_write_time_on_close;
	cookie.write_time_forced = fsp->fsp_flags.write_time_forced;
	cookie.close_write_time = full_timespec_to_nt_time(
		&fsp->close_write_time);

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
	cookie.stat_info.st_ex_iflags = fsp->fsp_name->st.st_ex_iflags;
	cookie.stat_info.st_ex_blksize = fsp->fsp_name->st.st_ex_blksize;
	cookie.stat_info.st_ex_blocks = fsp->fsp_name->st.st_ex_blocks;
	cookie.stat_info.st_ex_flags = fsp->fsp_name->st.st_ex_flags;

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

	if ((fsp_lease_type(fsp) & SMB2_LEASE_HANDLE) == 0) {
		return NT_STATUS_NOT_SUPPORTED;
	}

	/*
	 * For now let it be simple and do not keep
	 * delete on close files durable open
	 */
	if (fsp->fsp_flags.initial_delete_on_close) {
		return NT_STATUS_NOT_SUPPORTED;
	}
	if (fsp->fsp_flags.delete_on_close) {
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
		fsp_flush_write_time_update(fsp);
	}

	/*
	 * The above checks are done in mark_share_mode_disconnected() too
	 * but we want to avoid getting the lock if possible
	 */
	lck = get_existing_share_mode_lock(talloc_tos(), fsp->file_id);
	if (lck != NULL) {
		struct smb_file_time ft;

		init_smb_file_time(&ft);

		if (fsp->fsp_flags.write_time_forced) {
			NTTIME mtime = share_mode_changed_write_time(lck);
			ft.mtime = nt_time_to_full_timespec(mtime);
		} else if (fsp->fsp_flags.update_write_time_on_close) {
			if (is_omit_timespec(&fsp->close_write_time)) {
				ft.mtime = timespec_current();
			} else {
				ft.mtime = fsp->close_write_time;
			}
		}

		if (!is_omit_timespec(&ft.mtime)) {
			round_timespec(conn->ts_res, &ft.mtime);
			file_ntimes(conn, fsp, &ft);
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
	cookie.base_name = fsp_str_dbg(fsp);
	cookie.initial_allocation_size = fsp->initial_allocation_size;
	cookie.position_information = fh_get_position_information(fsp->fh);
	cookie.update_write_time_triggered =
		fsp->fsp_flags.update_write_time_triggered;
	cookie.update_write_time_on_close =
		fsp->fsp_flags.update_write_time_on_close;
	cookie.write_time_forced = fsp->fsp_flags.write_time_forced;
	cookie.close_write_time = full_timespec_to_nt_time(
		&fsp->close_write_time);

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
	cookie.stat_info.st_ex_iflags = fsp->fsp_name->st.st_ex_iflags;
	cookie.stat_info.st_ex_blksize = fsp->fsp_name->st.st_ex_blksize;
	cookie.stat_info.st_ex_blocks = fsp->fsp_name->st.st_ex_blocks;
	cookie.stat_info.st_ex_flags = fsp->fsp_name->st.st_ex_flags;

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

	if (cookie_st->st_ex_iflags != fsp_st->st_ex_iflags) {
		DEBUG(1, ("vfs_default_durable_reconnect (%s): "
			  "stat_ex.%s differs: "
			  "cookie:%llu != stat:%llu, "
			  "denying durable reconnect\n",
			  name,
			  "st_ex_calculated_birthtime",
			  (unsigned long long)cookie_st->st_ex_iflags,
			  (unsigned long long)fsp_st->st_ex_iflags));
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
		DBG_WARNING(" (%s): "
			    "stat_ex.%s differs: "
			    "cookie:%"PRIu32" != stat:%"PRIu32", "
			    "denying durable reconnect\n",
			    name,
			    "st_ex_flags",
			    cookie_st->st_ex_flags,
			    fsp_st->st_ex_flags);
		return false;
	}

	return true;
}

static bool durable_reconnect_fn(
	struct share_mode_entry *e,
	bool *modified,
	void *private_data)
{
	struct share_mode_entry *dst_e = private_data;

	if (dst_e->pid.pid != 0) {
		DBG_INFO("Found more than one entry, invalidating previous\n");
		dst_e->pid.pid = 0;
		return true;	/* end the loop through share mode entries */
	}
	*dst_e = *e;
	return false;		/* Look at potential other entries */
}

NTSTATUS vfs_default_durable_reconnect(struct connection_struct *conn,
				       struct smb_request *smb1req,
				       struct smbXsrv_open *op,
				       const DATA_BLOB old_cookie,
				       TALLOC_CTX *mem_ctx,
				       files_struct **result,
				       DATA_BLOB *new_cookie)
{
	const struct loadparm_substitution *lp_sub =
		loadparm_s3_global_substitution();
	struct share_mode_lock *lck;
	struct share_mode_entry e;
	struct files_struct *fsp = NULL;
	NTSTATUS status;
	bool ok;
	int ret;
	struct vfs_open_how how = { .flags = 0, };
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

	ndr_err = ndr_pull_struct_blob_all(
		&old_cookie,
		talloc_tos(),
		&cookie,
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
	smb_fname = synthetic_smb_fname(talloc_tos(),
					cookie.base_name,
					NULL,
					NULL,
					0,
					0);
	if (smb_fname == NULL) {
		return NT_STATUS_NO_MEMORY;
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

	e = (struct share_mode_entry) { .pid.pid = 0 };

	ok = share_mode_forall_entries(lck, durable_reconnect_fn, &e);
	if (!ok) {
		DBG_WARNING("share_mode_forall_entries failed\n");
		status = NT_STATUS_INTERNAL_DB_ERROR;
		goto fail;
	}

	if (e.pid.pid == 0) {
		DBG_WARNING("Did not find a unique valid share mode entry\n");
		status = NT_STATUS_OBJECT_NAME_NOT_FOUND;
		goto fail;
	}

	if (!server_id_is_disconnected(&e.pid)) {
		DEBUG(5, ("vfs_default_durable_reconnect: denying durable "
			  "reconnect for handle that was not marked "
			  "disconnected (e.g. smbd or cluster node died)\n"));
		status = NT_STATUS_OBJECT_NAME_NOT_FOUND;
		goto fail;
	}

	if (e.share_file_id != op->global->open_persistent_id) {
		DBG_INFO("denying durable "
			 "share_file_id changed %"PRIu64" != %"PRIu64" "
			 "(e.g. another client had opened the file)\n",
			 e.share_file_id,
			 op->global->open_persistent_id);
		status = NT_STATUS_OBJECT_NAME_NOT_FOUND;
		goto fail;
	}

	if ((e.access_mask & (FILE_WRITE_DATA|FILE_APPEND_DATA)) &&
	    !CAN_WRITE(conn))
	{
		DEBUG(5, ("vfs_default_durable_reconnect: denying durable "
			  "share[%s] is not writeable anymore\n",
			  lp_servicename(talloc_tos(), lp_sub, SNUM(conn))));
		status = NT_STATUS_OBJECT_NAME_NOT_FOUND;
		goto fail;
	}

	/*
	 * 2. proceed with opening file
	 */

	status = fsp_new(conn, conn, &fsp);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("vfs_default_durable_reconnect: failed to create "
			  "new fsp: %s\n", nt_errstr(status)));
		goto fail;
	}

	fh_set_private_options(fsp->fh, e.private_options);
	fsp->file_id = file_id;
	fsp->file_pid = smb1req->smbpid;
	fsp->vuid = smb1req->vuid;
	fsp->open_time = e.time;
	fsp->access_mask = e.access_mask;
	fsp->fsp_flags.can_read = ((fsp->access_mask & FILE_READ_DATA) != 0);
	fsp->fsp_flags.can_write = ((fsp->access_mask & (FILE_WRITE_DATA|FILE_APPEND_DATA)) != 0);
	fsp->fnum = op->local_id;
	fsp_set_gen_id(fsp);

	/*
	 * TODO:
	 * Do we need to store the modified flag in the DB?
	 */
	fsp->fsp_flags.modified = false;
	/*
	 * no durables for directories
	 */
	fsp->fsp_flags.is_directory = false;
	/*
	 * For normal files, can_lock == !is_directory
	 */
	fsp->fsp_flags.can_lock = true;
	/*
	 * We do not support aio write behind for smb2
	 */
	fsp->fsp_flags.aio_write_behind = false;
	fsp->oplock_type = e.op_type;

	if (fsp->oplock_type == LEASE_OPLOCK) {
		uint32_t current_state;
		uint16_t lease_version, epoch;

		/*
		 * Ensure the existing client guid matches the
		 * stored one in the share_mode_entry.
		 */
		if (!GUID_equal(fsp_client_guid(fsp),
				&e.client_guid)) {
			status = NT_STATUS_OBJECT_NAME_NOT_FOUND;
			goto fail;
		}

		status = leases_db_get(
			&e.client_guid,
			&e.lease_key,
			&file_id,
			&current_state, /* current_state */
			NULL, /* breaking */
			NULL, /* breaking_to_requested */
			NULL, /* breaking_to_required */
			&lease_version, /* lease_version */
			&epoch); /* epoch */
		if (!NT_STATUS_IS_OK(status)) {
			goto fail;
		}

		fsp->lease = find_fsp_lease(
			fsp,
			&e.lease_key,
			current_state,
			lease_version,
			epoch);
		if (fsp->lease == NULL) {
			status = NT_STATUS_NO_MEMORY;
			goto fail;
		}
	}

	fsp->initial_allocation_size = cookie.initial_allocation_size;
	fh_set_position_information(fsp->fh, cookie.position_information);
	fsp->fsp_flags.update_write_time_triggered =
		cookie.update_write_time_triggered;
	fsp->fsp_flags.update_write_time_on_close =
		cookie.update_write_time_on_close;
	fsp->fsp_flags.write_time_forced = cookie.write_time_forced;
	fsp->close_write_time = nt_time_to_full_timespec(
		cookie.close_write_time);

	status = fsp_set_smb_fname(fsp, smb_fname);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("vfs_default_durable_reconnect: "
			  "fsp_set_smb_fname failed: %s\n",
			  nt_errstr(status)));
		goto fail;
	}

	op->compat = fsp;
	fsp->op = op;

	ok = reset_share_mode_entry(
		lck,
		e.pid,
		e.share_file_id,
		messaging_server_id(conn->sconn->msg_ctx),
		smb1req->mid,
		fh_get_gen_id(fsp->fh));
	if (!ok) {
		DBG_DEBUG("Could not set new share_mode_entry values\n");
		status = NT_STATUS_INTERNAL_ERROR;
		goto fail;
	}

	ok = brl_reconnect_disconnected(fsp);
	if (!ok) {
		status = NT_STATUS_INTERNAL_ERROR;
		DEBUG(1, ("vfs_default_durable_reconnect: "
			  "failed to reopen brlocks: %s\n",
			  nt_errstr(status)));
		goto fail;
	}

	/*
	 * TODO: properly calculate open flags
	 */
	if (fsp->fsp_flags.can_write && fsp->fsp_flags.can_read) {
		how.flags = O_RDWR;
	} else if (fsp->fsp_flags.can_write) {
		how.flags = O_WRONLY;
	} else if (fsp->fsp_flags.can_read) {
		how.flags = O_RDONLY;
	}

	status = fd_openat(conn->cwd_fsp, fsp->fsp_name, fsp, &how);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(1, ("vfs_default_durable_reconnect: failed to open "
			  "file: %s\n", nt_errstr(status)));
		goto fail;
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
		goto fail;
	}

	if (!S_ISREG(fsp->fsp_name->st.st_ex_mode)) {
		status = NT_STATUS_OBJECT_NAME_NOT_FOUND;
		goto fail;
	}

	file_id = vfs_file_id_from_sbuf(conn, &fsp->fsp_name->st);
	if (!file_id_equal(&cookie.id, &file_id)) {
		status = NT_STATUS_OBJECT_NAME_NOT_FOUND;
		goto fail;
	}

	(void)fdos_mode(fsp);

	ok = vfs_default_durable_reconnect_check_stat(&cookie.stat_info,
						      &fsp->fsp_name->st,
						      fsp_str_dbg(fsp));
	if (!ok) {
		status = NT_STATUS_OBJECT_NAME_NOT_FOUND;
		goto fail;
	}

	status = set_file_oplock(fsp);
	if (!NT_STATUS_IS_OK(status)) {
		goto fail;
	}

	status = vfs_default_durable_cookie(fsp, mem_ctx, &new_cookie_blob);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(1, ("vfs_default_durable_reconnect: "
			  "vfs_default_durable_cookie - %s\n",
			  nt_errstr(status)));
		goto fail;
	}

	smb1req->chain_fsp = fsp;
	smb1req->smb2req->compat_chain_fsp = fsp;

	DEBUG(10, ("vfs_default_durable_reconnect: opened file '%s'\n",
		   fsp_str_dbg(fsp)));

	TALLOC_FREE(lck);

	fsp->fsp_flags.is_fsa = true;

	*result = fsp;
	*new_cookie = new_cookie_blob;

	return NT_STATUS_OK;

fail:
	if (fsp != NULL && fsp_get_pathref_fd(fsp) != -1) {
		NTSTATUS close_status;
		close_status = fd_close(fsp);
		if (!NT_STATUS_IS_OK(close_status)) {
			DBG_ERR("fd_close failed (%s), leaking fd\n",
				nt_errstr(close_status));
		}
	}
	TALLOC_FREE(lck);
	if (fsp != NULL) {
		op->compat = NULL;
		fsp->op = NULL;
		file_free(smb1req, fsp);
	}
	return status;
}
