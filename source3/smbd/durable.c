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
	cookie.write_time_forced = fsp->fsp_flags.write_time_forced;

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

	if (CHECK_DEBUGLVL(DBGLVL_DEBUG)) {
		DBG_DEBUG("Fresh cookie\n");
		NDR_PRINT_DEBUG(vfs_default_durable_cookie, &cookie);
	}

	ndr_err = ndr_push_struct_blob(cookie_blob, mem_ctx, &cookie,
			(ndr_push_flags_fn_t)ndr_push_vfs_default_durable_cookie);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		NTSTATUS status = ndr_map_error2ntstatus(ndr_err);
		return status;
	}

	return NT_STATUS_OK;
}

struct durable_disconnect_state {
	NTSTATUS status;
	struct files_struct *fsp;
};

static void default_durable_disconnect_fn(struct share_mode_lock *lck,
					  struct byte_range_lock *br_lck,
					  void *private_data)
{
	struct durable_disconnect_state *state = private_data;
	struct files_struct *fsp = state->fsp;
	bool ok;

	ok = mark_share_mode_disconnected(lck, fsp);
	if (!ok) {
		state->status = NT_STATUS_UNSUCCESSFUL;
		return;
	}

	if (br_lck == NULL) {
		state->status = NT_STATUS_OK;
		return;
	}

	ok = brl_mark_disconnected(fsp, br_lck);
	if (!ok) {
		state->status = NT_STATUS_UNSUCCESSFUL;
		return;
	}
	state->status = NT_STATUS_OK;
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
	struct durable_disconnect_state state;

	*new_cookie = data_blob_null;

	ZERO_STRUCT(cookie);

	ndr_err = ndr_pull_struct_blob(&old_cookie, talloc_tos(), &cookie,
			(ndr_pull_flags_fn_t)ndr_pull_vfs_default_durable_cookie);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		status = ndr_map_error2ntstatus(ndr_err);
		return status;
	}

	if (CHECK_DEBUGLVL(DBGLVL_DEBUG)) {
		DBG_DEBUG("Old cookie\n");
		NDR_PRINT_DEBUG(vfs_default_durable_cookie, &cookie);
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

	if (fsp->current_lock_count != 0 &&
	    (fsp_lease_type(fsp) & SMB2_LEASE_WRITE) == 0)
	{
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

	state = (struct durable_disconnect_state) {
		.fsp = fsp,
	};

	status = share_mode_do_locked_brl(fsp,
					  default_durable_disconnect_fn,
					  &state);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("share_mode_do_locked_brl [%s] failed: %s\n",
			fsp_str_dbg(fsp), nt_errstr(status));
		return status;
	}
	if (!NT_STATUS_IS_OK(state.status)) {
		DBG_ERR("default_durable_disconnect_fn [%s] failed: %s\n",
			fsp_str_dbg(fsp), nt_errstr(state.status));
		return state.status;
	}

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
	cookie.write_time_forced = fsp->fsp_flags.write_time_forced;

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

	if (CHECK_DEBUGLVL(DBGLVL_DEBUG)) {
		DBG_DEBUG("New cookie\n");
		NDR_PRINT_DEBUG(vfs_default_durable_cookie, &cookie);
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

struct durable_reconnect_state {
	struct smbXsrv_open *op;
	struct share_mode_entry *e;
};

static bool durable_reconnect_fn(
	struct share_mode_entry *e,
	bool *modified,
	void *private_data)
{
	struct durable_reconnect_state *state = private_data;
	uint64_t id = state->op->global->open_persistent_id;

	if (e->share_file_id != id) {
		return false; /* Look at potential other entries */
	}

	if (!server_id_is_disconnected(&e->pid)) {
		return false; /* Look at potential other entries */
	}

	if (state->e->share_file_id == id) {
		DBG_INFO("Found more than one entry, invalidating previous\n");
		*state->e = (struct share_mode_entry) { .pid = { .pid = 0, }};
		return true;	/* end the loop through share mode entries */
	}
	*state->e = *e;
	return false;		/* Look at potential other entries */
}

struct vfs_default_durable_reconnect_state {
	NTSTATUS status;
	TALLOC_CTX *mem_ctx;
	struct smb_request *smb1req;
	struct smbXsrv_open *op;
	struct vfs_default_durable_cookie cookie;
	struct files_struct *fsp;
	struct files_struct *dirfsp;
	struct smb_filename *rel_fname;
	DATA_BLOB new_cookie_blob;
};

static void vfs_default_durable_reconnect_fn(struct share_mode_lock *lck,
					     struct byte_range_lock *br_lck,
					     void *private_data)
{
	struct vfs_default_durable_reconnect_state *state = private_data;
	const struct loadparm_substitution *lp_sub =
		loadparm_s3_global_substitution();
	struct files_struct *fsp = state->fsp;
	struct share_mode_entry e = { .pid = { .pid = 0, }};
	struct durable_reconnect_state rstate = { .op = state->op, .e = &e, };
	struct vfs_open_how how = { .flags = 0, };
	struct file_id file_id;
	bool have_share_mode_entry = false;
	int ret;
	bool ok;

	ok = share_mode_forall_entries(lck, durable_reconnect_fn, &rstate);
	if (!ok) {
		DBG_WARNING("share_mode_forall_entries failed\n");
		state->status = NT_STATUS_INTERNAL_DB_ERROR;
		goto fail;
	}

	if (e.pid.pid == 0) {
		DBG_WARNING("Did not find a unique valid share mode entry\n");
		state->status = NT_STATUS_OBJECT_NAME_NOT_FOUND;
		goto fail;
	}

	if (!server_id_is_disconnected(&e.pid)) {
		DEBUG(5, ("vfs_default_durable_reconnect: denying durable "
			  "reconnect for handle that was not marked "
			  "disconnected (e.g. smbd or cluster node died)\n"));
		state->status = NT_STATUS_OBJECT_NAME_NOT_FOUND;
		goto fail;
	}

	if (e.share_file_id != state->op->global->open_persistent_id) {
		DBG_INFO("denying durable "
			 "share_file_id changed %"PRIu64" != %"PRIu64" "
			 "(e.g. another client had opened the file)\n",
			 e.share_file_id,
			 state->op->global->open_persistent_id);
		state->status = NT_STATUS_OBJECT_NAME_NOT_FOUND;
		goto fail;
	}

	if ((e.access_mask & (FILE_WRITE_DATA|FILE_APPEND_DATA)) &&
	    !CAN_WRITE(fsp->conn))
	{
		DEBUG(5, ("vfs_default_durable_reconnect: denying durable "
			  "share[%s] is not writeable anymore\n",
			  lp_servicename(talloc_tos(), lp_sub, SNUM(fsp->conn))));
		state->status = NT_STATUS_OBJECT_NAME_NOT_FOUND;
		goto fail;
	}

	fsp_apply_share_entry_flags(fsp, e.flags);
	fsp->open_time = e.time;
	fsp->access_mask = e.access_mask;
	fsp->fsp_flags.can_read = ((fsp->access_mask & FILE_READ_DATA) != 0);
	fsp->fsp_flags.can_write = ((fsp->access_mask & (FILE_WRITE_DATA|FILE_APPEND_DATA)) != 0);

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
			state->status = NT_STATUS_OBJECT_NAME_NOT_FOUND;
			goto fail;
		}

		state->status = leases_db_get(
			&e.client_guid,
			&e.lease_key,
			&fsp->file_id,
			&current_state, /* current_state */
			NULL, /* breaking */
			NULL, /* breaking_to_requested */
			NULL, /* breaking_to_required */
			&lease_version, /* lease_version */
			&epoch); /* epoch */
		if (!NT_STATUS_IS_OK(state->status)) {
			goto fail;
		}

		fsp->lease = find_fsp_lease(
			fsp,
			&e.lease_key,
			current_state,
			lease_version,
			epoch);
		if (fsp->lease == NULL) {
			state->status = NT_STATUS_NO_MEMORY;
			goto fail;
		}
	}

	fsp->initial_allocation_size = state->cookie.initial_allocation_size;
	fh_set_position_information(fsp->fh, state->cookie.position_information);
	fsp->fsp_flags.write_time_forced = state->cookie.write_time_forced;

	state->op->compat = fsp;
	fsp->op = state->op;

	ok = reset_share_mode_entry(
		lck,
		e.pid,
		e.share_file_id,
		messaging_server_id(fsp->conn->sconn->msg_ctx),
		state->smb1req->mid);
	if (!ok) {
		DBG_DEBUG("Could not set new share_mode_entry values\n");
		state->status = NT_STATUS_INTERNAL_ERROR;
		goto fail;
	}
	have_share_mode_entry = true;

	if (br_lck != NULL) {
		ok = brl_reconnect_disconnected(fsp, br_lck);
		if (!ok) {
			state->status = NT_STATUS_INTERNAL_ERROR;
			DBG_ERR("failed to reopen brlocks: %s\n",
				nt_errstr(state->status));
			goto fail;
		}
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

	state->status = fd_openat(state->dirfsp, state->rel_fname, fsp, &how);
	if (!NT_STATUS_IS_OK(state->status)) {
		DBG_ERR("failed to open file: %s\n", nt_errstr(state->status));
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
		state->status = map_nt_error_from_unix_common(errno);
		DBG_ERR("Unable to fstat stream: %s => %s\n",
			fsp_str_dbg(fsp),
			nt_errstr(state->status));
		goto fail;
	}

	if (!S_ISREG(fsp->fsp_name->st.st_ex_mode)) {
		state->status = NT_STATUS_OBJECT_NAME_NOT_FOUND;
		goto fail;
	}

	file_id = vfs_file_id_from_sbuf(fsp->conn, &fsp->fsp_name->st);
	if (!file_id_equal(&state->cookie.id, &file_id)) {
		state->status = NT_STATUS_OBJECT_NAME_NOT_FOUND;
		goto fail;
	}

	(void)fdos_mode(fsp);

	ok = vfs_default_durable_reconnect_check_stat(&state->cookie.stat_info,
						      &fsp->fsp_name->st,
						      fsp_str_dbg(fsp));
	if (!ok) {
		state->status = NT_STATUS_OBJECT_NAME_NOT_FOUND;
		goto fail;
	}

	state->status = set_file_oplock(fsp);
	if (!NT_STATUS_IS_OK(state->status)) {
		goto fail;
	}

	state->status = vfs_default_durable_cookie(fsp,
						   state->mem_ctx,
						   &state->new_cookie_blob);
	if (!NT_STATUS_IS_OK(state->status)) {
		DBG_ERR("vfs_default_durable_cookie - %s\n",
			nt_errstr(state->status));
		goto fail;
	}

	state->smb1req->chain_fsp = fsp;
	state->smb1req->smb2req->compat_chain_fsp = fsp;

	DBG_DEBUG("opened file '%s'\n", fsp_str_dbg(fsp));

	fsp->fsp_flags.is_fsa = true;

	state->status = NT_STATUS_OK;
	return;

fail:
	if (have_share_mode_entry) {
		/*
		 * Something is screwed up, delete the sharemode entry.
		 */
		del_share_mode(lck, fsp);
	}
	if (fsp_get_pathref_fd(fsp) != -1) {
		NTSTATUS close_status;
		close_status = fd_close(fsp);
		if (!NT_STATUS_IS_OK(close_status)) {
			DBG_ERR("fd_close failed (%s), leaking fd\n",
				nt_errstr(close_status));
		}
	}
	state->op->compat = NULL;
	fsp->op = NULL;
}

NTSTATUS vfs_default_durable_reconnect(struct connection_struct *conn,
				       struct smb_request *smb1req,
				       struct smbXsrv_open *op,
				       const DATA_BLOB old_cookie,
				       TALLOC_CTX *mem_ctx,
				       files_struct **result,
				       DATA_BLOB *new_cookie)
{
	struct vfs_default_durable_reconnect_state state;
	struct smb_filename *smb_fname = NULL;
	struct file_id file_id;
	NTSTATUS status;
	enum ndr_err_code ndr_err;
	bool ok;

	*result = NULL;
	*new_cookie = data_blob_null;

	if (!lp_durable_handles(SNUM(conn))) {
		return NT_STATUS_NOT_SUPPORTED;
	}

	state = (struct vfs_default_durable_reconnect_state) {
		.mem_ctx = mem_ctx,
		.smb1req = smb1req,
		.op = op,
	};

	/*
	 * the checks for kernel oplocks
	 * and similar things are done
	 * in the vfs_default_durable_cookie()
	 * call below.
	 */

	ndr_err = ndr_pull_struct_blob_all(
		&old_cookie,
		talloc_tos(),
		&state.cookie,
		(ndr_pull_flags_fn_t)ndr_pull_vfs_default_durable_cookie);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		status = ndr_map_error2ntstatus(ndr_err);
		return status;
	}

	if (CHECK_DEBUGLVL(DBGLVL_DEBUG)) {
		DBG_DEBUG("Cookie:\n");
		NDR_PRINT_DEBUG(vfs_default_durable_cookie, &state.cookie);
	}

	if (strcmp(state.cookie.magic, VFS_DEFAULT_DURABLE_COOKIE_MAGIC) != 0) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	if (state.cookie.version != VFS_DEFAULT_DURABLE_COOKIE_VERSION) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	if (!state.cookie.allow_reconnect) {
		return NT_STATUS_OBJECT_NAME_NOT_FOUND;
	}

	if (strcmp(state.cookie.servicepath, conn->connectpath) != 0) {
		return NT_STATUS_OBJECT_NAME_NOT_FOUND;
	}

	status = filename_convert_dirfsp_rel(talloc_tos(),
					     conn,
					     conn->cwd_fsp,
					     state.cookie.base_name,
					     UCF_LCOMP_LNK_OK,
					     0,
					     &state.dirfsp,
					     &smb_fname,
					     &state.rel_fname);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}
	if (!VALID_STAT(smb_fname->st)) {
		return NT_STATUS_OBJECT_NAME_NOT_FOUND;
	}
	if (!S_ISREG(smb_fname->st.st_ex_mode)) {
		return NT_STATUS_OBJECT_NAME_NOT_FOUND;
	}

	file_id = vfs_file_id_from_sbuf(conn, &smb_fname->st);
	if (!file_id_equal(&state.cookie.id, &file_id)) {
		return NT_STATUS_OBJECT_NAME_NOT_FOUND;
	}

	state.fsp = fsp_new(conn, conn);
	if (state.fsp == NULL) {
		DBG_ERR("failed to create new fsp\n");
		return NT_STATUS_NO_MEMORY;
	}
	state.fsp->file_id = file_id;
	state.fsp->file_pid = smb1req->smbpid;
	state.fsp->vuid = smb1req->vuid;
	state.fsp->fnum = op->local_id;
	fh_set_gen_id(state.fsp->fh, op->global->open_global_id);

	ok = fsp_set_smb_fname(state.fsp, smb_fname);
	if (!ok) {
		DBG_ERR("fsp_set_smb_fname failed\n");
		file_free(smb1req, state.fsp);
		return NT_STATUS_NO_MEMORY;
	}

	/*
	 * TODO:
	 * Do we need to store the modified flag in the DB?
	 */
	state.fsp->fsp_flags.modified = false;
	/*
	 * no durables for directories
	 */
	state.fsp->fsp_flags.is_directory = false;
	/*
	 * For normal files, can_lock == !is_directory
	 */
	state.fsp->fsp_flags.can_lock = true;
	/*
	 * We do not support aio write behind for smb2
	 */
	state.fsp->fsp_flags.aio_write_behind = false;

	status = share_mode_do_locked_brl(state.fsp,
					  vfs_default_durable_reconnect_fn,
					  &state);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("share_mode_do_locked_brl [%s] failed: %s\n",
			smb_fname_str_dbg(smb_fname), nt_errstr(status));
		file_free(smb1req, state.fsp);
		return status;
	}
	if (!NT_STATUS_IS_OK(state.status)) {
		DBG_ERR("default_durable_reconnect_fn [%s] failed: %s\n",
			smb_fname_str_dbg(smb_fname),
			nt_errstr(state.status));
		file_free(smb1req, state.fsp);
		return state.status;
	}

	*result = state.fsp;
	*new_cookie = state.new_cookie_blob;

	return NT_STATUS_OK;
}
