/*
   Unix SMB/CIFS implementation.
   Core SMB2 server

   Copyright (C) Stefan Metzmacher 2009
   Copyright (C) Jeremy Allison 2010

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
#include "locking/share_mode_lock.h"
#include "smbd/smbd.h"
#include "smbd/globals.h"
#include "../libcli/smb/smb_common.h"
#include "trans2.h"
#include "../lib/util/tevent_ntstatus.h"
#include "../librpc/gen_ndr/open_files.h"
#include "source3/lib/dbwrap/dbwrap_watch.h"
#include "messages.h"
#include "librpc/gen_ndr/ndr_quota.h"
#include "libcli/security/security.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_SMB2

static struct tevent_req *smbd_smb2_setinfo_send(TALLOC_CTX *mem_ctx,
						 struct tevent_context *ev,
						 struct smbd_smb2_request *smb2req,
						 struct files_struct *in_fsp,
						 uint8_t in_info_type,
						 uint8_t in_file_info_class,
						 DATA_BLOB in_input_buffer,
						 uint32_t in_additional_information);
static NTSTATUS smbd_smb2_setinfo_recv(struct tevent_req *req);

static void smbd_smb2_request_setinfo_done(struct tevent_req *subreq);
NTSTATUS smbd_smb2_request_process_setinfo(struct smbd_smb2_request *req)
{
	struct smbXsrv_connection *xconn = req->xconn;
	NTSTATUS status;
	const uint8_t *inbody;
	uint8_t in_info_type;
	uint8_t in_file_info_class;
	uint16_t in_input_buffer_offset;
	uint32_t in_input_buffer_length;
	DATA_BLOB in_input_buffer;
	uint32_t in_additional_information;
	uint64_t in_file_id_persistent;
	uint64_t in_file_id_volatile;
	struct files_struct *in_fsp;
	struct tevent_req *subreq;

	status = smbd_smb2_request_verify_sizes(req, 0x21);
	if (!NT_STATUS_IS_OK(status)) {
		return smbd_smb2_request_error(req, status);
	}
	inbody = SMBD_SMB2_IN_BODY_PTR(req);

	in_info_type			= CVAL(inbody, 0x02);
	in_file_info_class		= CVAL(inbody, 0x03);
	in_input_buffer_length		= IVAL(inbody, 0x04);
	in_input_buffer_offset		= SVAL(inbody, 0x08);
	/* 0x0A 2 bytes reserved */
	in_additional_information	= IVAL(inbody, 0x0C);
	in_file_id_persistent		= BVAL(inbody, 0x10);
	in_file_id_volatile		= BVAL(inbody, 0x18);

	if (in_input_buffer_offset == 0 && in_input_buffer_length == 0) {
		/* This is ok */
	} else if (in_input_buffer_offset !=
		   (SMB2_HDR_BODY + SMBD_SMB2_IN_BODY_LEN(req))) {
		return smbd_smb2_request_error(req, NT_STATUS_INVALID_PARAMETER);
	}

	if (in_input_buffer_length > SMBD_SMB2_IN_DYN_LEN(req)) {
		return smbd_smb2_request_error(req, NT_STATUS_INVALID_PARAMETER);
	}

	in_input_buffer.data = SMBD_SMB2_IN_DYN_PTR(req);
	in_input_buffer.length = in_input_buffer_length;

	if (in_input_buffer.length > xconn->smb2.server.max_trans) {
		DEBUG(2,("smbd_smb2_request_process_setinfo: "
			 "client ignored max trans: %s: 0x%08X: 0x%08X\n",
			 __location__, (unsigned)in_input_buffer.length,
			 (unsigned)xconn->smb2.server.max_trans));
		return smbd_smb2_request_error(req, NT_STATUS_INVALID_PARAMETER);
	}

	status = smbd_smb2_request_verify_creditcharge(req,
						in_input_buffer.length);
	if (!NT_STATUS_IS_OK(status)) {
		return smbd_smb2_request_error(req, status);
	}

	in_fsp = file_fsp_smb2(req, in_file_id_persistent, in_file_id_volatile);
	if (in_fsp == NULL) {
		return smbd_smb2_request_error(req, NT_STATUS_FILE_CLOSED);
	}

	subreq = smbd_smb2_setinfo_send(req, req->sconn->ev_ctx,
					req, in_fsp,
					in_info_type,
					in_file_info_class,
					in_input_buffer,
					in_additional_information);
	if (subreq == NULL) {
		return smbd_smb2_request_error(req, NT_STATUS_NO_MEMORY);
	}
	tevent_req_set_callback(subreq, smbd_smb2_request_setinfo_done, req);

	/*
	 * Windows never sends async interim responses if a rename triggers a
	 * lease break. See test smb2.lease.compound_rename_middle.
	 */
	return smbd_smb2_request_pending_queue(req, subreq, 0);
}

static void smbd_smb2_request_setinfo_done(struct tevent_req *subreq)
{
	struct smbd_smb2_request *req = tevent_req_callback_data(subreq,
					struct smbd_smb2_request);
	DATA_BLOB outbody;
	NTSTATUS status;
	NTSTATUS error; /* transport error */

	status = smbd_smb2_setinfo_recv(subreq);
	TALLOC_FREE(subreq);
	if (!NT_STATUS_IS_OK(status)) {
		error = smbd_smb2_request_error(req, status);
		if (!NT_STATUS_IS_OK(error)) {
			smbd_server_connection_terminate(req->xconn,
							 nt_errstr(error));
			return;
		}
		return;
	}

	outbody = smbd_smb2_generate_outbody(req, 0x02);
	if (outbody.data == NULL) {
		error = smbd_smb2_request_error(req, NT_STATUS_NO_MEMORY);
		if (!NT_STATUS_IS_OK(error)) {
			smbd_server_connection_terminate(req->xconn,
							 nt_errstr(error));
			return;
		}
		return;
	}

	SSVAL(outbody.data, 0x00, 0x02);	/* struct size */

	error = smbd_smb2_request_done(req, outbody, NULL);
	if (!NT_STATUS_IS_OK(error)) {
		smbd_server_connection_terminate(req->xconn,
						 nt_errstr(error));
		return;
	}
}

struct smbd_smb2_setinfo_state {
	struct tevent_context *ev;
	struct smbd_smb2_request *smb2req;
	struct files_struct *fsp;
	struct share_mode_lock *lck;
	struct files_struct *dstfsp;
	struct files_struct *dst_parent_dirfsp;
	uint16_t file_info_level;
	DATA_BLOB data;
	bool delay;
	bool rename_dst_check_done;
	bool rename_dst_parent_check_done;
};

static void smbd_smb2_setinfo_lease_break_check(struct tevent_req *req);

static void smbd_smb2_setinfo_cleanup(struct tevent_req *req,
				      enum tevent_req_state req_state)
{
	struct smbd_smb2_setinfo_state *state = tevent_req_data(
		req, struct smbd_smb2_setinfo_state);

	if (req_state == TEVENT_REQ_DONE) {
		return;
	}
	TALLOC_FREE(state->lck);
}

static struct tevent_req *smbd_smb2_setinfo_send(TALLOC_CTX *mem_ctx,
						 struct tevent_context *ev,
						 struct smbd_smb2_request *smb2req,
						 struct files_struct *fsp,
						 uint8_t in_info_type,
						 uint8_t in_file_info_class,
						 DATA_BLOB in_input_buffer,
						 uint32_t in_additional_information)
{
	struct tevent_req *req = NULL;
	struct smbd_smb2_setinfo_state *state = NULL;
	struct smb_request *smbreq = NULL;
	connection_struct *conn = smb2req->tcon->compat;
	NTSTATUS status;
	int ret;

	req = tevent_req_create(mem_ctx, &state,
				struct smbd_smb2_setinfo_state);
	if (req == NULL) {
		return NULL;
	}
	state->ev = ev;
	state->smb2req = smb2req;
	state->fsp = fsp;
	state->data = in_input_buffer;

	tevent_req_set_cleanup_fn(req, smbd_smb2_setinfo_cleanup);

	DEBUG(10,("smbd_smb2_setinfo_send: %s - %s\n",
		  fsp_str_dbg(fsp), fsp_fnum_dbg(fsp)));

	smbreq = smbd_smb2_fake_smb_request(smb2req, fsp);
	if (tevent_req_nomem(smbreq, req)) {
		return tevent_req_post(req, ev);
	}

	if (IS_IPC(conn)) {
		tevent_req_nterror(req, NT_STATUS_NOT_SUPPORTED);
		return tevent_req_post(req, ev);
	}

	switch (in_info_type) {
	case SMB2_0_INFO_FILE:
	{
		uint16_t file_info_level;

		file_info_level = in_file_info_class + 1000;
		if (file_info_level == SMB_FILE_RENAME_INFORMATION) {
			/* SMB2_FILE_RENAME_INFORMATION_INTERNAL == 0xFF00 + in_file_info_class */
			file_info_level = SMB2_FILE_RENAME_INFORMATION_INTERNAL;
		}
		state->file_info_level = file_info_level;

		if (fsp_get_pathref_fd(fsp) == -1) {
			/*
			 * This is actually a SETFILEINFO on a directory
			 * handle (returned from an NT SMB). NT5.0 seems
			 * to do this call. JRA.
			 */
			ret = vfs_stat(fsp->conn, fsp->fsp_name);
			if (ret != 0) {
				DBG_WARNING("vfs_stat() of %s failed (%s)\n",
					    fsp_str_dbg(fsp),
					    strerror(errno));
				status = map_nt_error_from_unix(errno);
				tevent_req_nterror(req, status);
				return tevent_req_post(req, ev);
			}
		} else if (fsp->print_file) {
			/*
			 * Doing a DELETE_ON_CLOSE should cancel a print job.
			 */
			if ((file_info_level == SMB_SET_FILE_DISPOSITION_INFO)
			    && in_input_buffer.length >= 1
			    && CVAL(in_input_buffer.data,0)) {
				fsp->fsp_flags.delete_on_close = true;

				DEBUG(3,("smbd_smb2_setinfo_send: "
					 "Cancelling print job (%s)\n",
					 fsp_str_dbg(fsp)));

				tevent_req_done(req);
				return tevent_req_post(req, ev);
			}
			tevent_req_nterror(req, NT_STATUS_OBJECT_PATH_INVALID);
			return tevent_req_post(req, ev);
		} else {
			/*
			 * Original code - this is an open file.
			 */

			status = vfs_stat_fsp(fsp);
			if (!NT_STATUS_IS_OK(status)) {
				DEBUG(3,("smbd_smb2_setinfo_send: fstat "
					 "of %s failed (%s)\n",
					 fsp_fnum_dbg(fsp),
					 nt_errstr(status)));
				tevent_req_nterror(req, status);
				return tevent_req_post(req, ev);
			}
		}

		smbd_smb2_setinfo_lease_break_check(req);
		if (!tevent_req_is_in_progress(req)) {
			return tevent_req_post(req, ev);
		}
		SMB_ASSERT(state->delay);
		return req;
	}

	case SMB2_0_INFO_FILESYSTEM:
	{
		uint16_t file_info_level = in_file_info_class + 1000;

		status = smbd_do_setfsinfo(conn, smbreq, state,
					file_info_level,
					fsp,
					&in_input_buffer);
		if (!NT_STATUS_IS_OK(status)) {
			if (NT_STATUS_EQUAL(status, NT_STATUS_INVALID_LEVEL)) {
				status = NT_STATUS_INVALID_INFO_CLASS;
			}
			tevent_req_nterror(req, status);
			return tevent_req_post(req, ev);
		}
		break;
	}

	case SMB2_0_INFO_SECURITY:
	{
		if (!CAN_WRITE(conn)) {
			tevent_req_nterror(req, NT_STATUS_ACCESS_DENIED);
			return tevent_req_post(req, ev);
		}

		status = set_sd_blob(fsp,
				in_input_buffer.data,
				in_input_buffer.length,
				in_additional_information &
				SMB_SUPPORTED_SECINFO_FLAGS);
		if (!NT_STATUS_IS_OK(status)) {
			tevent_req_nterror(req, status);
			return tevent_req_post(req, ev);
		}
		break;
	}

	case SMB2_0_INFO_QUOTA:
	{
#ifdef HAVE_SYS_QUOTAS
		struct file_quota_information info = {0};
		SMB_NTQUOTA_STRUCT qt = {0};
		enum ndr_err_code err;

		if (!fsp->fake_file_handle) {
			tevent_req_nterror(req, NT_STATUS_INVALID_PARAMETER);
			return tevent_req_post(req, ev);
		}
		err = ndr_pull_struct_blob(
			&in_input_buffer, state, &info,
			(ndr_pull_flags_fn_t)ndr_pull_file_quota_information);
		if (!NDR_ERR_CODE_IS_SUCCESS(err)) {
			tevent_req_nterror(req, NT_STATUS_UNSUCCESSFUL);
			return tevent_req_post(req, ev);
		}

		qt.usedspace = info.quota_used;

		qt.softlim = info.quota_threshold;

		qt.hardlim = info.quota_limit;

		qt.sid = info.sid;
		ret = vfs_set_ntquota(fsp, SMB_USER_QUOTA_TYPE, &qt.sid, &qt);
		if (ret !=0 ) {
			status = map_nt_error_from_unix(errno);
			tevent_req_nterror(req, status);
			return tevent_req_post(req, ev);
		}
		status = NT_STATUS_OK;
		break;
#else
		tevent_req_nterror(req, NT_STATUS_NOT_SUPPORTED);
		return tevent_req_post(req, ev);
#endif
	}
	default:
		tevent_req_nterror(req, NT_STATUS_INVALID_PARAMETER);
		return tevent_req_post(req, ev);
	}

	tevent_req_done(req);
	return tevent_req_post(req, ev);
}

static void smbd_smb2_setinfo_lease_break_fsp_check(struct tevent_req *req);
static void smbd_smb2_setinfo_lease_break_fsp_done(struct tevent_req *subreq);
static void smbd_smb2_setinfo_rename_dst_check(struct tevent_req *req);
static void smbd_smb2_setinfo_rename_dst_delay_done(struct tevent_req *subreq);
static void smbd_smb2_setinfo_rename_dst_parent_check(struct tevent_req *req);
static void smbd_smb2_setinfo_rename_dst_parent_delay_done(
	struct tevent_req *subreq);

static void smbd_smb2_setinfo_lease_break_check(struct tevent_req *req)
{
	struct smbd_smb2_setinfo_state *state = tevent_req_data(
		req, struct smbd_smb2_setinfo_state);
	int ret_size;
	NTSTATUS status;

	state->delay = false;

	smbd_smb2_setinfo_rename_dst_check(req);
	if (!tevent_req_is_in_progress(req)) {
		return;
	}
	if (state->delay) {
		DBG_DEBUG("Waiting for h-lease breaks on rename destination\n");
		return;
	}

	smbd_smb2_setinfo_rename_dst_parent_check(req);
	if (!tevent_req_is_in_progress(req)) {
		return;
	}
	if (state->delay) {
		DBG_DEBUG("Waiting for h-lease breaks on rename destination "
			  "parent directory\n");
		return;
	}

	smbd_smb2_setinfo_lease_break_fsp_check(req);
	if (!tevent_req_is_in_progress(req)) {
		return;
	}
	if (state->delay) {
		TALLOC_FREE(state->lck);
		DBG_DEBUG("Waiting for h-lease breaks on fsp [%s]\n",
			  fsp_str_dbg(state->fsp));
		return;
	}

	status = smbd_do_setfilepathinfo(state->fsp->conn,
					 state->smb2req->smb1req,
					 state,
					 state->file_info_level,
					 state->fsp,
					 &state->lck,
					 state->fsp->fsp_name,
					 (char *)state->data.data,
					 state->data.length,
					 &ret_size);
	TALLOC_FREE(state->lck);
	if (!NT_STATUS_IS_OK(status)) {
		if (NT_STATUS_EQUAL(status, NT_STATUS_INVALID_LEVEL)) {
			status = NT_STATUS_INVALID_INFO_CLASS;
		}
		tevent_req_nterror(req, status);
		return;
	}

	tevent_req_done(req);
}

static void smbd_smb2_setinfo_lease_break_fsp_check(struct tevent_req *req)
{
	struct smbd_smb2_setinfo_state *state = tevent_req_data(
		req, struct smbd_smb2_setinfo_state);
	struct smbd_smb2_request *smb2req = state->smb2req;
	struct files_struct *fsp = state->fsp;
	uint16_t file_info_level = state->file_info_level;
	struct tevent_req *subreq = NULL;
	struct timeval timeout;
	bool rename;
	bool delete_on_close = false;
	NTSTATUS status;

	rename = (file_info_level == SMB2_FILE_RENAME_INFORMATION_INTERNAL);

	if (file_info_level == SMB_FILE_DISPOSITION_INFORMATION) {
		status = smb_check_file_disposition_info(
			fsp,
			(char *)state->data.data,
			state->data.length,
			&delete_on_close);
		if (tevent_req_nterror(req, status)) {
			return;
		}
	}

	if (!rename && !delete_on_close) {
		return;
	}

	state->lck = get_existing_share_mode_lock(state, fsp->file_id);
	if (state->lck == NULL) {
		tevent_req_nterror(req, NT_STATUS_UNSUCCESSFUL);
		return;
	}

	timeout = tevent_timeval_set(OPLOCK_BREAK_TIMEOUT, 0);
	timeout = timeval_sum(&smb2req->request_time, &timeout);

	subreq = delay_for_handle_lease_break_send(state,
						   state->ev,
						   timeout,
						   fsp,
						   SEC_RIGHTS_DIR_ALL,
						   rename,
						   &state->lck);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	if (tevent_req_is_in_progress(subreq)) {
		state->delay = true;
		tevent_req_set_callback(subreq,
					smbd_smb2_setinfo_lease_break_fsp_done,
					req);
		return;
	}

	status = delay_for_handle_lease_break_recv(subreq, state, &state->lck);
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		return;
	}
}

static void smbd_smb2_setinfo_lease_break_fsp_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct smbd_smb2_setinfo_state *state = tevent_req_data(
		req, struct smbd_smb2_setinfo_state);
	int ret_size;
	NTSTATUS status;
	bool ok;

	status = delay_for_handle_lease_break_recv(subreq, state, &state->lck);
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		return;
	}

	/*
	 * Make sure we run as the user again
	 */
	ok = change_to_user_and_service(
		state->smb2req->tcon->compat,
		state->smb2req->session->global->session_wire_id);
	if (!ok) {
		tevent_req_nterror(req, NT_STATUS_ACCESS_DENIED);
		return;
	}

	/* Do the setinfo again under the lock. */
	status = smbd_do_setfilepathinfo(state->fsp->conn,
				state->smb2req->smb1req,
				state,
				state->file_info_level,
				state->fsp,
				&state->lck,
				state->fsp->fsp_name,
				(char *)state->data.data,
				state->data.length,
				&ret_size);
	TALLOC_FREE(state->lck);
	if (tevent_req_nterror(req, status)) {
		return;
	}

	tevent_req_done(req);
}

static void smbd_smb2_setinfo_rename_dst_check(struct tevent_req *req)
{
	struct smbd_smb2_setinfo_state *state = tevent_req_data(
		req, struct smbd_smb2_setinfo_state);
	struct tevent_req *subreq = NULL;
	struct timeval timeout;
	char *newname = NULL;
	bool overwrite = false;
	struct files_struct *fsp = state->fsp;
	struct files_struct *dst_dirfsp = NULL;
	struct smb_filename *smb_fname_dst = NULL;
	bool has_other_open;
	NTSTATUS status;
	NTSTATUS close_status;

	if (state->file_info_level != SMB2_FILE_RENAME_INFORMATION_INTERNAL) {
		return;
	}

	if (state->rename_dst_check_done) {
		return;
	}

	status = smb2_parse_file_rename_information(state,
						    fsp->conn,
						    state->smb2req->smb1req,
						    (char *)state->data.data,
						    state->data.length,
						    fsp,
						    fsp->fsp_name,
						    &newname,
						    &overwrite,
						    &dst_dirfsp,
						    &smb_fname_dst);
	if (tevent_req_nterror(req, status)) {
		return;
	}

	if (!VALID_STAT(smb_fname_dst->st)) {
		/* Doesn't exist, nothing to do here */
		return;
	}
	if (strequal(fsp->fsp_name->base_name, smb_fname_dst->base_name) &&
	    strequal(fsp->fsp_name->stream_name, smb_fname_dst->stream_name))
	{
		return;
	}
	if (!overwrite) {
		/* Return the correct error */
		tevent_req_nterror(req, NT_STATUS_OBJECT_NAME_COLLISION);
		return;
	}

	status = SMB_VFS_CREATE_FILE(
		fsp->conn,
		NULL,
		dst_dirfsp,
		smb_fname_dst,
		FILE_READ_ATTRIBUTES,
		FILE_SHARE_READ
		| FILE_SHARE_WRITE
		| FILE_SHARE_DELETE,
		FILE_OPEN,		/* create_disposition*/
		0,			/* create_options */
		FILE_ATTRIBUTE_NORMAL,
		INTERNAL_OPEN_ONLY,	/* oplock_request */
		NULL,			/* lease */
		0,			/* allocation_size */
		0,			/* private_flags */
		NULL,			/* sd */
		NULL,			/* ea_list */
		&state->dstfsp,		/* result */
		NULL,			/* psbuf */
		NULL,
		NULL);			/* create context */
	if (!NT_STATUS_IS_OK(status)) {
		if (NT_STATUS_EQUAL(status, NT_STATUS_OBJECT_NAME_NOT_FOUND)) {
			/* A race, file was deleted */
			return;
		}
		tevent_req_nterror(req, status);
		return;
	}

	state->lck = get_existing_share_mode_lock(state, state->dstfsp->file_id);
	if (state->lck == NULL) {
		close_status = close_file_free(NULL, &state->dstfsp, ERROR_CLOSE);
		if (!NT_STATUS_IS_OK(close_status)) {
			DBG_ERR("close_file_free failed\n");
		}
		return;
	}

	timeout = tevent_timeval_set(OPLOCK_BREAK_TIMEOUT, 0);
	timeout = timeval_sum(&state->smb2req->request_time, &timeout);

	subreq = delay_for_handle_lease_break_send(state,
						   state->ev,
						   timeout,
						   state->dstfsp,
						   SEC_RIGHTS_DIR_ALL,
						   false,
						   &state->lck);
	if (subreq == NULL) {
		close_status = close_file_free(NULL, &state->dstfsp, ERROR_CLOSE);
		if (!NT_STATUS_IS_OK(close_status)) {
			DBG_ERR("close_file_free failed\n");
		}
		tevent_req_nterror(req, NT_STATUS_NO_MEMORY);
		return;
	}
	if (tevent_req_is_in_progress(subreq)) {
		state->delay = true;
		tevent_req_set_callback(subreq,
					smbd_smb2_setinfo_rename_dst_delay_done,
					req);
		return;
	}

	status = delay_for_handle_lease_break_recv(subreq, state, &state->lck);
	TALLOC_FREE(subreq);
	if (!NT_STATUS_IS_OK(status)) {
		close_status = close_file_free(NULL, &state->dstfsp, ERROR_CLOSE);
		if (!NT_STATUS_IS_OK(close_status)) {
			DBG_ERR("close_file_free failed\n");
		}
		tevent_req_nterror(req, status);
		return;
	}

	has_other_open = has_other_nonposix_opens(state->lck, state->dstfsp);
	TALLOC_FREE(state->lck);

	status = close_file_free(NULL, &state->dstfsp, NORMAL_CLOSE);
	if (tevent_req_nterror(req, status)) {
		DBG_ERR("close_file_free failed\n");
		return;
	}

	if (has_other_open) {
		tevent_req_nterror(req, NT_STATUS_ACCESS_DENIED);
		return;
	}
	state->rename_dst_check_done = true;
	return;
}

static void smbd_smb2_setinfo_rename_dst_delay_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct smbd_smb2_setinfo_state *state = tevent_req_data(
		req, struct smbd_smb2_setinfo_state);
	struct smbXsrv_session *session = state->smb2req->session;
	bool has_other_open;
	NTSTATUS close_status;
	NTSTATUS status;
	bool ok;

	status = delay_for_handle_lease_break_recv(subreq, state, &state->lck);
	TALLOC_FREE(subreq);
	if (!NT_STATUS_IS_OK(status)) {
		close_status = close_file_free(NULL,
					       &state->dstfsp,
					       NORMAL_CLOSE);
		if (!NT_STATUS_IS_OK(close_status)) {
			DBG_ERR("close_file_free failed\n");
		}
		tevent_req_nterror(req, status);
		return;
	}

	/*
	 * Make sure we run as the user again
	 */
	ok = change_to_user_and_service(state->dstfsp->conn,
					session->global->session_wire_id);
	if (!ok) {
		close_status = close_file_free(NULL,
					       &state->dstfsp,
					       NORMAL_CLOSE);
		if (!NT_STATUS_IS_OK(close_status)) {
			DBG_ERR("close_file_free failed\n");
		}
		tevent_req_nterror(req, NT_STATUS_ACCESS_DENIED);
		return;
	}

	has_other_open = has_other_nonposix_opens(state->lck, state->dstfsp);
	TALLOC_FREE(state->lck);

	status = close_file_free(NULL, &state->dstfsp, NORMAL_CLOSE);
	if (tevent_req_nterror(req, status)) {
		DBG_ERR("close_file_free failed\n");
		return;
	}

	if (has_other_open) {
		tevent_req_nterror(req, NT_STATUS_ACCESS_DENIED);
		return;
	}

	/*
	 * We've finished breaking H-lease on the rename destination, now
	 * trigger the fsp check.
	 */
	state->rename_dst_check_done = true;
	smbd_smb2_setinfo_lease_break_check(req);
}

static void smbd_smb2_setinfo_rename_dst_parent_check(struct tevent_req *req)
{
	struct smbd_smb2_setinfo_state *state = tevent_req_data(
		req, struct smbd_smb2_setinfo_state);
	struct tevent_req *subreq = NULL;
	struct timeval timeout;
	char *newname = NULL;
	bool overwrite = false;
	struct files_struct *fsp = state->fsp;
	struct files_struct *dst_parent_dirfsp = NULL;
	struct smb_filename *smb_fname_dst = NULL;
	NTSTATUS status;

	if (state->rename_dst_parent_check_done) {
		return;
	}
	state->rename_dst_parent_check_done = true;

	if (state->file_info_level != SMB2_FILE_RENAME_INFORMATION_INTERNAL) {
		return;
	}
	if (is_named_stream(fsp->fsp_name)) {
		return;
	}
	status = smb2_parse_file_rename_information(state,
						    fsp->conn,
						    state->smb2req->smb1req,
						    (char *)state->data.data,
						    state->data.length,
						    fsp,
						    fsp->fsp_name,
						    &newname,
						    &overwrite,
						    &dst_parent_dirfsp,
						    &smb_fname_dst);
	if (tevent_req_nterror(req, status)) {
		return;
	}
	SMB_ASSERT(dst_parent_dirfsp != NULL);
	state->dst_parent_dirfsp = dst_parent_dirfsp;

	state->lck = get_existing_share_mode_lock(state,
						  dst_parent_dirfsp->file_id);
	if (state->lck == NULL) {
		/* No opens around */
		return;
	}

	timeout = tevent_timeval_set(OPLOCK_BREAK_TIMEOUT, 0);
	timeout = timeval_sum(&state->smb2req->request_time, &timeout);

	subreq = delay_for_handle_lease_break_send(state,
						   state->ev,
						   timeout,
						   dst_parent_dirfsp,
						   SEC_STD_DELETE,
						   false,
						   &state->lck);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	if (tevent_req_is_in_progress(subreq)) {
		state->delay = true;
		tevent_req_set_callback(
			subreq,
			smbd_smb2_setinfo_rename_dst_parent_delay_done,
			req);
		return;
	}

	status = delay_for_handle_lease_break_recv(subreq, state, &state->lck);
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		return;
	}

	if (state->lck != NULL) {
		bool delete_open;
		bool detete_pending;
		bool ok;

		ok = has_delete_opens(dst_parent_dirfsp,
				      state->lck,
				      &delete_open,
				      &detete_pending);
		TALLOC_FREE(state->lck);
		if (!ok) {
			tevent_req_nterror(req, NT_STATUS_INTERNAL_ERROR);
			return;
		}

		if (detete_pending) {
			tevent_req_nterror(req, NT_STATUS_DELETE_PENDING);
			return;
		}
		if (delete_open) {
			tevent_req_nterror(req, NT_STATUS_SHARING_VIOLATION);
			return;
		}
	}

	return;
}

static void smbd_smb2_setinfo_rename_dst_parent_delay_done(
	struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct smbd_smb2_setinfo_state *state = tevent_req_data(
		req, struct smbd_smb2_setinfo_state);
	struct smbXsrv_session *session = state->smb2req->session;
	NTSTATUS status;
	bool ok;

	status = delay_for_handle_lease_break_recv(subreq, state, &state->lck);
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		return;
	}

	/*
	 * Make sure we run as the user again
	 */
	ok = change_to_user_and_service(state->fsp->conn,
					session->global->session_wire_id);
	if (!ok) {
		tevent_req_nterror(req, NT_STATUS_ACCESS_DENIED);
		return;
	}

	if (state->lck != NULL) {
		bool delete_open;
		bool detete_pending;

		ok = has_delete_opens(state->dst_parent_dirfsp,
				      state->lck,
				      &delete_open,
				      &detete_pending);
		TALLOC_FREE(state->lck);
		if (!ok) {
			tevent_req_nterror(req, NT_STATUS_INTERNAL_ERROR);
			return;
		}

		if (detete_pending) {
			tevent_req_nterror(req, NT_STATUS_DELETE_PENDING);
			return;
		}
		if (delete_open) {
			tevent_req_nterror(req, NT_STATUS_SHARING_VIOLATION);
			return;
		}
	}

	/*
	 * We've finished breaking H-lease on the rename destination, now
	 * trigger the fsp check.
	 */
	state->rename_dst_parent_check_done = true;
	smbd_smb2_setinfo_lease_break_check(req);
}

static NTSTATUS smbd_smb2_setinfo_recv(struct tevent_req *req)
{
	NTSTATUS status;

	if (tevent_req_is_nterror(req, &status)) {
		tevent_req_received(req);
		return status;
	}

	tevent_req_received(req);
	return NT_STATUS_OK;
}
