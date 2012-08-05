/*
   Unix SMB/CIFS implementation.
   Core SMB2 server

   Copyright (C) Stefan Metzmacher 2009

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
#include "smbd/globals.h"
#include "../libcli/smb/smb_common.h"
#include "../lib/util/tevent_ntstatus.h"
#include "lib/tevent_wait.h"

static struct tevent_req *smbd_smb2_close_send(TALLOC_CTX *mem_ctx,
					       struct tevent_context *ev,
					       struct smbd_smb2_request *smb2req,
					       struct files_struct *in_fsp,
					       uint16_t in_flags);
static NTSTATUS smbd_smb2_close_recv(struct tevent_req *req,
				     uint16_t *out_flags,
				     NTTIME *out_creation_time,
				     NTTIME *out_last_access_time,
				     NTTIME *out_last_write_time,
				     NTTIME *out_change_time,
				     uint64_t *out_allocation_size,
				     uint64_t *out_end_of_file,
				     uint32_t *out_file_attributes);

static void smbd_smb2_request_close_done(struct tevent_req *subreq);

NTSTATUS smbd_smb2_request_process_close(struct smbd_smb2_request *req)
{
	const uint8_t *inbody;
	uint16_t in_flags;
	uint64_t in_file_id_persistent;
	uint64_t in_file_id_volatile;
	struct files_struct *in_fsp;
	NTSTATUS status;
	struct tevent_req *subreq;

	status = smbd_smb2_request_verify_sizes(req, 0x18);
	if (!NT_STATUS_IS_OK(status)) {
		return smbd_smb2_request_error(req, status);
	}
	inbody = SMBD_SMB2_IN_BODY_PTR(req);

	in_flags		= SVAL(inbody, 0x02);
	in_file_id_persistent	= BVAL(inbody, 0x08);
	in_file_id_volatile	= BVAL(inbody, 0x10);

	in_fsp = file_fsp_smb2(req, in_file_id_persistent, in_file_id_volatile);
	if (in_fsp == NULL) {
		return smbd_smb2_request_error(req, NT_STATUS_FILE_CLOSED);
	}

	subreq = smbd_smb2_close_send(req, req->sconn->ev_ctx,
				      req, in_fsp, in_flags);
	if (subreq == NULL) {
		return smbd_smb2_request_error(req, NT_STATUS_NO_MEMORY);
	}
	tevent_req_set_callback(subreq, smbd_smb2_request_close_done, req);

	return smbd_smb2_request_pending_queue(req, subreq, 500);
}

static void smbd_smb2_request_close_done(struct tevent_req *subreq)
{
	struct smbd_smb2_request *req =
		tevent_req_callback_data(subreq,
		struct smbd_smb2_request);
	DATA_BLOB outbody;
	uint16_t out_flags;
	NTTIME out_creation_time;
	NTTIME out_last_access_time;
	NTTIME out_last_write_time;
	NTTIME out_change_time;
	uint64_t out_allocation_size;
	uint64_t out_end_of_file;
	uint32_t out_file_attributes;
	NTSTATUS status;
	NTSTATUS error;

	status = smbd_smb2_close_recv(subreq,
				      &out_flags,
				      &out_creation_time,
				      &out_last_access_time,
				      &out_last_write_time,
				      &out_change_time,
				      &out_allocation_size,
				      &out_end_of_file,
				      &out_file_attributes);
	TALLOC_FREE(subreq);
	if (!NT_STATUS_IS_OK(status)) {
		error = smbd_smb2_request_error(req, status);
		if (!NT_STATUS_IS_OK(error)) {
			smbd_server_connection_terminate(req->sconn,
							 nt_errstr(error));
			return;
		}
		return;
	}

	outbody = data_blob_talloc(req->out.vector, NULL, 0x3C);
	if (outbody.data == NULL) {
		error = smbd_smb2_request_error(req, NT_STATUS_NO_MEMORY);
		if (!NT_STATUS_IS_OK(error)) {
			smbd_server_connection_terminate(req->sconn,
							 nt_errstr(error));
			return;
		}
		return;
	}

	SSVAL(outbody.data, 0x00, 0x3C);	/* struct size */
	SSVAL(outbody.data, 0x02, out_flags);
	SIVAL(outbody.data, 0x04, 0);		/* reserved */
	SBVAL(outbody.data, 0x08, out_creation_time);
	SBVAL(outbody.data, 0x10, out_last_access_time);
	SBVAL(outbody.data, 0x18, out_last_write_time);
	SBVAL(outbody.data, 0x20, out_change_time);
	SBVAL(outbody.data, 0x28, out_allocation_size);
	SBVAL(outbody.data, 0x30, out_end_of_file);
	SIVAL(outbody.data, 0x38, out_file_attributes);

	error = smbd_smb2_request_done(req, outbody, NULL);
	if (!NT_STATUS_IS_OK(error)) {
		smbd_server_connection_terminate(req->sconn,
						 nt_errstr(error));
		return;
	}
}

static NTSTATUS smbd_smb2_close(struct smbd_smb2_request *req,
				struct files_struct *fsp,
				uint16_t in_flags,
				uint16_t *out_flags,
				NTTIME *out_creation_time,
				NTTIME *out_last_access_time,
				NTTIME *out_last_write_time,
				NTTIME *out_change_time,
				uint64_t *out_allocation_size,
				uint64_t *out_end_of_file,
				uint32_t *out_file_attributes)
{
	NTSTATUS status;
	struct smb_request *smbreq;
	connection_struct *conn = req->tcon->compat;
	struct smb_filename *smb_fname = NULL;
	struct timespec mdate_ts, adate_ts, cdate_ts, create_date_ts;
	uint64_t allocation_size = 0;
	uint64_t file_size = 0;
	uint32_t dos_attrs = 0;
	uint16_t flags = 0;
	bool posix_open = false;

	ZERO_STRUCT(create_date_ts);
	ZERO_STRUCT(adate_ts);
	ZERO_STRUCT(mdate_ts);
	ZERO_STRUCT(cdate_ts);

	*out_flags = 0;
	*out_creation_time = 0;
	*out_last_access_time = 0;
	*out_last_write_time = 0;
	*out_change_time = 0;
	*out_allocation_size = 0;
	*out_end_of_file = 0;
	*out_file_attributes = 0;

	DEBUG(10,("smbd_smb2_close: %s - %s\n",
		  fsp_str_dbg(fsp), fsp_fnum_dbg(fsp)));

	smbreq = smbd_smb2_fake_smb_request(req);
	if (smbreq == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	posix_open = fsp->posix_open;
	status = copy_smb_filename(talloc_tos(),
				fsp->fsp_name,
				&smb_fname);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	status = close_file(smbreq, fsp, NORMAL_CLOSE);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(5,("smbd_smb2_close: close_file[%s]: %s\n",
			 fsp_str_dbg(fsp), nt_errstr(status)));
		return status;
	}

	if (in_flags & SMB2_CLOSE_FLAGS_FULL_INFORMATION) {
		int ret;
		if (posix_open) {
			ret = SMB_VFS_LSTAT(conn, smb_fname);
		} else {
			ret = SMB_VFS_STAT(conn, smb_fname);
		}
		if (ret == 0) {
			flags = SMB2_CLOSE_FLAGS_FULL_INFORMATION;
			dos_attrs = dos_mode(conn, smb_fname);
			mdate_ts = smb_fname->st.st_ex_mtime;
			adate_ts = smb_fname->st.st_ex_atime;
			create_date_ts = get_create_timespec(conn, NULL, smb_fname);
			cdate_ts = get_change_timespec(conn, NULL, smb_fname);

			if (lp_dos_filetime_resolution(SNUM(conn))) {
				dos_filetime_timespec(&create_date_ts);
				dos_filetime_timespec(&mdate_ts);
				dos_filetime_timespec(&adate_ts);
				dos_filetime_timespec(&cdate_ts);
			}
			if (!(dos_attrs & FILE_ATTRIBUTE_DIRECTORY)) {
				file_size = get_file_size_stat(&smb_fname->st);
			}

			allocation_size = SMB_VFS_GET_ALLOC_SIZE(conn, NULL, &smb_fname->st);
		}
	}

	*out_flags = flags;

	round_timespec(conn->ts_res, &create_date_ts);
	unix_timespec_to_nt_time(out_creation_time, create_date_ts);

	round_timespec(conn->ts_res, &adate_ts);
	unix_timespec_to_nt_time(out_last_access_time, adate_ts);

	round_timespec(conn->ts_res, &mdate_ts);
	unix_timespec_to_nt_time(out_last_write_time, mdate_ts);

	round_timespec(conn->ts_res, &cdate_ts);
	unix_timespec_to_nt_time(out_change_time, cdate_ts);

	*out_allocation_size = allocation_size;
	*out_end_of_file = file_size;
	*out_file_attributes = dos_attrs;

	return NT_STATUS_OK;
}

struct smbd_smb2_close_state {
	struct smbd_smb2_request *smb2req;
	struct files_struct *in_fsp;
	uint16_t in_flags;
	uint16_t out_flags;
	NTTIME out_creation_time;
	NTTIME out_last_access_time;
	NTTIME out_last_write_time;
	NTTIME out_change_time;
	uint64_t out_allocation_size;
	uint64_t out_end_of_file;
	uint32_t out_file_attributes;
};

static void smbd_smb2_close_do(struct tevent_req *subreq);

static struct tevent_req *smbd_smb2_close_send(TALLOC_CTX *mem_ctx,
					       struct tevent_context *ev,
					       struct smbd_smb2_request *smb2req,
					       struct files_struct *in_fsp,
					       uint16_t in_flags)
{
	struct tevent_req *req;
	struct smbd_smb2_close_state *state;
	NTSTATUS status;

	req = tevent_req_create(mem_ctx, &state,
				struct smbd_smb2_close_state);
	if (req == NULL) {
		return NULL;
	}
	state->smb2req = smb2req;
	state->in_fsp = in_fsp;
	state->in_flags = in_flags;

	if (in_fsp->num_aio_requests != 0) {

		in_fsp->deferred_close = tevent_wait_send(in_fsp, ev);
		if (tevent_req_nomem(in_fsp->deferred_close, req)) {
			return tevent_req_post(req, ev);
		}
		tevent_req_set_callback(in_fsp->deferred_close,
					smbd_smb2_close_do, req);
		return req;
	}

	status = smbd_smb2_close(smb2req,
				 state->in_fsp,
				 state->in_flags,
				 &state->out_flags,
				 &state->out_creation_time,
				 &state->out_last_access_time,
				 &state->out_last_write_time,
				 &state->out_change_time,
				 &state->out_allocation_size,
				 &state->out_end_of_file,
				 &state->out_file_attributes);
	if (tevent_req_nterror(req, status)) {
		return tevent_req_post(req, ev);
	}

	tevent_req_done(req);
	return tevent_req_post(req, ev);
}

static void smbd_smb2_close_do(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct smbd_smb2_close_state *state = tevent_req_data(
		req, struct smbd_smb2_close_state);
	NTSTATUS status;
	int ret;

	ret = tevent_wait_recv(subreq);
	TALLOC_FREE(subreq);
	if (ret != 0) {
		DEBUG(10, ("tevent_wait_recv returned %s\n",
			   strerror(ret)));
		/*
		 * Continue anyway, this should never happen
		 */
	}

	status = smbd_smb2_close(state->smb2req,
				 state->in_fsp,
				 state->in_flags,
				 &state->out_flags,
				 &state->out_creation_time,
				 &state->out_last_access_time,
				 &state->out_last_write_time,
				 &state->out_change_time,
				 &state->out_allocation_size,
				 &state->out_end_of_file,
				 &state->out_file_attributes);
	if (tevent_req_nterror(req, status)) {
		return;
	}
	tevent_req_done(req);
}

static NTSTATUS smbd_smb2_close_recv(struct tevent_req *req,
				     uint16_t *out_flags,
				     NTTIME *out_creation_time,
				     NTTIME *out_last_access_time,
				     NTTIME *out_last_write_time,
				     NTTIME *out_change_time,
				     uint64_t *out_allocation_size,
				     uint64_t *out_end_of_file,
				     uint32_t *out_file_attributes)
{
	struct smbd_smb2_close_state *state =
		tevent_req_data(req,
		struct smbd_smb2_close_state);
	NTSTATUS status;

	if (tevent_req_is_nterror(req, &status)) {
		tevent_req_received(req);
		return status;
	}

	*out_flags = state->out_flags;
	*out_creation_time = state->out_creation_time;
	*out_last_access_time = state->out_last_access_time;
	*out_last_write_time = state->out_last_write_time;
	*out_change_time = state->out_change_time;
	*out_allocation_size = state->out_allocation_size;
	*out_end_of_file = state->out_end_of_file;
	*out_file_attributes = state->out_file_attributes;

	tevent_req_received(req);
	return NT_STATUS_OK;
}
