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
				     struct timespec *out_creation_ts,
				     struct timespec *out_last_access_ts,
				     struct timespec *out_last_write_ts,
				     struct timespec *out_change_ts,
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
	uint16_t out_flags = 0;
	connection_struct *conn = req->tcon->compat;
	struct timespec out_creation_ts = { 0, };
	struct timespec out_last_access_ts = { 0, };
	struct timespec out_last_write_ts = { 0, };
	struct timespec out_change_ts = { 0, };
	uint64_t out_allocation_size = 0;
	uint64_t out_end_of_file = 0;
	uint32_t out_file_attributes = 0;
	NTSTATUS status;
	NTSTATUS error;

	status = smbd_smb2_close_recv(subreq,
				      &out_flags,
				      &out_creation_ts,
				      &out_last_access_ts,
				      &out_last_write_ts,
				      &out_change_ts,
				      &out_allocation_size,
				      &out_end_of_file,
				      &out_file_attributes);
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

	outbody = smbd_smb2_generate_outbody(req, 0x3C);
	if (outbody.data == NULL) {
		error = smbd_smb2_request_error(req, NT_STATUS_NO_MEMORY);
		if (!NT_STATUS_IS_OK(error)) {
			smbd_server_connection_terminate(req->xconn,
							 nt_errstr(error));
			return;
		}
		return;
	}

	SSVAL(outbody.data, 0x00, 0x3C);	/* struct size */
	SSVAL(outbody.data, 0x02, out_flags);
	SIVAL(outbody.data, 0x04, 0);		/* reserved */
	put_long_date_timespec(conn->ts_res,
		(char *)outbody.data + 0x08, out_creation_ts);
	put_long_date_timespec(conn->ts_res,
		(char *)outbody.data + 0x10, out_last_access_ts);
	put_long_date_timespec(conn->ts_res,
		(char *)outbody.data + 0x18, out_last_write_ts);
	put_long_date_timespec(conn->ts_res,
		(char *)outbody.data + 0x20, out_change_ts);
	SBVAL(outbody.data, 0x28, out_allocation_size);
	SBVAL(outbody.data, 0x30, out_end_of_file);
	SIVAL(outbody.data, 0x38, out_file_attributes);

	error = smbd_smb2_request_done(req, outbody, NULL);
	if (!NT_STATUS_IS_OK(error)) {
		smbd_server_connection_terminate(req->xconn,
						 nt_errstr(error));
		return;
	}
}

static void setup_close_full_information(connection_struct *conn,
				struct smb_filename *smb_fname,
				bool posix_open,
				struct timespec *out_creation_ts,
				struct timespec *out_last_access_ts,
				struct timespec *out_last_write_ts,
				struct timespec *out_change_ts,
				uint16_t *out_flags,
				uint64_t *out_allocation_size,
				uint64_t *out_end_of_file,
				uint32_t *out_file_attributes)
{
	int ret;
	if (posix_open) {
		ret = SMB_VFS_LSTAT(conn, smb_fname);
	} else {
		ret = SMB_VFS_STAT(conn, smb_fname);
	}
	if (ret != 0) {
		return;
	}

	*out_flags = SMB2_CLOSE_FLAGS_FULL_INFORMATION;
	*out_file_attributes = dos_mode(conn, smb_fname);
	*out_last_write_ts = smb_fname->st.st_ex_mtime;
	*out_last_access_ts = smb_fname->st.st_ex_atime;
	*out_creation_ts = get_create_timespec(conn, NULL, smb_fname);
	*out_change_ts = get_change_timespec(conn, NULL, smb_fname);

	if (lp_dos_filetime_resolution(SNUM(conn))) {
		dos_filetime_timespec(out_creation_ts);
		dos_filetime_timespec(out_last_write_ts);
		dos_filetime_timespec(out_last_access_ts);
		dos_filetime_timespec(out_change_ts);
	}
	if (!(*out_file_attributes & FILE_ATTRIBUTE_DIRECTORY)) {
		*out_end_of_file = get_file_size_stat(&smb_fname->st);
	}

	*out_allocation_size = SMB_VFS_GET_ALLOC_SIZE(conn, NULL, &smb_fname->st);
}

static NTSTATUS smbd_smb2_close(struct smbd_smb2_request *req,
				struct files_struct *fsp,
				uint16_t in_flags,
				uint16_t *out_flags,
				struct timespec *out_creation_ts,
				struct timespec *out_last_access_ts,
				struct timespec *out_last_write_ts,
				struct timespec *out_change_ts,
				uint64_t *out_allocation_size,
				uint64_t *out_end_of_file,
				uint32_t *out_file_attributes)
{
	NTSTATUS status;
	struct smb_request *smbreq;
	connection_struct *conn = req->tcon->compat;
	struct smb_filename *smb_fname = NULL;
	uint64_t allocation_size = 0;
	uint64_t file_size = 0;
	uint32_t dos_attrs = 0;
	uint16_t flags = 0;
	bool posix_open = false;

	ZERO_STRUCTP(out_creation_ts);
	ZERO_STRUCTP(out_last_access_ts);
	ZERO_STRUCTP(out_last_write_ts);
	ZERO_STRUCTP(out_change_ts);

	*out_flags = 0;
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
	smb_fname = cp_smb_filename(talloc_tos(), fsp->fsp_name);
	if (smb_fname == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	if ((in_flags & SMB2_CLOSE_FLAGS_FULL_INFORMATION) &&
	    (fsp->initial_delete_on_close || fsp->delete_on_close)) {
		/*
		 * We might be deleting the file. Ensure we
		 * return valid data from before the file got
		 * removed.
		 */
		setup_close_full_information(conn,
				smb_fname,
				posix_open,
				out_creation_ts,
				out_last_access_ts,
				out_last_write_ts,
				out_change_ts,
				&flags,
				&allocation_size,
				&file_size,
				&dos_attrs);
	}

	status = close_file(smbreq, fsp, NORMAL_CLOSE);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(5,("smbd_smb2_close: close_file[%s]: %s\n",
			 fsp_str_dbg(fsp), nt_errstr(status)));
		return status;
	}

	if (in_flags & SMB2_CLOSE_FLAGS_FULL_INFORMATION) {
		setup_close_full_information(conn,
				smb_fname,
				posix_open,
				out_creation_ts,
				out_last_access_ts,
				out_last_write_ts,
				out_change_ts,
				&flags,
				&allocation_size,
				&file_size,
				&dos_attrs);
	}

	*out_flags = flags;
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
	struct timespec out_creation_ts;
	struct timespec out_last_access_ts;
	struct timespec out_last_write_ts;
	struct timespec out_change_ts;
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
				 &state->out_creation_ts,
				 &state->out_last_access_ts,
				 &state->out_last_write_ts,
				 &state->out_change_ts,
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
				 &state->out_creation_ts,
				 &state->out_last_access_ts,
				 &state->out_last_write_ts,
				 &state->out_change_ts,
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
				     struct timespec *out_creation_ts,
				     struct timespec *out_last_access_ts,
				     struct timespec *out_last_write_ts,
				     struct timespec *out_change_ts,
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
	*out_creation_ts = state->out_creation_ts;
	*out_last_access_ts = state->out_last_access_ts;
	*out_last_write_ts = state->out_last_write_ts;
	*out_change_ts = state->out_change_ts;
	*out_allocation_size = state->out_allocation_size;
	*out_end_of_file = state->out_end_of_file;
	*out_file_attributes = state->out_file_attributes;

	tevent_req_received(req);
	return NT_STATUS_OK;
}
