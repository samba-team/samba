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
#include "smbd/globals.h"
#include "../libcli/smb/smb_common.h"

static struct tevent_req *smbd_smb2_read_send(TALLOC_CTX *mem_ctx,
					      struct tevent_context *ev,
					      struct smbd_smb2_request *smb2req,
					      uint32_t in_smbpid,
					      uint64_t in_file_id_volatile,
					      uint32_t in_length,
					      uint64_t in_offset,
					      uint32_t in_minimum,
					      uint32_t in_remaining);
static NTSTATUS smbd_smb2_read_recv(struct tevent_req *req,
				    TALLOC_CTX *mem_ctx,
				    DATA_BLOB *out_data,
				    uint32_t *out_remaining);

static void smbd_smb2_request_read_done(struct tevent_req *subreq);
NTSTATUS smbd_smb2_request_process_read(struct smbd_smb2_request *req)
{
	const uint8_t *inhdr;
	const uint8_t *inbody;
	int i = req->current_idx;
	size_t expected_body_size = 0x31;
	size_t body_size;
	uint32_t in_smbpid;
	uint32_t in_length;
	uint64_t in_offset;
	uint64_t in_file_id_persistent;
	uint64_t in_file_id_volatile;
	uint32_t in_minimum_count;
	uint32_t in_remaining_bytes;
	struct tevent_req *subreq;

	inhdr = (const uint8_t *)req->in.vector[i+0].iov_base;
	if (req->in.vector[i+1].iov_len != (expected_body_size & 0xFFFFFFFE)) {
		return smbd_smb2_request_error(req, NT_STATUS_INVALID_PARAMETER);
	}

	inbody = (const uint8_t *)req->in.vector[i+1].iov_base;

	body_size = SVAL(inbody, 0x00);
	if (body_size != expected_body_size) {
		return smbd_smb2_request_error(req, NT_STATUS_INVALID_PARAMETER);
	}

	in_smbpid = IVAL(inhdr, SMB2_HDR_PID);

	in_length		= IVAL(inbody, 0x04);
	in_offset		= BVAL(inbody, 0x08);
	in_file_id_persistent	= BVAL(inbody, 0x10);
	in_file_id_volatile	= BVAL(inbody, 0x18);
	in_minimum_count	= IVAL(inbody, 0x20);
	in_remaining_bytes	= IVAL(inbody, 0x28);

	/* check the max read size */
	if (in_length > lp_smb2_max_read()) {
		DEBUG(0,("here:%s: 0x%08X: 0x%08X\n",
			__location__, in_length, lp_smb2_max_read()));
		return smbd_smb2_request_error(req, NT_STATUS_INVALID_PARAMETER);
	}

	if (req->compat_chain_fsp) {
		/* skip check */
	} else if (in_file_id_persistent != in_file_id_volatile) {
		return smbd_smb2_request_error(req, NT_STATUS_FILE_CLOSED);
	}

	subreq = smbd_smb2_read_send(req,
				     req->sconn->smb2.event_ctx,
				     req,
				     in_smbpid,
				     in_file_id_volatile,
				     in_length,
				     in_offset,
				     in_minimum_count,
				     in_remaining_bytes);
	if (subreq == NULL) {
		return smbd_smb2_request_error(req, NT_STATUS_NO_MEMORY);
	}
	tevent_req_set_callback(subreq, smbd_smb2_request_read_done, req);

	return smbd_smb2_request_pending_queue(req, subreq);
}

static void smbd_smb2_request_read_done(struct tevent_req *subreq)
{
	struct smbd_smb2_request *req = tevent_req_callback_data(subreq,
					struct smbd_smb2_request);
	int i = req->current_idx;
	uint8_t *outhdr;
	DATA_BLOB outbody;
	DATA_BLOB outdyn;
	uint8_t out_data_offset;
	DATA_BLOB out_data_buffer = data_blob_null;
	uint32_t out_data_remaining = 0;
	NTSTATUS status;
	NTSTATUS error; /* transport error */

	status = smbd_smb2_read_recv(subreq,
				     req,
				     &out_data_buffer,
				     &out_data_remaining);
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

	out_data_offset = SMB2_HDR_BODY + 0x10;

	outhdr = (uint8_t *)req->out.vector[i].iov_base;

	outbody = data_blob_talloc(req->out.vector, NULL, 0x10);
	if (outbody.data == NULL) {
		error = smbd_smb2_request_error(req, NT_STATUS_NO_MEMORY);
		if (!NT_STATUS_IS_OK(error)) {
			smbd_server_connection_terminate(req->sconn,
							 nt_errstr(error));
			return;
		}
		return;
	}

	SSVAL(outbody.data, 0x00, 0x10 + 1);	/* struct size */
	SCVAL(outbody.data, 0x02,
	      out_data_offset);			/* data offset */
	SCVAL(outbody.data, 0x03, 0);		/* reserved */
	SIVAL(outbody.data, 0x04,
	      out_data_buffer.length);		/* data length */
	SIVAL(outbody.data, 0x08,
	      out_data_remaining);		/* data remaining */
	SIVAL(outbody.data, 0x0C, 0);		/* reserved */

	outdyn = out_data_buffer;

	error = smbd_smb2_request_done(req, outbody, &outdyn);
	if (!NT_STATUS_IS_OK(error)) {
		smbd_server_connection_terminate(req->sconn,
						 nt_errstr(error));
		return;
	}
}

struct smbd_smb2_read_state {
	struct smbd_smb2_request *smb2req;
	files_struct *fsp;
	uint32_t in_length;
	uint64_t in_offset;
	uint32_t in_minimum;
	DATA_BLOB out_data;
	uint32_t out_remaining;
};

static void smbd_smb2_read_pipe_done(struct tevent_req *subreq);

/*******************************************************************
 Common read complete processing function for both synchronous and
 asynchronous reads.
*******************************************************************/

NTSTATUS smb2_read_complete(struct tevent_req *req, ssize_t nread, int err)
{
	struct smbd_smb2_read_state *state = tevent_req_data(req,
					struct smbd_smb2_read_state);
	files_struct *fsp = state->fsp;

	if (nread < 0) {
		NTSTATUS status = map_nt_error_from_unix(err);

		DEBUG( 3,( "smb2_read_complete: file %s nread = %d. "
			"Error = %s (NTSTATUS %s)\n",
			fsp_str_dbg(fsp),
			(int)nread,
			strerror(err),
			nt_errstr(status)));

		return status;
	}
	if (nread == 0 && state->in_length != 0) {
		DEBUG(5,("smb2_read_complete: read_file[%s] end of file\n",
			fsp_str_dbg(fsp)));
		return NT_STATUS_END_OF_FILE;
	}

	if (nread < state->in_minimum) {
		DEBUG(5,("smb2_read_complete: read_file[%s] read less %d than "
			"minimum requested %u. Returning end of file\n",
			fsp_str_dbg(fsp),
			(int)nread,
			(unsigned int)state->in_minimum));
		return NT_STATUS_END_OF_FILE;
	}

	DEBUG(3,("smbd_smb2_read: fnum=[%d/%s] length=%lu offset=%lu read=%lu\n",
		fsp->fnum,
		fsp_str_dbg(fsp),
		(unsigned long)state->in_length,
		(unsigned long)state->in_offset,
		(unsigned long)nread));

	state->out_data.length = nread;
	state->out_remaining = 0;

	return NT_STATUS_OK;
}

static struct tevent_req *smbd_smb2_read_send(TALLOC_CTX *mem_ctx,
					      struct tevent_context *ev,
					      struct smbd_smb2_request *smb2req,
					      uint32_t in_smbpid,
					      uint64_t in_file_id_volatile,
					      uint32_t in_length,
					      uint64_t in_offset,
					      uint32_t in_minimum,
					      uint32_t in_remaining)
{
	NTSTATUS status;
	struct tevent_req *req = NULL;
	struct smbd_smb2_read_state *state = NULL;
	struct smb_request *smbreq = NULL;
	connection_struct *conn = smb2req->tcon->compat_conn;
	files_struct *fsp = NULL;
	ssize_t nread = -1;
	struct lock_struct lock;
	int saved_errno;

	req = tevent_req_create(mem_ctx, &state,
				struct smbd_smb2_read_state);
	if (req == NULL) {
		return NULL;
	}
	state->smb2req = smb2req;
	state->in_length = in_length;
	state->in_offset = in_offset;
	state->in_minimum = in_minimum;
	state->out_data = data_blob_null;
	state->out_remaining = 0;

	DEBUG(10,("smbd_smb2_read: file_id[0x%016llX]\n",
		  (unsigned long long)in_file_id_volatile));

	smbreq = smbd_smb2_fake_smb_request(smb2req);
	if (tevent_req_nomem(smbreq, req)) {
		return tevent_req_post(req, ev);
	}

	fsp = file_fsp(smbreq, (uint16_t)in_file_id_volatile);
	if (fsp == NULL) {
		tevent_req_nterror(req, NT_STATUS_FILE_CLOSED);
		return tevent_req_post(req, ev);
	}
	if (conn != fsp->conn) {
		tevent_req_nterror(req, NT_STATUS_FILE_CLOSED);
		return tevent_req_post(req, ev);
	}
	if (smb2req->session->vuid != fsp->vuid) {
		tevent_req_nterror(req, NT_STATUS_FILE_CLOSED);
		return tevent_req_post(req, ev);
	}
	if (fsp->is_directory) {
		tevent_req_nterror(req, NT_STATUS_INVALID_DEVICE_REQUEST);
		return tevent_req_post(req, ev);
	}

	state->out_data = data_blob_talloc(state, NULL, in_length);
	if (in_length > 0 && tevent_req_nomem(state->out_data.data, req)) {
		return tevent_req_post(req, ev);
	}

	state->fsp = fsp;

	if (IS_IPC(smbreq->conn)) {
		struct tevent_req *subreq = NULL;

		if (!fsp_is_np(fsp)) {
			tevent_req_nterror(req, NT_STATUS_FILE_CLOSED);
			return tevent_req_post(req, ev);
		}

		subreq = np_read_send(state, smbd_event_context(),
				      fsp->fake_file_handle,
				      state->out_data.data,
				      state->out_data.length);
		if (tevent_req_nomem(subreq, req)) {
			return tevent_req_post(req, ev);
		}
		tevent_req_set_callback(subreq,
					smbd_smb2_read_pipe_done,
					req);
		return req;
	}

	if (!CHECK_READ(fsp, smbreq)) {
		tevent_req_nterror(req, NT_STATUS_ACCESS_DENIED);
		return tevent_req_post(req, ev);
	}

	status = schedule_smb2_aio_read(fsp->conn,
				smbreq,
				fsp,
				(char *)state->out_data.data,
				(SMB_OFF_T)in_offset,
				(size_t)in_length);

	if (NT_STATUS_IS_OK(status)) {
		/*
		 * Doing an async read. Don't
		 * send a "gone async" message
		 * as we expect this to be less
		 * than the client timeout period.
		 * JRA. FIXME for offline files..
		 * FIXME. Add cancel code..
		 */
		smb2req->async = true;
		return req;
	}

	if (!NT_STATUS_EQUAL(status, NT_STATUS_RETRY)) {
		/* Real error in setting up aio. Fail. */
		tevent_req_nterror(req, NT_STATUS_FILE_CLOSED);
		return tevent_req_post(req, ev);
	}

	/* Fallback to synchronous. */

	init_strict_lock_struct(fsp,
				in_file_id_volatile,
				in_offset,
				in_length,
				READ_LOCK,
				&lock);

	if (!SMB_VFS_STRICT_LOCK(conn, fsp, &lock)) {
		tevent_req_nterror(req, NT_STATUS_FILE_LOCK_CONFLICT);
		return tevent_req_post(req, ev);
	}

	nread = read_file(fsp,
			  (char *)state->out_data.data,
			  in_offset,
			  in_length);

	saved_errno = errno;

	SMB_VFS_STRICT_UNLOCK(conn, fsp, &lock);

	DEBUG(10,("smbd_smb2_read: file %s handle [0x%016llX] offset=%llu "
		"len=%llu returned %lld\n",
		fsp_str_dbg(fsp),
		(unsigned long long)in_file_id_volatile,
		(unsigned long long)in_offset,
		(unsigned long long)in_length,
		(long long)nread));

	status = smb2_read_complete(req, nread, saved_errno);
	if (!NT_STATUS_IS_OK(status)) {
		tevent_req_nterror(req, status);
	} else {
		/* Success. */
		tevent_req_done(req);
	}
	return tevent_req_post(req, ev);
}

static void smbd_smb2_read_pipe_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(subreq,
				 struct tevent_req);
	struct smbd_smb2_read_state *state = tevent_req_data(req,
					     struct smbd_smb2_read_state);
	NTSTATUS status;
	ssize_t nread = -1;
	bool is_data_outstanding;

	status = np_read_recv(subreq, &nread, &is_data_outstanding);
	TALLOC_FREE(subreq);
	if (!NT_STATUS_IS_OK(status)) {
		tevent_req_nterror(req, status);
		return;
	}

	if (nread == 0 && state->out_data.length != 0) {
		tevent_req_nterror(req, NT_STATUS_END_OF_FILE);
		return;
	}

	state->out_data.length = nread;
	state->out_remaining = 0;

	tevent_req_done(req);
}

static NTSTATUS smbd_smb2_read_recv(struct tevent_req *req,
				    TALLOC_CTX *mem_ctx,
				    DATA_BLOB *out_data,
				    uint32_t *out_remaining)
{
	NTSTATUS status;
	struct smbd_smb2_read_state *state = tevent_req_data(req,
					     struct smbd_smb2_read_state);

	if (tevent_req_is_nterror(req, &status)) {
		tevent_req_received(req);
		return status;
	}

	*out_data = state->out_data;
	talloc_steal(mem_ctx, out_data->data);
	*out_remaining = state->out_remaining;

	tevent_req_received(req);
	return NT_STATUS_OK;
}
