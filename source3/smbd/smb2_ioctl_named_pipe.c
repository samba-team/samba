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
#include "rpc_server/srv_pipe_hnd.h"
#include "include/ntioctl.h"
#include "smb2_ioctl_private.h"

static void smbd_smb2_ioctl_pipe_write_done(struct tevent_req *subreq);
static void smbd_smb2_ioctl_pipe_read_done(struct tevent_req *subreq);

struct tevent_req *smb2_ioctl_named_pipe(uint32_t ctl_code,
					 struct tevent_context *ev,
					 struct tevent_req *req,
					 struct smbd_smb2_ioctl_state *state)
{
	NTSTATUS status;
	uint8_t *out_data = NULL;
	uint32_t out_data_len = 0;

	if (ctl_code == FSCTL_PIPE_TRANSCEIVE) {
		struct tevent_req *subreq;

		if (!IS_IPC(state->smbreq->conn)) {
			tevent_req_nterror(req, NT_STATUS_NOT_SUPPORTED);
			return tevent_req_post(req, ev);
		}

		if (state->fsp == NULL) {
			tevent_req_nterror(req, NT_STATUS_FILE_CLOSED);
			return tevent_req_post(req, ev);
		}

		if (!fsp_is_np(state->fsp)) {
			tevent_req_nterror(req, NT_STATUS_FILE_CLOSED);
			return tevent_req_post(req, ev);
		}

		DEBUG(10,("smbd_smb2_ioctl_send: np_write_send of size %u\n",
			(unsigned int)state->in_input.length ));

		subreq = np_write_send(state, ev,
				       state->fsp->fake_file_handle,
				       state->in_input.data,
				       state->in_input.length);
		if (tevent_req_nomem(subreq, req)) {
			return tevent_req_post(req, ev);
		}
		tevent_req_set_callback(subreq,
					smbd_smb2_ioctl_pipe_write_done,
					req);
		return req;
	}

	if (state->fsp == NULL) {
		status = NT_STATUS_NOT_SUPPORTED;
	} else {
		status = SMB_VFS_FSCTL(state->fsp,
				       state,
				       ctl_code,
				       state->smbreq->flags2,
				       state->in_input.data,
				       state->in_input.length,
				       &out_data,
				       state->in_max_output,
				       &out_data_len);
		state->out_output = data_blob_const(out_data, out_data_len);
		if (NT_STATUS_IS_OK(status)) {
			tevent_req_done(req);
			return tevent_req_post(req, ev);
		}
	}

	if (NT_STATUS_EQUAL(status, NT_STATUS_NOT_SUPPORTED)) {
		if (IS_IPC(state->smbreq->conn)) {
			status = NT_STATUS_FS_DRIVER_REQUIRED;
		} else {
			status = NT_STATUS_INVALID_DEVICE_REQUEST;
		}
	}

	tevent_req_nterror(req, status);
	return tevent_req_post(req, ev);
}

static void smbd_smb2_ioctl_pipe_write_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(subreq,
				 struct tevent_req);
	struct smbd_smb2_ioctl_state *state = tevent_req_data(req,
					      struct smbd_smb2_ioctl_state);
	NTSTATUS status;
	ssize_t nwritten = -1;

	status = np_write_recv(subreq, &nwritten);

	DEBUG(10,("smbd_smb2_ioctl_pipe_write_done: received %ld\n",
		(long int)nwritten ));

	TALLOC_FREE(subreq);
	if (!NT_STATUS_IS_OK(status)) {
		tevent_req_nterror(req, status);
		return;
	}

	if (nwritten != state->in_input.length) {
		tevent_req_nterror(req, NT_STATUS_PIPE_NOT_AVAILABLE);
		return;
	}

	state->out_output = data_blob_talloc(state, NULL, state->in_max_output);
	if (state->in_max_output > 0 &&
	    tevent_req_nomem(state->out_output.data, req)) {
		return;
	}

	DEBUG(10,("smbd_smb2_ioctl_pipe_write_done: issuing np_read_send "
		"of size %u\n",
		(unsigned int)state->out_output.length ));

	subreq = np_read_send(state->smbreq->conn,
			      state->smb2req->sconn->ev_ctx,
			      state->fsp->fake_file_handle,
			      state->out_output.data,
			      state->out_output.length);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, smbd_smb2_ioctl_pipe_read_done, req);
}

static void smbd_smb2_ioctl_pipe_read_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(subreq,
				 struct tevent_req);
	struct smbd_smb2_ioctl_state *state = tevent_req_data(req,
					      struct smbd_smb2_ioctl_state);
	NTSTATUS status;
	ssize_t nread = -1;
	bool is_data_outstanding = false;

	status = np_read_recv(subreq, &nread, &is_data_outstanding);

	DEBUG(10,("smbd_smb2_ioctl_pipe_read_done: np_read_recv nread = %d "
		 "is_data_outstanding = %d, status = %s\n",
		(int)nread,
		(int)is_data_outstanding,
		nt_errstr(status) ));

	TALLOC_FREE(subreq);
	if (!NT_STATUS_IS_OK(status)) {
		tevent_req_nterror(req, status);
		return;
	}

	state->out_output.length = nread;

	if (is_data_outstanding) {
		tevent_req_nterror(req, STATUS_BUFFER_OVERFLOW);
		return;
	}

	tevent_req_done(req);
}
