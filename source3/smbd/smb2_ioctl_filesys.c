/*
   Unix SMB/CIFS implementation.
   Core SMB2 server

   Copyright (C) Stefan Metzmacher 2009
   Copyright (C) David Disseldorp 2013

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
#include "../libcli/security/security.h"
#include "../lib/util/tevent_ntstatus.h"
#include "rpc_server/srv_pipe_hnd.h"
#include "include/ntioctl.h"
#include "../librpc/ndr/libndr.h"
#include "librpc/gen_ndr/ndr_ioctl.h"
#include "smb2_ioctl_private.h"

static NTSTATUS fsctl_get_cmprn(TALLOC_CTX *mem_ctx,
				struct tevent_context *ev,
				struct files_struct *fsp,
				size_t in_max_output,
				DATA_BLOB *out_output)
{
	struct compression_state cmpr_state;
	enum ndr_err_code ndr_ret;
	DATA_BLOB output;
	NTSTATUS status;

	if (fsp == NULL) {
		return NT_STATUS_FILE_CLOSED;
	}

	/* Windows doesn't check for SEC_FILE_READ_ATTRIBUTE permission here */

	if ((fsp->conn->fs_capabilities & FILE_FILE_COMPRESSION) == 0) {
		DEBUG(4, ("FS does not advertise compression support\n"));
		return NT_STATUS_NOT_SUPPORTED;
	}

	ZERO_STRUCT(cmpr_state);
	status = SMB_VFS_GET_COMPRESSION(fsp->conn,
					 mem_ctx,
					 fsp,
					 NULL,
					 &cmpr_state.format);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	ndr_ret = ndr_push_struct_blob(&output, mem_ctx,
				       &cmpr_state,
			(ndr_push_flags_fn_t)ndr_push_compression_state);
	if (ndr_ret != NDR_ERR_SUCCESS) {
		return NT_STATUS_INTERNAL_ERROR;
	}

	if (in_max_output < output.length) {
		DEBUG(1, ("max output %u too small for compression state %ld\n",
		      (unsigned int)in_max_output, (long int)output.length));
		return NT_STATUS_INVALID_USER_BUFFER;
	}
	*out_output = output;

	return NT_STATUS_OK;
}

static NTSTATUS fsctl_set_cmprn(TALLOC_CTX *mem_ctx,
				struct tevent_context *ev,
				struct files_struct *fsp,
				DATA_BLOB *in_input)
{
	struct compression_state cmpr_state;
	enum ndr_err_code ndr_ret;
	NTSTATUS status;

	if (fsp == NULL) {
		return NT_STATUS_FILE_CLOSED;
	}

	/* WRITE_DATA permission is required, WRITE_ATTRIBUTES is not */
	status = check_access(fsp->conn, fsp, NULL,
			      FILE_WRITE_DATA);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	if ((fsp->conn->fs_capabilities & FILE_FILE_COMPRESSION) == 0) {
		DEBUG(4, ("FS does not advertise compression support\n"));
		return NT_STATUS_NOT_SUPPORTED;
	}

	ndr_ret = ndr_pull_struct_blob(in_input, mem_ctx, &cmpr_state,
			(ndr_pull_flags_fn_t)ndr_pull_compression_state);
	if (ndr_ret != NDR_ERR_SUCCESS) {
		DEBUG(0, ("failed to unmarshall set compression req\n"));
		return NT_STATUS_INVALID_PARAMETER;
	}

	status = SMB_VFS_SET_COMPRESSION(fsp->conn,
					 mem_ctx,
					 fsp,
					 cmpr_state.format);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	return NT_STATUS_OK;
}

struct tevent_req *smb2_ioctl_filesys(uint32_t ctl_code,
				      struct tevent_context *ev,
				      struct tevent_req *req,
				      struct smbd_smb2_ioctl_state *state)
{
	NTSTATUS status;

	switch (ctl_code) {
	case FSCTL_GET_COMPRESSION:
		status = fsctl_get_cmprn(state, ev, state->fsp,
					 state->in_max_output,
					 &state->out_output);
		if (!tevent_req_nterror(req, status)) {
			tevent_req_done(req);
		}
		return tevent_req_post(req, ev);
		break;
	case FSCTL_SET_COMPRESSION:
		status = fsctl_set_cmprn(state, ev, state->fsp,
					 &state->in_input);
		if (!tevent_req_nterror(req, status)) {
			tevent_req_done(req);
		}
		return tevent_req_post(req, ev);
		break;
	default: {
		uint8_t *out_data = NULL;
		uint32_t out_data_len = 0;

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
		break;
	}
	}

	tevent_req_nterror(req, NT_STATUS_INTERNAL_ERROR);
	return tevent_req_post(req, ev);
}
