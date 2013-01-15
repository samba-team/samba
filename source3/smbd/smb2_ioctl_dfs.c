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
#include "include/ntioctl.h"
#include "smb2_ioctl_private.h"

static NTSTATUS fsctl_dfs_get_refers(TALLOC_CTX *mem_ctx,
				     struct tevent_context *ev,
				     struct connection_struct *conn,
				     DATA_BLOB *in_input,
				     uint32_t in_max_output,
				     DATA_BLOB *out_output)
{
	uint16_t in_max_referral_level;
	DATA_BLOB in_file_name_buffer;
	char *in_file_name_string;
	size_t in_file_name_string_size;
	bool ok;
	bool overflow = false;
	NTSTATUS status;
	int dfs_size;
	char *dfs_data = NULL;
	DATA_BLOB output;

	if (!IS_IPC(conn)) {
		return NT_STATUS_INVALID_DEVICE_REQUEST;
	}

	if (!lp_host_msdfs()) {
		return NT_STATUS_FS_DRIVER_REQUIRED;
	}

	if (in_input->length < (2 + 2)) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	in_max_referral_level = SVAL(in_input->data, 0);
	in_file_name_buffer.data = in_input->data + 2;
	in_file_name_buffer.length = in_input->length - 2;

	ok = convert_string_talloc(mem_ctx, CH_UTF16, CH_UNIX,
				   in_file_name_buffer.data,
				   in_file_name_buffer.length,
				   &in_file_name_string,
				   &in_file_name_string_size);
	if (!ok) {
		return NT_STATUS_ILLEGAL_CHARACTER;
	}

	dfs_size = setup_dfs_referral(conn,
				      in_file_name_string,
				      in_max_referral_level,
				      &dfs_data, &status);
	if (dfs_size < 0) {
		return status;
	}

	if (dfs_size > in_max_output) {
		/*
		 * TODO: we need a testsuite for this
		 */
		overflow = true;
		dfs_size = in_max_output;
	}

	output = data_blob_talloc(mem_ctx, (uint8_t *)dfs_data, dfs_size);
	SAFE_FREE(dfs_data);
	if ((dfs_size > 0) && (output.data == NULL)) {
		return NT_STATUS_NO_MEMORY;
	}
	*out_output = output;

	if (overflow) {
		return STATUS_BUFFER_OVERFLOW;
	}
	return NT_STATUS_OK;
}

struct tevent_req *smb2_ioctl_dfs(uint32_t ctl_code,
				  struct tevent_context *ev,
				  struct tevent_req *req,
				  struct smbd_smb2_ioctl_state *state)
{
	NTSTATUS status;

	switch (ctl_code) {
	case FSCTL_DFS_GET_REFERRALS:
		status = fsctl_dfs_get_refers(state, ev, state->smbreq->conn,
					      &state->in_input,
					      state->in_max_output,
					      &state->out_output);
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
