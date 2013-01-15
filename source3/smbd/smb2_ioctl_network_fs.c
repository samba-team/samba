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
#include "../librpc/ndr/libndr.h"
#include "smb2_ioctl_private.h"

static NTSTATUS fsctl_validate_neg_info(TALLOC_CTX *mem_ctx,
				        struct tevent_context *ev,
				        struct smbXsrv_connection *conn,
				        DATA_BLOB *in_input,
				        uint32_t in_max_output,
				        DATA_BLOB *out_output,
					bool *disconnect)
{
	uint32_t in_capabilities;
	DATA_BLOB in_guid_blob;
	struct GUID in_guid;
	uint16_t in_security_mode;
	uint16_t in_num_dialects;
	uint16_t i;
	DATA_BLOB out_guid_blob;
	NTSTATUS status;

	if (in_input->length < 0x18) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	in_capabilities = IVAL(in_input->data, 0x00);
	in_guid_blob = data_blob_const(in_input->data + 0x04, 16);
	in_security_mode = SVAL(in_input->data, 0x14);
	in_num_dialects = SVAL(in_input->data, 0x16);

	if (in_input->length < (0x18 + in_num_dialects*2)) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	if (in_max_output < 0x18) {
		return NT_STATUS_BUFFER_TOO_SMALL;
	}

	status = GUID_from_ndr_blob(&in_guid_blob, &in_guid);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	if (in_num_dialects != conn->smb2.client.num_dialects) {
		*disconnect = true;
		return NT_STATUS_ACCESS_DENIED;
	}

	for (i=0; i < in_num_dialects; i++) {
		uint16_t v = SVAL(in_input->data, 0x18 + i*2);

		if (conn->smb2.client.dialects[i] != v) {
			*disconnect = true;
			return NT_STATUS_ACCESS_DENIED;
		}
	}

	if (GUID_compare(&in_guid, &conn->smb2.client.guid) != 0) {
		*disconnect = true;
		return NT_STATUS_ACCESS_DENIED;
	}

	if (in_security_mode != conn->smb2.client.security_mode) {
		*disconnect = true;
		return NT_STATUS_ACCESS_DENIED;
	}

	if (in_capabilities != conn->smb2.client.capabilities) {
		*disconnect = true;
		return NT_STATUS_ACCESS_DENIED;
	}

	status = GUID_to_ndr_blob(&conn->smb2.server.guid, mem_ctx,
				  &out_guid_blob);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	*out_output = data_blob_talloc(mem_ctx, NULL, 0x18);
	if (out_output->data == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	SIVAL(out_output->data, 0x00, conn->smb2.server.capabilities);
	memcpy(out_output->data+0x04, out_guid_blob.data, 16);
	SIVAL(out_output->data, 0x14, conn->smb2.server.security_mode);
	SIVAL(out_output->data, 0x16, conn->smb2.server.dialect);

	return NT_STATUS_OK;
}

NTSTATUS smb2_ioctl_network_fs(uint32_t ctl_code,
			       struct tevent_context *ev,
			       struct tevent_req *req,
			       struct smbd_smb2_ioctl_state *state)
{
	NTSTATUS status;

	switch (ctl_code) {
	case FSCTL_VALIDATE_NEGOTIATE_INFO:
	{
		status = fsctl_validate_neg_info(state, ev,
						 state->smbreq->sconn->conn,
						 &state->in_input,
						 state->in_max_output,
						 &state->out_output,
						 &state->disconnect);
		if (!tevent_req_nterror(req, status)) {
			tevent_req_done(req);
		}
		return tevent_req_post(req, ev);
	}
	default: {
		uint8_t *out_data = NULL;
		uint32_t out_data_len = 0;

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
