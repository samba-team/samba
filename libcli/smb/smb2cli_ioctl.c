/*
   Unix SMB/CIFS implementation.
   smb2 lib
   Copyright (C) Stefan Metzmacher 2011

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
#include "system/network.h"
#include "lib/util/tevent_ntstatus.h"
#include "smb_common.h"
#include "smbXcli_base.h"

struct smb2cli_ioctl_state {
	uint8_t fixed[0x38];
	uint8_t dyn_pad[1];
	uint32_t max_input_length;
	uint32_t max_output_length;
	struct iovec *recv_iov;
	bool out_valid;
	DATA_BLOB out_input_buffer;
	DATA_BLOB out_output_buffer;
	uint32_t ctl_code;
};

static void smb2cli_ioctl_done(struct tevent_req *subreq);

struct tevent_req *smb2cli_ioctl_send(TALLOC_CTX *mem_ctx,
				      struct tevent_context *ev,
				      struct smbXcli_conn *conn,
				      uint32_t timeout_msec,
				      struct smbXcli_session *session,
				      struct smbXcli_tcon *tcon,
				      uint64_t in_fid_persistent,
				      uint64_t in_fid_volatile,
				      uint32_t in_ctl_code,
				      uint32_t in_max_input_length,
				      const DATA_BLOB *in_input_buffer,
				      uint32_t in_max_output_length,
				      const DATA_BLOB *in_output_buffer,
				      uint32_t in_flags)
{
	struct tevent_req *req, *subreq;
	struct smb2cli_ioctl_state *state;
	uint8_t *fixed;
	uint8_t *dyn;
	size_t dyn_len;
	uint32_t input_buffer_offset = 0;
	uint32_t input_buffer_length = 0;
	uint32_t output_buffer_offset = 0;
	uint32_t output_buffer_length = 0;
	uint32_t pad_length = 0;
	uint64_t tmp64;
	uint32_t max_dyn_len = 0;

	req = tevent_req_create(mem_ctx, &state,
				struct smb2cli_ioctl_state);
	if (req == NULL) {
		return NULL;
	}
	state->ctl_code = in_ctl_code;
	state->max_input_length = in_max_input_length;
	state->max_output_length = in_max_output_length;

	tmp64 = in_max_input_length;
	tmp64 += in_max_output_length;
	if (tmp64 > UINT32_MAX) {
		max_dyn_len = UINT32_MAX;
	} else {
		max_dyn_len = tmp64;
	}

	if (in_input_buffer) {
		input_buffer_offset = SMB2_HDR_BODY+0x38;
		input_buffer_length = in_input_buffer->length;
	}

	if (in_output_buffer) {
		output_buffer_offset = SMB2_HDR_BODY+0x38;
		output_buffer_length = in_output_buffer->length;
		if (input_buffer_length > 0 && output_buffer_length > 0) {
			uint32_t tmp;
			output_buffer_offset += input_buffer_length;
			tmp = output_buffer_offset;
			output_buffer_offset = NDR_ROUND(output_buffer_offset, 8);
			pad_length = output_buffer_offset - tmp;
		}
	}

	fixed = state->fixed;

	SSVAL(fixed, 0x00, 0x39);
	SSVAL(fixed, 0x02, 0); /* reserved */
	SIVAL(fixed, 0x04, in_ctl_code);
	SBVAL(fixed, 0x08, in_fid_persistent);
	SBVAL(fixed, 0x10, in_fid_volatile);
	SIVAL(fixed, 0x18, input_buffer_offset);
	SIVAL(fixed, 0x1C, input_buffer_length);
	SIVAL(fixed, 0x20, in_max_input_length);
	SIVAL(fixed, 0x24, output_buffer_offset);
	SIVAL(fixed, 0x28, output_buffer_length);
	SIVAL(fixed, 0x2C, in_max_output_length);
	SIVAL(fixed, 0x30, in_flags);
	SIVAL(fixed, 0x34, 0); /* reserved */

	if (input_buffer_length > 0 && output_buffer_length > 0) {
		size_t avail = UINT32_MAX - (input_buffer_length + pad_length);
		size_t ofs = output_buffer_offset - input_buffer_offset;

		if (avail < output_buffer_length) {
			tevent_req_nterror(req, NT_STATUS_INVALID_PARAMETER_MIX);
			return tevent_req_post(req, ev);
		}

		dyn_len = input_buffer_length + output_buffer_length + pad_length;

		dyn = talloc_zero_array(state, uint8_t, dyn_len);
		if (tevent_req_nomem(dyn, req)) {
			return tevent_req_post(req, ev);
		}
		memcpy(dyn, in_input_buffer->data,
		       in_input_buffer->length);
		memcpy(dyn + ofs, in_output_buffer->data,
		       in_output_buffer->length);
	} else if (input_buffer_length > 0) {
		dyn = in_input_buffer->data;
		dyn_len = in_input_buffer->length;
	} else if (output_buffer_length > 0) {
		dyn = in_output_buffer->data;
		dyn_len = in_output_buffer->length;
	} else {
		dyn = state->dyn_pad;
		dyn_len = sizeof(state->dyn_pad);
	}

	subreq = smb2cli_req_send(state, ev, conn, SMB2_OP_IOCTL,
				  0, 0, /* flags */
				  timeout_msec,
				  tcon,
				  session,
				  state->fixed, sizeof(state->fixed),
				  dyn, dyn_len,
				  max_dyn_len);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, smb2cli_ioctl_done, req);
	return req;
}

static void smb2cli_ioctl_done(struct tevent_req *subreq)
{
	struct tevent_req *req =
		tevent_req_callback_data(subreq,
		struct tevent_req);
	struct smb2cli_ioctl_state *state =
		tevent_req_data(req,
		struct smb2cli_ioctl_state);
	NTSTATUS status;
	NTSTATUS error;
	struct iovec *iov;
	uint8_t *fixed;
	DATA_BLOB dyn_buffer = data_blob_null;
	uint32_t dyn_ofs = SMB2_HDR_BODY + 0x30;
	uint32_t input_min_offset;
	uint32_t input_buffer_offset;
	uint32_t input_buffer_length;
	uint32_t input_next_offset;
	uint32_t output_min_offset;
	uint32_t output_buffer_offset;
	uint32_t output_buffer_length;
	uint32_t output_next_offset;
	static const struct smb2cli_req_expected_response expected[] = {
	{
		.status = NT_STATUS_OK,
		.body_size = 0x31
	},
	{
		.status = STATUS_BUFFER_OVERFLOW,
		.body_size = 0x31
	},
	{
		/*
		 * We need to make sure that
		 * a response with NT_STATUS_FILE_CLOSED
		 * without signing generates NT_STATUS_ACCESS_DENIED
		 * if the request was signed.
		 */
		.status = NT_STATUS_FILE_CLOSED,
		.body_size = 0x09,
	},
	{
		/*
		 * a normal error
		 */
		.status = NT_STATUS_INVALID_PARAMETER,
		.body_size = 0x09
	},
	{
		/*
		 * a special case for FSCTL_SRV_COPYCHUNK_*
		 */
		.status = NT_STATUS_INVALID_PARAMETER,
		.body_size = 0x31
	},
	};

	status = smb2cli_req_recv(subreq, state, &iov,
				  expected, ARRAY_SIZE(expected));
	TALLOC_FREE(subreq);
	if (NT_STATUS_EQUAL(status, NT_STATUS_INVALID_PARAMETER)) {
		switch (state->ctl_code) {
		case FSCTL_SRV_COPYCHUNK:
		case FSCTL_SRV_COPYCHUNK_WRITE:
			break;
		default:
			tevent_req_nterror(req, status);
			return;
		}

		if (iov[1].iov_len != 0x30) {
			tevent_req_nterror(req,
					NT_STATUS_INVALID_NETWORK_RESPONSE);
			return;
		}
	} else if (NT_STATUS_EQUAL(status, STATUS_BUFFER_OVERFLOW)) {
		/* no error */
	} else {
		if (tevent_req_nterror(req, status)) {
			return;
		}
	}

	/*
	 * At this stage we're sure that got a body size of 0x31,
	 * either with NT_STATUS_OK, STATUS_BUFFER_OVERFLOW or
	 * NT_STATUS_INVALID_PARAMETER.
	 */

	state->recv_iov = iov;
	fixed = (uint8_t *)iov[1].iov_base;
	dyn_buffer = data_blob_const((uint8_t *)iov[2].iov_base,
				     iov[2].iov_len);

	input_buffer_offset = IVAL(fixed, 0x18);
	input_buffer_length = IVAL(fixed, 0x1C);
	output_buffer_offset = IVAL(fixed, 0x20);
	output_buffer_length = IVAL(fixed, 0x24);

	input_min_offset = dyn_ofs;
	input_next_offset = dyn_ofs;
	error = smb2cli_parse_dyn_buffer(dyn_ofs,
					 dyn_buffer,
					 input_min_offset,
					 input_buffer_offset,
					 input_buffer_length,
					 state->max_input_length,
					 &input_next_offset,
					 &state->out_input_buffer);
	if (tevent_req_nterror(req, error)) {
		return;
	}

	/*
	 * If output data is returned, the output offset MUST be set to
	 * InputOffset + InputCount rounded up to a multiple of 8.
	 */
	output_min_offset = NDR_ROUND(input_next_offset, 8);
	output_next_offset = 0; /* this variable is completely ignored */
	error = smb2cli_parse_dyn_buffer(dyn_ofs,
					 dyn_buffer,
					 output_min_offset,
					 output_buffer_offset,
					 output_buffer_length,
					 state->max_output_length,
					 &output_next_offset,
					 &state->out_output_buffer);
	if (tevent_req_nterror(req, error)) {
		return;
	}

	state->out_valid = true;

	if (tevent_req_nterror(req, status)) {
		return;
	}

	tevent_req_done(req);
}

NTSTATUS smb2cli_ioctl_recv(struct tevent_req *req,
			    TALLOC_CTX *mem_ctx,
			    DATA_BLOB *out_input_buffer,
			    DATA_BLOB *out_output_buffer)
{
	struct smb2cli_ioctl_state *state =
		tevent_req_data(req,
		struct smb2cli_ioctl_state);
	NTSTATUS status = NT_STATUS_OK;

	if (tevent_req_is_nterror(req, &status) && !state->out_valid) {
		if (out_input_buffer) {
			*out_input_buffer = data_blob_null;
		}
		if (out_output_buffer) {
			*out_output_buffer = data_blob_null;
		}
		tevent_req_received(req);
		return status;
	}

	talloc_steal(mem_ctx, state->recv_iov);
	if (out_input_buffer) {
		*out_input_buffer = state->out_input_buffer;
	}
	if (out_output_buffer) {
		*out_output_buffer = state->out_output_buffer;
	}

	tevent_req_received(req);
	return status;
}

NTSTATUS smb2cli_ioctl(struct smbXcli_conn *conn,
		       uint32_t timeout_msec,
		       struct smbXcli_session *session,
		       struct smbXcli_tcon *tcon,
		       uint64_t in_fid_persistent,
		       uint64_t in_fid_volatile,
		       uint32_t in_ctl_code,
		       uint32_t in_max_input_length,
		       const DATA_BLOB *in_input_buffer,
		       uint32_t in_max_output_length,
		       const DATA_BLOB *in_output_buffer,
		       uint32_t in_flags,
		       TALLOC_CTX *mem_ctx,
		       DATA_BLOB *out_input_buffer,
		       DATA_BLOB *out_output_buffer)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct tevent_context *ev;
	struct tevent_req *req;
	NTSTATUS status = NT_STATUS_NO_MEMORY;

	if (smbXcli_conn_has_async_calls(conn)) {
		/*
		 * Can't use sync call while an async call is in flight
		 */
		status = NT_STATUS_INVALID_PARAMETER_MIX;
		goto fail;
	}
	ev = samba_tevent_context_init(frame);
	if (ev == NULL) {
		goto fail;
	}
	req = smb2cli_ioctl_send(frame, ev, conn, timeout_msec,
				 session, tcon,
				 in_fid_persistent,
				 in_fid_volatile,
				 in_ctl_code,
				 in_max_input_length,
				 in_input_buffer,
				 in_max_output_length,
				 in_output_buffer,
				 in_flags);
	if (req == NULL) {
		goto fail;
	}
	if (!tevent_req_poll_ntstatus(req, ev, &status)) {
		goto fail;
	}
	status = smb2cli_ioctl_recv(req, mem_ctx,
				    out_input_buffer,
				    out_output_buffer);
 fail:
	TALLOC_FREE(frame);
	return status;
}
