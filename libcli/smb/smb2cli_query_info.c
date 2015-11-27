/*
   Unix SMB/CIFS implementation.
   smb2 lib
   Copyright (C) Stefan Metzmacher 2012

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

struct smb2cli_query_info_state {
	uint8_t fixed[0x28];
	uint8_t dyn_pad[1];
	uint32_t max_output_length;
	struct iovec *recv_iov;
	DATA_BLOB out_output_buffer;
	bool out_valid;
};

static void smb2cli_query_info_done(struct tevent_req *subreq);

struct tevent_req *smb2cli_query_info_send(TALLOC_CTX *mem_ctx,
					   struct tevent_context *ev,
					   struct smbXcli_conn *conn,
					   uint32_t timeout_msec,
					   struct smbXcli_session *session,
					   struct smbXcli_tcon *tcon,
					   uint8_t in_info_type,
					   uint8_t in_file_info_class,
					   uint32_t in_max_output_length,
					   const DATA_BLOB *in_input_buffer,
					   uint32_t in_additional_info,
					   uint32_t in_flags,
					   uint64_t in_fid_persistent,
					   uint64_t in_fid_volatile)
{
	struct tevent_req *req, *subreq;
	struct smb2cli_query_info_state *state;
	uint8_t *fixed;
	uint8_t *dyn;
	size_t dyn_len;
	uint16_t input_buffer_offset = 0;
	uint32_t input_buffer_length = 0;

	req = tevent_req_create(mem_ctx, &state,
				struct smb2cli_query_info_state);
	if (req == NULL) {
		return NULL;
	}
	state->max_output_length = in_max_output_length;

	if (in_input_buffer) {
		input_buffer_offset = SMB2_HDR_BODY+0x28;
		input_buffer_length = in_input_buffer->length;
	}

	fixed = state->fixed;

	SSVAL(fixed, 0x00, 0x29);
	SCVAL(fixed, 0x02, in_info_type);
	SCVAL(fixed, 0x03, in_file_info_class); /* reserved */
	SIVAL(fixed, 0x04, in_max_output_length);
	SSVAL(fixed, 0x08, input_buffer_offset);
	SSVAL(fixed, 0x0A, 0); /* reserved */
	SIVAL(fixed, 0x0C, input_buffer_length);
	SIVAL(fixed, 0x10, in_additional_info);
	SIVAL(fixed, 0x14, in_flags);
	SBVAL(fixed, 0x18, in_fid_persistent);
	SBVAL(fixed, 0x20, in_fid_volatile);

	if (input_buffer_length > 0) {
		dyn = in_input_buffer->data;
		dyn_len = in_input_buffer->length;
	} else {
		dyn = state->dyn_pad;
		dyn_len = sizeof(state->dyn_pad);
	}

	subreq = smb2cli_req_send(state, ev, conn, SMB2_OP_GETINFO,
				  0, 0, /* flags */
				  timeout_msec,
				  tcon,
				  session,
				  state->fixed, sizeof(state->fixed),
				  dyn, dyn_len,
				  in_max_output_length); /* max_dyn_len */
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, smb2cli_query_info_done, req);
	return req;
}

static void smb2cli_query_info_done(struct tevent_req *subreq)
{
	struct tevent_req *req =
		tevent_req_callback_data(subreq,
		struct tevent_req);
	struct smb2cli_query_info_state *state =
		tevent_req_data(req,
		struct smb2cli_query_info_state);
	NTSTATUS status;
	struct iovec *iov;
	uint8_t *fixed;
	uint8_t *dyn;
	size_t dyn_len;
	uint32_t dyn_ofs = SMB2_HDR_BODY + 0x08;
	uint32_t output_buffer_offset;
	uint32_t output_buffer_length;
	static const struct smb2cli_req_expected_response expected[] = {
	{
		.status = NT_STATUS_OK,
		.body_size = 0x09
	},
	{
		.status = STATUS_BUFFER_OVERFLOW,
		.body_size = 0x09
	}
	};

	status = smb2cli_req_recv(subreq, state, &iov,
				  expected, ARRAY_SIZE(expected));
	TALLOC_FREE(subreq);
	if (NT_STATUS_EQUAL(status, STATUS_BUFFER_OVERFLOW)) {
		/* no error */
	} else {
		if (tevent_req_nterror(req, status)) {
			return;
		}
	}

	state->recv_iov = iov;
	fixed = (uint8_t *)iov[1].iov_base;
	dyn = (uint8_t *)iov[2].iov_base;
	dyn_len = iov[2].iov_len;

	output_buffer_offset = SVAL(fixed, 0x02);
	output_buffer_length = IVAL(fixed, 0x04);

	if ((output_buffer_offset > 0) && (output_buffer_length > 0)) {
		if (output_buffer_offset != dyn_ofs) {
			tevent_req_nterror(
				req, NT_STATUS_INVALID_NETWORK_RESPONSE);
			return;
		}

		if (output_buffer_length > dyn_len) {
			tevent_req_nterror(
				req, NT_STATUS_INVALID_NETWORK_RESPONSE);
			return;
		}

		if (output_buffer_length > state->max_output_length) {
			tevent_req_nterror(
				req, NT_STATUS_INVALID_NETWORK_RESPONSE);
			return;
		}

		state->out_output_buffer.data = dyn;
		state->out_output_buffer.length = output_buffer_length;
	}

	state->out_valid = true;

	if (tevent_req_nterror(req, status)) {
		return;
	}

	tevent_req_done(req);
}

NTSTATUS smb2cli_query_info_recv(struct tevent_req *req,
				 TALLOC_CTX *mem_ctx,
				 DATA_BLOB *out_output_buffer)
{
	struct smb2cli_query_info_state *state =
		tevent_req_data(req,
		struct smb2cli_query_info_state);
	NTSTATUS status = NT_STATUS_OK;

	if (tevent_req_is_nterror(req, &status) && !state->out_valid) {
		if (out_output_buffer) {
			*out_output_buffer = data_blob_null;
		}
		tevent_req_received(req);
		return status;
	}

	talloc_steal(mem_ctx, state->recv_iov);
	if (out_output_buffer) {
		*out_output_buffer = state->out_output_buffer;
	}

	tevent_req_received(req);
	return status;
}

NTSTATUS smb2cli_query_info(struct smbXcli_conn *conn,
			    uint32_t timeout_msec,
			    struct smbXcli_session *session,
			    struct smbXcli_tcon *tcon,
			    uint8_t in_info_type,
			    uint8_t in_file_info_class,
			    uint32_t in_max_output_length,
			    const DATA_BLOB *in_input_buffer,
			    uint32_t in_additional_info,
			    uint32_t in_flags,
			    uint64_t in_fid_persistent,
			    uint64_t in_fid_volatile,
			    TALLOC_CTX *mem_ctx,
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
	req = smb2cli_query_info_send(frame, ev,
				      conn, timeout_msec,
				      session, tcon,
				      in_info_type,
				      in_file_info_class,
				      in_max_output_length,
				      in_input_buffer,
				      in_additional_info,
				      in_flags,
				      in_fid_persistent,
				      in_fid_volatile);
	if (req == NULL) {
		goto fail;
	}
	if (!tevent_req_poll_ntstatus(req, ev, &status)) {
		goto fail;
	}
	status = smb2cli_query_info_recv(req, mem_ctx,
					 out_output_buffer);
 fail:
	TALLOC_FREE(frame);
	return status;
}
