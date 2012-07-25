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

struct smb2cli_set_info_state {
	uint8_t fixed[0x20];
	uint8_t dyn_pad[1];
};

static void smb2cli_set_info_done(struct tevent_req *subreq);

struct tevent_req *smb2cli_set_info_send(TALLOC_CTX *mem_ctx,
					 struct tevent_context *ev,
					 struct smbXcli_conn *conn,
					 uint32_t timeout_msec,
					 struct smbXcli_session *session,
					 struct smbXcli_tcon *tcon,
					 uint8_t in_info_type,
					 uint8_t in_file_info_class,
					 const DATA_BLOB *in_input_buffer,
					 uint32_t in_additional_info,
					 uint64_t in_fid_persistent,
					 uint64_t in_fid_volatile)
{
	struct tevent_req *req, *subreq;
	struct smb2cli_set_info_state *state;
	uint8_t *fixed;
	uint8_t *dyn;
	size_t dyn_len;
	uint16_t input_buffer_offset = 0;
	uint32_t input_buffer_length = 0;

	req = tevent_req_create(mem_ctx, &state,
				struct smb2cli_set_info_state);
	if (req == NULL) {
		return NULL;
	}

	if (in_input_buffer) {
		input_buffer_offset = SMB2_HDR_BODY+0x20;
		input_buffer_length = in_input_buffer->length;
	}

	fixed = state->fixed;

	SSVAL(fixed, 0x00, 0x21);
	SCVAL(fixed, 0x02, in_info_type);
	SCVAL(fixed, 0x03, in_file_info_class);
	SIVAL(fixed, 0x04, input_buffer_length);
	SSVAL(fixed, 0x08, input_buffer_offset);
	SSVAL(fixed, 0x0A, 0); /* reserved */
	SIVAL(fixed, 0x0C, in_additional_info);
	SBVAL(fixed, 0x10, in_fid_persistent);
	SBVAL(fixed, 0x18, in_fid_volatile);

	if (input_buffer_length > 0) {
		dyn = in_input_buffer->data;
		dyn_len = in_input_buffer->length;
	} else {
		dyn = state->dyn_pad;
		dyn_len = sizeof(state->dyn_pad);
	}

	subreq = smb2cli_req_send(state, ev, conn, SMB2_OP_SETINFO,
				  0, 0, /* flags */
				  timeout_msec,
				  tcon,
				  session,
				  state->fixed, sizeof(state->fixed),
				  dyn, dyn_len);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, smb2cli_set_info_done, req);
	return req;
}

static void smb2cli_set_info_done(struct tevent_req *subreq)
{
	struct tevent_req *req =
		tevent_req_callback_data(subreq,
		struct tevent_req);
	NTSTATUS status;
	static const struct smb2cli_req_expected_response expected[] = {
	{
		.status = NT_STATUS_OK,
		.body_size = 0x02
	},
	};

	status = smb2cli_req_recv(subreq, NULL, NULL,
				  expected, ARRAY_SIZE(expected));
	if (tevent_req_nterror(req, status)) {
		return;
	}

	tevent_req_done(req);
}

NTSTATUS smb2cli_set_info_recv(struct tevent_req *req)
{
	NTSTATUS status;

	if (tevent_req_is_nterror(req, &status)) {
		tevent_req_received(req);
		return status;
	}

	tevent_req_received(req);
	return NT_STATUS_OK;
}

NTSTATUS smb2cli_set_info(struct smbXcli_conn *conn,
			  uint32_t timeout_msec,
			  struct smbXcli_session *session,
			  struct smbXcli_tcon *tcon,
			  uint8_t in_info_type,
			  uint8_t in_file_info_class,
			  const DATA_BLOB *in_input_buffer,
			  uint32_t in_additional_info,
			  uint64_t in_fid_persistent,
			  uint64_t in_fid_volatile)
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
	ev = tevent_context_init(frame);
	if (ev == NULL) {
		goto fail;
	}
	req = smb2cli_set_info_send(frame, ev,
				    conn, timeout_msec,
				    session, tcon,
				    in_info_type,
				    in_file_info_class,
				    in_input_buffer,
				    in_additional_info,
				    in_fid_persistent,
				    in_fid_volatile);
	if (req == NULL) {
		goto fail;
	}
	if (!tevent_req_poll_ntstatus(req, ev, &status)) {
		goto fail;
	}
	status = smb2cli_set_info_recv(req);

 fail:
	TALLOC_FREE(frame);
	return status;
}
