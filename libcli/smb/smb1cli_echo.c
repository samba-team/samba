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

struct smb1cli_echo_state {
	uint16_t vwv[1];
	DATA_BLOB data;
	uint16_t num_echos;
};

static void smb1cli_echo_done(struct tevent_req *subreq);

struct tevent_req *smb1cli_echo_send(TALLOC_CTX *mem_ctx,
				     struct tevent_context *ev,
				     struct smbXcli_conn *conn,
				     uint32_t timeout_msec,
				     uint16_t num_echos,
				     DATA_BLOB data)
{
	struct tevent_req *req, *subreq;
	struct smb1cli_echo_state *state;

	req = tevent_req_create(mem_ctx, &state, struct smb1cli_echo_state);
	if (req == NULL) {
		return NULL;
	}
	SSVAL(state->vwv, 0, num_echos);
	state->data = data;
	state->num_echos = num_echos;

	subreq = smb1cli_req_send(state, ev, conn, SMBecho,
				  0, 0, /* *_flags */
				  0, 0, /* *_flags2 */
				  timeout_msec,
				  0, /* pid */
				  NULL, /* tcon */
				  NULL, /* session */
				  ARRAY_SIZE(state->vwv), state->vwv,
				  data.length, data.data);
	if (subreq == NULL) {
		goto fail;
	}
	tevent_req_set_callback(subreq, smb1cli_echo_done, req);
	return req;
 fail:
	TALLOC_FREE(req);
	return NULL;
}

static void smb1cli_echo_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct smb1cli_echo_state *state = tevent_req_data(
		req, struct smb1cli_echo_state);
	NTSTATUS status;
	uint32_t num_bytes;
	uint8_t *bytes;
	struct iovec *recv_iov;
	struct smb1cli_req_expected_response expected[] = {
	{
		.status = NT_STATUS_OK,
		.wct    = 1,
	},
	};

	status = smb1cli_req_recv(subreq, state,
				  &recv_iov,
				  NULL, /* phdr */
				  NULL, /* pwct */
				  NULL, /* pvwv */
				  NULL, /* pvwv_offset */
				  &num_bytes,
				  &bytes,
				  NULL, /* pbytes_offset */
				  NULL, /* pinbuf */
				  expected, ARRAY_SIZE(expected));
	if (!NT_STATUS_IS_OK(status)) {
		tevent_req_nterror(req, status);
		return;
	}

	if (num_bytes != state->data.length) {
		tevent_req_nterror(req, NT_STATUS_INVALID_NETWORK_RESPONSE);
		return;
	}

	if (memcmp(bytes, state->data.data, num_bytes) != 0) {
		tevent_req_nterror(req, NT_STATUS_INVALID_NETWORK_RESPONSE);
		return;
	}

	/* TODO: do we want to verify the sequence number? */

	state->num_echos -=1;
	if (state->num_echos == 0) {
		tevent_req_done(req);
		return;
	}

	if (!smbXcli_req_set_pending(subreq)) {
		tevent_req_nterror(req, NT_STATUS_NO_MEMORY);
		return;
	}
}

/**
 * Get the result out from an echo request
 * @param[in] req	The async_req from smb1cli_echo_send
 * @retval Did the server reply correctly?
 */

NTSTATUS smb1cli_echo_recv(struct tevent_req *req)
{
	return tevent_req_simple_recv_ntstatus(req);
}

NTSTATUS smb1cli_echo(struct smbXcli_conn *conn, uint32_t timeout_msec,
		      uint16_t num_echos, DATA_BLOB data)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct tevent_context *ev;
	struct tevent_req *req;
	NTSTATUS status = NT_STATUS_NO_MEMORY;

	if (smbXcli_conn_has_async_calls(conn)) {
		/*
		 * Can't use sync call while an async call is in flight
		 */
		status = NT_STATUS_INVALID_PARAMETER;
		goto fail;
	}
	ev = samba_tevent_context_init(frame);
	if (ev == NULL) {
		goto fail;
	}
	req = smb1cli_echo_send(frame, ev, conn, timeout_msec, num_echos, data);
	if (req == NULL) {
		goto fail;
	}
	if (!tevent_req_poll_ntstatus(req, ev, &status)) {
		goto fail;
	}
	status = smb1cli_echo_recv(req);
 fail:
	TALLOC_FREE(frame);
	return status;
}
