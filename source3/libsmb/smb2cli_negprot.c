/*
   Unix SMB/CIFS implementation.
   smb2 lib
   Copyright (C) Volker Lendecke 2011

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
#include "client.h"
#include "async_smb.h"
#include "smb2cli_base.h"
#include "smb2cli.h"
#include "libsmb/proto.h"
#include "librpc/ndr/libndr.h"
#include "lib/util/tevent_ntstatus.h"

struct smb2cli_negprot_state {
	struct cli_state *cli;
	uint8_t fixed[36];
	uint8_t dyn[4];
};

static void smb2cli_negprot_done(struct tevent_req *subreq);

struct tevent_req *smb2cli_negprot_send(TALLOC_CTX *mem_ctx,
					struct tevent_context *ev,
					struct cli_state *cli)
{
	struct tevent_req *req, *subreq;
	struct smb2cli_negprot_state *state;
	uint8_t *buf;

	req = tevent_req_create(mem_ctx, &state,
				struct smb2cli_negprot_state);
	if (req == NULL) {
		return NULL;
	}
	state->cli = cli;

	buf = state->fixed;
	SSVAL(buf, 0, 36);
	SSVAL(buf, 2, 2);	/* DialectCount */
	if (client_is_signing_mandatory(cli)) {
		SSVAL(buf, 4, SMB2_NEGOTIATE_SIGNING_REQUIRED);
	} else {
		SSVAL(buf, 4, SMB2_NEGOTIATE_SIGNING_ENABLED);
	}
	SSVAL(buf, 6, 0);	/* Reserved */
	SSVAL(buf, 8, 0); 	/* Capabilities */
	memset(buf+12, 0, 16);	/* ClientGuid */
	SBVAL(buf, 28, 0);	/* ClientStartTime */

	buf = state->dyn;
	SSVAL(buf, 0, 0x202);	/* SMB2.002 */
	SSVAL(buf, 2, 0x210);	/* SMB2.1 */

	subreq = smb2cli_req_send(state, ev, cli, SMB2_OP_NEGPROT, 0,
				  state->fixed, sizeof(state->fixed),
				  state->dyn, sizeof(state->dyn));
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, smb2cli_negprot_done, req);
	return req;
}

static void smb2cli_negprot_done(struct tevent_req *subreq)
{
	struct tevent_req *req =
		tevent_req_callback_data(subreq,
		struct tevent_req);
	struct smb2cli_negprot_state *state =
		tevent_req_data(req,
		struct smb2cli_negprot_state);
	struct cli_state *cli = state->cli;
	size_t security_offset, security_length;
	DATA_BLOB blob;
	NTSTATUS status;
	struct iovec *iov;
	uint8_t *body;

	status = smb2cli_req_recv(subreq, talloc_tos(), &iov, 65);
	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(subreq);
		tevent_req_nterror(req, status);
		return;
	}
	body = (uint8_t *)iov[1].iov_base;

	cli->smb2.security_mode		= SVAL(body, 2);
	cli->smb2.dialect_revision	= SVAL(body, 4);

	blob = data_blob_const(body + 8, 16);
	GUID_from_data_blob(&blob, &cli->smb2.server_guid);

	cli->smb2.server_capabilities	= IVAL(body, 24);
	cli->smb2.max_transact_size	= IVAL(body, 28);
	cli->smb2.max_read_size		= IVAL(body, 32);
	cli->smb2.max_write_size	= IVAL(body, 36);
	cli->smb2.system_time		= interpret_long_date((char *)body + 40);
	cli->smb2.server_start_time	= interpret_long_date((char *)body + 48);

	security_offset		= SVAL(body, 56);
	security_length		= SVAL(body, 58);

	if ((security_offset != SMB2_HDR_BODY + iov[1].iov_len) ||
	    (security_length > iov[2].iov_len)) {
		tevent_req_nterror(req, NT_STATUS_INVALID_NETWORK_RESPONSE);
		return;
	}
	cli->secblob = data_blob(iov[1].iov_base, security_length);

	tevent_req_done(req);
}

NTSTATUS smb2cli_negprot_recv(struct tevent_req *req)
{
	return tevent_req_simple_recv_ntstatus(req);
}

NTSTATUS smb2cli_negprot(struct cli_state *cli)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct event_context *ev;
	struct tevent_req *req;
	NTSTATUS status = NT_STATUS_NO_MEMORY;

	if (cli_has_async_calls(cli)) {
		/*
		 * Can't use sync call while an async call is in flight
		 */
		status = NT_STATUS_INVALID_PARAMETER;
		goto fail;
	}
	ev = event_context_init(frame);
	if (ev == NULL) {
		goto fail;
	}
	req = smb2cli_negprot_send(frame, ev, cli);
	if (req == NULL) {
		goto fail;
	}
	if (!tevent_req_poll_ntstatus(req, ev, &status)) {
		goto fail;
	}
	status = smb2cli_negprot_recv(req);
 fail:
	TALLOC_FREE(frame);
	return status;
}

