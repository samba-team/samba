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
#include "../libcli/smb/smbXcli_base.h"
#include "smb2cli.h"
#include "libsmb/proto.h"
#include "lib/util/tevent_ntstatus.h"

struct smb2cli_tcon_state {
	struct cli_state *cli;
	uint8_t fixed[8];
	uint8_t dyn_pad[1];
};

static void smb2cli_tcon_done(struct tevent_req *subreq);

struct tevent_req *smb2cli_tcon_send(TALLOC_CTX *mem_ctx,
				     struct tevent_context *ev,
				     struct cli_state *cli,
				     const char *share)
{
	struct tevent_req *req, *subreq;
	struct smb2cli_tcon_state *state;
	uint8_t *fixed;
	char srv_ip[INET6_ADDRSTRLEN];
	const char *tcon_share;
	uint8_t *dyn;
	size_t dyn_len;

	req = tevent_req_create(mem_ctx, &state, struct smb2cli_tcon_state);
	if (req == NULL) {
		return NULL;
	}
	state->cli = cli;

	print_sockaddr(srv_ip, sizeof(srv_ip), smbXcli_conn_remote_sockaddr(cli->conn));

	tcon_share = talloc_asprintf(state, "\\\\%s\\%s",
				     srv_ip, share);
	if (tevent_req_nomem(tcon_share, req)) {
		return tevent_req_post(req, ev);
	}
	if (!convert_string_talloc(state, CH_UNIX, CH_UTF16,
				   tcon_share, strlen(tcon_share),
				   &dyn, &dyn_len)) {
		tevent_req_oom(req);
		return tevent_req_post(req, ev);
	}

	if (strlen(tcon_share) == 0) {
		TALLOC_FREE(dyn);
		dyn_len = 0;
	}

	fixed = state->fixed;
	SSVAL(fixed, 0, 9);
	SSVAL(fixed, 4, SMB2_HDR_BODY + 8);
	SSVAL(fixed, 6, dyn_len);

	if (dyn_len == 0) {
		dyn = state->dyn_pad;;
		dyn_len = sizeof(state->dyn_pad);
	}

	subreq = smb2cli_req_send(state, ev, cli->conn, SMB2_OP_TCON,
				  0, 0, /* flags */
				  cli->timeout,
				  NULL, /* tcon */
				  cli->smb2.session,
				  state->fixed, sizeof(state->fixed),
				  dyn, dyn_len);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, smb2cli_tcon_done, req);
	return req;
}

static void smb2cli_tcon_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct smb2cli_tcon_state *state = tevent_req_data(
		req, struct smb2cli_tcon_state);
	struct cli_state *cli = state->cli;
	NTSTATUS status;
	struct iovec *iov;
	uint8_t *body;
	uint32_t tcon_id;
	uint8_t share_type;
	uint32_t share_flags;
	uint32_t share_capabilities;
	uint32_t maximal_access;
	static const struct smb2cli_req_expected_response expected[] = {
	{
		.status = NT_STATUS_OK,
		.body_size = 0x10
	}
	};

	status = smb2cli_req_recv(subreq, state, &iov,
				  expected, ARRAY_SIZE(expected));
	TALLOC_FREE(subreq);
	if (!NT_STATUS_IS_OK(status)) {
		tevent_req_nterror(req, status);
		return;
	}

	tcon_id = IVAL(iov[0].iov_base, SMB2_HDR_TID);

	body = (uint8_t *)iov[1].iov_base;
	share_type		= CVAL(body, 0x02);
	share_flags		= IVAL(body, 0x04);
	share_capabilities	= IVAL(body, 0x08);
	maximal_access		= IVAL(body, 0x0C);

	cli->smb2.tcon = smbXcli_tcon_create(cli);
	if (tevent_req_nomem(cli->smb2.tcon, req)) {
		return;
	}

	smb2cli_tcon_set_values(cli->smb2.tcon,
				cli->smb2.session,
				tcon_id,
				share_type,
				share_flags,
				share_capabilities,
				maximal_access);

	tevent_req_done(req);
}

NTSTATUS smb2cli_tcon_recv(struct tevent_req *req)
{
	return tevent_req_simple_recv_ntstatus(req);
}

NTSTATUS smb2cli_tcon(struct cli_state *cli, const char *share)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct tevent_context *ev;
	struct tevent_req *req;
	NTSTATUS status = NT_STATUS_NO_MEMORY;

	if (smbXcli_conn_has_async_calls(cli->conn)) {
		/*
		 * Can't use sync call while an async call is in flight
		 */
		status = NT_STATUS_INVALID_PARAMETER;
		goto fail;
	}
	ev = tevent_context_init(frame);
	if (ev == NULL) {
		goto fail;
	}
	req = smb2cli_tcon_send(frame, ev, cli, share);
	if (req == NULL) {
		goto fail;
	}
	if (!tevent_req_poll_ntstatus(req, ev, &status)) {
		goto fail;
	}
	status = smb2cli_tcon_recv(req);
 fail:
	TALLOC_FREE(frame);
	return status;
}

struct smb2cli_tdis_state {
	struct cli_state *cli;
	uint8_t fixed[4];
};

static void smb2cli_tdis_done(struct tevent_req *subreq);

struct tevent_req *smb2cli_tdis_send(TALLOC_CTX *mem_ctx,
				      struct tevent_context *ev,
				      struct cli_state *cli)
{
	struct tevent_req *req, *subreq;
	struct smb2cli_tdis_state *state;

	req = tevent_req_create(mem_ctx, &state,
				struct smb2cli_tdis_state);
	if (req == NULL) {
		return NULL;
	}
	state->cli = cli;
	SSVAL(state->fixed, 0, 4);

	subreq = smb2cli_req_send(state, ev, cli->conn, SMB2_OP_TDIS,
				  0, 0, /* flags */
				  cli->timeout,
				  cli->smb2.tcon,
				  cli->smb2.session,
				  state->fixed, sizeof(state->fixed),
				  NULL, 0);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, smb2cli_tdis_done, req);
	return req;
}

static void smb2cli_tdis_done(struct tevent_req *subreq)
{
	struct tevent_req *req =
		tevent_req_callback_data(subreq,
		struct tevent_req);
	struct smb2cli_tdis_state *state =
		tevent_req_data(req,
		struct smb2cli_tdis_state);
	NTSTATUS status;
	static const struct smb2cli_req_expected_response expected[] = {
	{
		.status = NT_STATUS_OK,
		.body_size = 0x04
	}
	};

	status = smb2cli_req_recv(subreq, NULL, NULL,
				  expected, ARRAY_SIZE(expected));
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		return;
	}
	TALLOC_FREE(state->cli->smb2.tcon);
	tevent_req_done(req);
}

NTSTATUS smb2cli_tdis_recv(struct tevent_req *req)
{
	return tevent_req_simple_recv_ntstatus(req);
}

NTSTATUS smb2cli_tdis(struct cli_state *cli)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct tevent_context *ev;
	struct tevent_req *req;
	NTSTATUS status = NT_STATUS_NO_MEMORY;

	if (smbXcli_conn_has_async_calls(cli->conn)) {
		/*
		 * Can't use sync call while an async call is in flight
		 */
		status = NT_STATUS_INVALID_PARAMETER;
		goto fail;
	}
	ev = tevent_context_init(frame);
	if (ev == NULL) {
		goto fail;
	}
	req = smb2cli_tdis_send(frame, ev, cli);
	if (req == NULL) {
		goto fail;
	}
	if (!tevent_req_poll_ntstatus(req, ev, &status)) {
		goto fail;
	}
	status = smb2cli_tdis_recv(req);
 fail:
	TALLOC_FREE(frame);
	return status;
}
