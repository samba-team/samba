/*
 *  Unix SMB/CIFS implementation.
 *  RPC client transport over named pipes
 *  Copyright (C) Volker Lendecke 2009
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include "includes.h"
#include "../lib/util/tevent_ntstatus.h"
#include "rpc_client/rpc_transport.h"
#include "librpc/ndr/ndr_table.h"
#include "libcli/smb/smbXcli_base.h"
#include "libcli/smb/tstream_smbXcli_np.h"
#include "client.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_RPC_CLI

struct rpc_transport_np_init_state {
	struct rpc_cli_transport *transport;
	int retries;
	struct tevent_context *ev;
	struct smbXcli_conn *conn;
	int timeout;
	struct timeval abs_timeout;
	const char *pipe_name;
	struct smbXcli_session *session;
	struct smbXcli_tcon *tcon;
	uint16_t pid;
};

static void rpc_transport_np_init_pipe_open(struct tevent_req *subreq);

struct tevent_req *rpc_transport_np_init_send(TALLOC_CTX *mem_ctx,
					      struct tevent_context *ev,
					      struct cli_state *cli,
					      const struct ndr_interface_table *table)
{
	struct tevent_req *req;
	struct rpc_transport_np_init_state *state;
	struct tevent_req *subreq;

	req = tevent_req_create(mem_ctx, &state,
				struct rpc_transport_np_init_state);
	if (req == NULL) {
		return NULL;
	}

	if (smbXcli_conn_protocol(cli->conn) >= PROTOCOL_SMB2_02) {
		state->tcon = cli->smb2.tcon;
		state->session = cli->smb2.session;
	} else {
		state->tcon = cli->smb1.tcon;
		state->session = cli->smb1.session;
		state->pid = cli->smb1.pid;
	}

	state->ev = ev;
	state->conn = cli->conn;
	state->timeout = cli->timeout;
	state->abs_timeout = timeval_current_ofs_msec(cli->timeout);
	state->pipe_name = dcerpc_default_transport_endpoint(state, NCACN_NP,
							     table);
	if (tevent_req_nomem(state->pipe_name, req)) {
		return tevent_req_post(req, ev);
	}

	while (state->pipe_name[0] == '\\') {
		state->pipe_name++;
	}

	subreq = tstream_smbXcli_np_open_send(state, ev, state->conn,
					      state->session, state->tcon,
					      state->pid, state->timeout,
					      state->pipe_name);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, rpc_transport_np_init_pipe_open, req);

	return req;
}

static void rpc_transport_np_init_pipe_open_retry(struct tevent_context *ev,
						  struct tevent_timer *te,
						  struct timeval t,
						  void *priv_data)
{
	struct tevent_req *subreq;
	struct tevent_req *req = talloc_get_type(priv_data, struct tevent_req);
	struct rpc_transport_np_init_state *state = tevent_req_data(
		req, struct rpc_transport_np_init_state);

	subreq = tstream_smbXcli_np_open_send(state, ev,
					      state->conn,
					      state->session,
					      state->tcon,
					      state->pid,
					      state->timeout,
					      state->pipe_name);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, rpc_transport_np_init_pipe_open, req);
	state->retries++;
}

static void rpc_transport_np_init_pipe_open(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct rpc_transport_np_init_state *state = tevent_req_data(
		req, struct rpc_transport_np_init_state);
	NTSTATUS status;
	struct tstream_context *stream;

	status = tstream_smbXcli_np_open_recv(subreq, state, &stream);
	TALLOC_FREE(subreq);
	if (NT_STATUS_EQUAL(status, NT_STATUS_PIPE_NOT_AVAILABLE)
				&& (!timeval_expired(&state->abs_timeout))) {
		struct tevent_timer *te;
		/*
		 * Retry on STATUS_PIPE_NOT_AVAILABLE, Windows starts some
		 * servers (FssagentRpc) on demand.
		 */
		DEBUG(2, ("RPC pipe %s not available, retry %d\n",
			  state->pipe_name, state->retries));
		te = tevent_add_timer(state->ev, state,
				 timeval_current_ofs_msec(100 * state->retries),
				 rpc_transport_np_init_pipe_open_retry, req);
		if (tevent_req_nomem(te, req)) {
			DEBUG(2, ("Failed to create asynchronous "
					"tevent_timer"));
		}
		return;
	} else if (!NT_STATUS_IS_OK(status)) {
		tevent_req_nterror(req, status);
		return;
	}

	status = rpc_transport_tstream_init(state,
					    &stream,
					    &state->transport);
	if (!NT_STATUS_IS_OK(status)) {
		tevent_req_nterror(req, status);
		return;
	}

	tevent_req_done(req);
}

NTSTATUS rpc_transport_np_init_recv(struct tevent_req *req,
				    TALLOC_CTX *mem_ctx,
				    struct rpc_cli_transport **presult)
{
	struct rpc_transport_np_init_state *state = tevent_req_data(
		req, struct rpc_transport_np_init_state);
	NTSTATUS status;

	if (tevent_req_is_nterror(req, &status)) {
		return status;
	}

	*presult = talloc_move(mem_ctx, &state->transport);
	return NT_STATUS_OK;
}

NTSTATUS rpc_transport_np_init(TALLOC_CTX *mem_ctx, struct cli_state *cli,
			       const struct ndr_interface_table *table,
			       struct rpc_cli_transport **presult)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct tevent_context *ev;
	struct tevent_req *req;
	NTSTATUS status = NT_STATUS_OK;

	ev = samba_tevent_context_init(frame);
	if (ev == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto fail;
	}

	req = rpc_transport_np_init_send(frame, ev, cli, table);
	if (req == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto fail;
	}

	if (!tevent_req_poll_ntstatus(req, ev, &status)) {
		goto fail;
	}

	status = rpc_transport_np_init_recv(req, mem_ctx, presult);
 fail:
	TALLOC_FREE(frame);
	return status;
}
