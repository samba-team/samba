/*
 * Unix SMB/CIFS implementation.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "source3/include/includes.h"
#include "source3/torture/proto.h"
#include "librpc/gen_ndr/ndr_spoolss_c.h"
#include "lib/util/tevent_ntstatus.h"
#include "source3/rpc_client/rpc_client.h"
#include "source3/rpc_client/cli_pipe.h"
#include "libcli/smb/smbXcli_base.h"

extern int torture_nprocs;
extern int torture_numops;

struct rpc_scale_one_state {
	struct tevent_context *ev;
	struct cli_state *cli;
	size_t num_iterations;
	struct rpc_pipe_client *rpccli;
	DATA_BLOB buffer;
	uint32_t needed;
	uint32_t num_printers;
	union spoolss_PrinterInfo *printers;
};

static void rpc_scale_one_opened(struct tevent_req *subreq);
static void rpc_scale_one_bound(struct tevent_req *subreq);
static void rpc_scale_one_listed(struct tevent_req *subreq);

static struct tevent_req *rpc_scale_one_send(
	TALLOC_CTX *mem_ctx,
	struct tevent_context *ev,
	struct cli_state *cli,
	size_t num_iterations)
{
	struct tevent_req *req = NULL, *subreq = NULL;
	struct rpc_scale_one_state *state = NULL;

	req = tevent_req_create(mem_ctx, &state, struct rpc_scale_one_state);
	if (req == NULL) {
		return NULL;
	}
	state->ev = ev;
	state->cli = cli;
	state->num_iterations = num_iterations;

	subreq = rpc_pipe_open_np_send(
		state, ev, cli, &ndr_table_spoolss);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, rpc_scale_one_opened, req);
	return req;
}

static void rpc_scale_one_opened(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct rpc_scale_one_state *state = tevent_req_data(
		req, struct rpc_scale_one_state);
	struct pipe_auth_data *auth = NULL;
	NTSTATUS status;

	status = rpc_pipe_open_np_recv(subreq, state, &state->rpccli);
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		return;
	}

	status = rpccli_anon_bind_data(state, &auth);
	if (tevent_req_nterror(req, status)) {
		return;
	}

	subreq = rpc_pipe_bind_send(state, state->ev, state->rpccli, auth);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, rpc_scale_one_bound, req);
}

static void rpc_scale_one_bound(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct rpc_scale_one_state *state = tevent_req_data(
		req, struct rpc_scale_one_state);
	char *server = NULL;
	NTSTATUS status;

	status = rpc_pipe_bind_recv(subreq);
	if (tevent_req_nterror(req, status)) {
		return;
	}

	server = talloc_asprintf(
		state,
		"\\%s\n",
		smbXcli_conn_remote_name(state->cli->conn));
	if (tevent_req_nomem(server, req)) {
		return;
	}
	state->buffer = data_blob_talloc(state, NULL, 4096);
	if (tevent_req_nomem(state->buffer.data, req)) {
		return;
	}

	subreq = dcerpc_spoolss_EnumPrinters_send(
		state,
		state->ev,
		state->rpccli->binding_handle,
		PRINTER_ENUM_LOCAL,
		server,
		1,		/* level */
		&state->buffer,
		state->buffer.length,
		&state->num_printers,
		&state->printers,
		&state->needed);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, rpc_scale_one_listed, req);
}

static void rpc_scale_one_listed(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct rpc_scale_one_state *state = tevent_req_data(
		req, struct rpc_scale_one_state);
	NTSTATUS status;
	WERROR result;

	status = dcerpc_spoolss_EnumPrinters_recv(subreq, state, &result);
	if (tevent_req_nterror(req, status)) {
		return;
	}

	if (!W_ERROR_IS_OK(result)) {
		status = werror_to_ntstatus(result);
		tevent_req_nterror(req, status);
		return;
	}

	/*
	 * This will trigger a sync close. Making that async will be a
	 * lot of effort, and even with this being sync this test is
	 * nasty enough.
	 */
	TALLOC_FREE(state->rpccli);

	state->num_iterations -= 1;

	if (state->num_iterations == 0) {
		tevent_req_done(req);
		return;
	}

	subreq = rpc_pipe_open_np_send(
		state, state->ev, state->cli, &ndr_table_spoolss);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, rpc_scale_one_opened, req);
}

static NTSTATUS rpc_scale_one_recv(struct tevent_req *req)
{
	return tevent_req_simple_recv_ntstatus(req);
}

struct rpc_scale_state {
	size_t num_reqs;
	size_t done;
};

static void rpc_scale_done(struct tevent_req *subreq);

static struct tevent_req *rpc_scale_send(
	TALLOC_CTX *mem_ctx,
	struct tevent_context *ev,
	struct cli_state **clis)
{
	struct tevent_req *req = NULL;
	struct rpc_scale_state *state = NULL;
	size_t i, num_clis = talloc_array_length(clis);

	req = tevent_req_create(mem_ctx, &state, struct rpc_scale_state);
	if (req == NULL) {
		return NULL;
	}
	state->num_reqs = num_clis;

	for (i=0; i<num_clis; i++) {
		struct tevent_req *subreq = rpc_scale_one_send(
			state, ev, clis[i], torture_numops);
		if (tevent_req_nomem(subreq, req)) {
			return tevent_req_post(req, ev);
		}
		tevent_req_set_callback(subreq, rpc_scale_done, req);
	}
	return req;
}

static void rpc_scale_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct rpc_scale_state *state = tevent_req_data(
		req, struct rpc_scale_state);
	NTSTATUS status;

	status = rpc_scale_one_recv(subreq);
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		return;
	}

	state->done += 1;

	if (state->done == state->num_reqs) {
		tevent_req_done(req);
	}
}

static NTSTATUS rpc_scale_recv(struct tevent_req *req)
{
	return tevent_req_simple_recv_ntstatus(req);
}

bool run_rpc_scale(int dummy)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct cli_state **clis = NULL;
	struct tevent_req *req = NULL;
	struct tevent_context *ev = NULL;
	bool ok, result = false;
	NTSTATUS status;
	int i;

	clis = talloc_zero_array(
		talloc_tos(), struct cli_state *, torture_nprocs);
	if (clis == NULL) {
		fprintf(stderr, "talloc failed\n");
		goto fail;
	}

	for (i=0; i<torture_nprocs; i++) {
		ok = torture_open_connection_flags(&clis[i], i, 0);
		if (!ok) {
			fprintf(stderr, "could not open connection %d\n", i);
			goto fail;
		}
	}

	ev = samba_tevent_context_init(talloc_tos());
	if (ev == NULL) {
		goto fail;
	}

	req = rpc_scale_send(talloc_tos(), ev, clis);
	if (req == NULL) {
		goto fail;
	}

	ok = tevent_req_poll_ntstatus(req, ev, &status);
	if (!ok) {
		fprintf(stderr,
			"rpc_scale_send failed: %s\n",
			nt_errstr(status));
		goto fail;
	}

	status = rpc_scale_recv(req);
	if (!NT_STATUS_IS_OK(status)) {
		fprintf(stderr, "rpc_scale failed: %s\n", nt_errstr(status));
		goto fail;
	}

	result = true;
fail:
	TALLOC_FREE(frame);
	return result;
}
