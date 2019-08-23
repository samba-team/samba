/*
   Unix SMB/CIFS implementation.
   Main metadata server / Spotlight client functions

   Copyright (C) Ralph Boehme 2019

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
#include "rpc_client.h"
#include "../librpc/gen_ndr/ndr_mdssvc_c.h"
#include "lib/util/tevent_ntstatus.h"
#include "rpc_server/mdssvc/dalloc.h"
#include "rpc_server/mdssvc/marshalling.h"
#include "cli_mdssvc.h"
#include "cli_mdssvc_private.h"
#include "cli_mdssvc_util.h"

struct mdsctx_id mdscli_new_ctx_id(struct mdscli_ctx *mdscli_ctx)
{
	mdscli_ctx->ctx_id.id++;
	return mdscli_ctx->ctx_id;
}

char *mdscli_get_basepath(TALLOC_CTX *mem_ctx,
			  struct mdscli_ctx *mdscli_ctx)
{
	return talloc_strdup(mem_ctx, mdscli_ctx->mdscmd_open.share_path);
}

struct mdscli_connect_state {
	struct tevent_context *ev;
	struct mdscli_ctx *mdscli_ctx;
};

static void mdscli_connect_open_done(struct tevent_req *subreq);
static void mdscli_connect_unknown1_done(struct tevent_req *subreq);

struct tevent_req *mdscli_connect_send(TALLOC_CTX *mem_ctx,
				       struct tevent_context *ev,
				       struct dcerpc_binding_handle *bh,
				       const char *share_name,
				       const char *mount_path)
{
	struct tevent_req *req = NULL;
	struct mdscli_connect_state *state = NULL;
	struct tevent_req *subreq = NULL;
	struct mdscli_ctx *ctx = NULL;

	req = tevent_req_create(req, &state, struct mdscli_connect_state);
	if (req == NULL) {
		return NULL;
	}

	ctx = talloc_zero(state, struct mdscli_ctx);
	if (tevent_req_nomem(ctx, req)) {
		return tevent_req_post(req, ev);
	}

	*state = (struct mdscli_connect_state) {
		.ev = ev,
		.mdscli_ctx = ctx,
	};

	*ctx = (struct mdscli_ctx) {
		.bh = bh,
		.max_fragment_size = 64 * 1024,
		/*
		 * The connection id is a per tcon value sent by the client,
		 * 0x6b000060 is a value used most of the times for the first
		 * tcon.
		 */
		.ctx_id.connection = UINT64_C(0x6b000060),
	};

	subreq = dcerpc_mdssvc_open_send(state,
					 state->ev,
					 ctx->bh,
					 &ctx->dev,
					 &ctx->mdscmd_open.unkn2,
					 &ctx->mdscmd_open.unkn3,
					 mount_path,
					 share_name,
					 ctx->mdscmd_open.share_path,
					 &ctx->ph);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, state->ev);
	}
	tevent_req_set_callback(subreq, mdscli_connect_open_done, req);
	ctx->async_pending++;

	return req;
}

static void mdscli_connect_open_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct mdscli_connect_state *state = tevent_req_data(
		req, struct mdscli_connect_state);
	struct mdscli_ctx *mdscli_ctx = state->mdscli_ctx;
	NTSTATUS status;

	status = dcerpc_mdssvc_open_recv(subreq, state);
	TALLOC_FREE(subreq);
	state->mdscli_ctx->async_pending--;
	if (tevent_req_nterror(req, status)) {
		return;
	}

	subreq = dcerpc_mdssvc_unknown1_send(
			state,
			state->ev,
			mdscli_ctx->bh,
			&mdscli_ctx->ph,
			0,
			mdscli_ctx->dev,
			mdscli_ctx->mdscmd_open.unkn2,
			0,
			geteuid(),
			getegid(),
			&mdscli_ctx->mdscmd_unknown1.status,
			&mdscli_ctx->flags,
			&mdscli_ctx->mdscmd_unknown1.unkn7);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, mdscli_connect_unknown1_done, req);
}

static void mdscli_connect_unknown1_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct mdscli_connect_state *state = tevent_req_data(
		req, struct mdscli_connect_state);
	NTSTATUS status;

	status = dcerpc_mdssvc_unknown1_recv(subreq, state);
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		return;
	}

	tevent_req_done(req);
}

NTSTATUS mdscli_connect_recv(struct tevent_req *req,
			     TALLOC_CTX *mem_ctx,
			     struct mdscli_ctx **mdscli_ctx)
{
	struct mdscli_connect_state *state = tevent_req_data(
		req, struct mdscli_connect_state);
	NTSTATUS status;

	if (tevent_req_is_nterror(req, &status)) {
		tevent_req_received(req);
		return status;
	}

	*mdscli_ctx = talloc_move(mem_ctx, &state->mdscli_ctx);
	tevent_req_received(req);
	return NT_STATUS_OK;
}

NTSTATUS mdscli_connect(TALLOC_CTX *mem_ctx,
			struct dcerpc_binding_handle *bh,
			const char *share_name,
			const char *mount_path,
			struct mdscli_ctx **mdscli_ctx)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct tevent_req *req = NULL;
	struct tevent_context *ev = NULL;
	NTSTATUS status = NT_STATUS_NO_MEMORY;

	ev = samba_tevent_context_init(frame);
	if (ev == NULL) {
		goto fail;
	}

	req = mdscli_connect_send(frame,
				  ev,
				  bh,
				  share_name,
				  mount_path);
	if (req == NULL) {
		goto fail;
	}
	if (!tevent_req_poll_ntstatus(req, ev, &status)) {
		goto fail;
	}

	status = mdscli_connect_recv(req, mem_ctx, mdscli_ctx);
fail:
	TALLOC_FREE(frame);
	return status;
}

struct mdscli_search_state {
	struct mdscli_search_ctx *search;
	struct mdssvc_blob request_blob;
	struct mdssvc_blob response_blob;
};

static void mdscli_search_cmd_done(struct tevent_req *subreq);

struct tevent_req *mdscli_search_send(TALLOC_CTX *mem_ctx,
				      struct tevent_context *ev,
				      struct mdscli_ctx *mdscli_ctx,
				      const char *mds_query,
				      const char *path_scope_in,
				      bool live)
{
	struct tevent_req *req = NULL;
	struct mdscli_search_state *state = NULL;
	struct tevent_req *subreq = NULL;
	struct mdscli_search_ctx *search = NULL;
	char *path_scope = NULL;
	NTSTATUS status;

	req = tevent_req_create(req, &state, struct mdscli_search_state);
	if (req == NULL) {
		return NULL;
	}

	search = talloc_zero(state, struct mdscli_search_ctx);
	if (tevent_req_nomem(search, req)) {
		return tevent_req_post(req, ev);
	}

	if (path_scope_in[0] == '/') {
		path_scope = talloc_strdup(search, path_scope_in);
	} else {
		path_scope = talloc_asprintf(search,
					     "%s/%s",
					     mdscli_ctx->mdscmd_open.share_path,
					     path_scope_in);
	}
	if (tevent_req_nomem(path_scope, req)) {
		return tevent_req_post(req, ev);
	}

	*search = (struct mdscli_search_ctx) {
		.mdscli_ctx = mdscli_ctx,
		.ctx_id = mdscli_new_ctx_id(mdscli_ctx),
		.unique_id = generate_random_u64(),
		.live = live,
		.path_scope = path_scope,
		.mds_query = talloc_strdup(search, mds_query),
	};
	if (tevent_req_nomem(search->mds_query, req)) {
		return tevent_req_post(req, ev);
	}

	*state = (struct mdscli_search_state) {
		.search = search,
	};

	status = mdscli_blob_search(state,
				    search,
				    &state->request_blob);
	if (tevent_req_nterror(req, status)) {
		return tevent_req_post(req, ev);
	}

	state->response_blob.spotlight_blob = talloc_array(
		state,
		uint8_t,
		mdscli_ctx->max_fragment_size);
	if (tevent_req_nomem(state->response_blob.spotlight_blob, req)) {
		return tevent_req_post(req, ev);
	}
	state->response_blob.size = mdscli_ctx->max_fragment_size;

	subreq = dcerpc_mdssvc_cmd_send(state,
					ev,
					mdscli_ctx->bh,
					&mdscli_ctx->ph,
					0,
					mdscli_ctx->dev,
					mdscli_ctx->mdscmd_open.unkn2,
					0,
					mdscli_ctx->flags,
					state->request_blob,
					0,
					mdscli_ctx->max_fragment_size,
					1,
					mdscli_ctx->max_fragment_size,
					0,
					0,
					&mdscli_ctx->mdscmd_cmd.fragment,
					&state->response_blob,
					&mdscli_ctx->mdscmd_cmd.unkn9);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, mdscli_search_cmd_done, req);
	mdscli_ctx->async_pending++;
	return req;
}

static void mdscli_search_cmd_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct mdscli_search_state *state = tevent_req_data(
		req, struct mdscli_search_state);
	DALLOC_CTX *d = NULL;
	uint64_t *uint64p = NULL;
	NTSTATUS status;
	bool ok;

	status = dcerpc_mdssvc_cmd_recv(subreq, state);
	TALLOC_FREE(subreq);
	state->search->mdscli_ctx->async_pending--;
	if (tevent_req_nterror(req, status)) {
		return;
	}

	d = dalloc_new(state);
	if (tevent_req_nomem(d, req)) {
		return;
	}

	ok = sl_unpack(d,
		       (char *)state->response_blob.spotlight_blob,
		       state->response_blob.length);
	if (!ok) {
		tevent_req_nterror(req, NT_STATUS_INTERNAL_ERROR);
		return;
	}

	uint64p = dalloc_get(d,
			     "DALLOC_CTX", 0,
			     "uint64_t", 0);
	if (uint64p == NULL) {
		DBG_DEBUG("Unexpected mds reponse: %s", dalloc_dump(d, 0));
		tevent_req_nterror(req, NT_STATUS_INTERNAL_ERROR);
		return;
	}

	if (*uint64p != 0) {
		DBG_DEBUG("Unexpected mds result: 0x%" PRIx64, *uint64p);
		tevent_req_nterror(req, NT_STATUS_INTERNAL_ERROR);
		return;
	}

	tevent_req_done(req);
	return;
}

NTSTATUS mdscli_search_recv(struct tevent_req *req,
			    TALLOC_CTX *mem_ctx,
			    struct mdscli_search_ctx **search)
{
	struct mdscli_search_state *state = tevent_req_data(
		req, struct mdscli_search_state);
	NTSTATUS status;

	if (tevent_req_is_nterror(req, &status)) {
		tevent_req_received(req);
		return status;
	}

	*search = talloc_move(mem_ctx, &state->search);
	tevent_req_received(req);
	return NT_STATUS_OK;
}

NTSTATUS mdscli_search(TALLOC_CTX *mem_ctx,
		       struct mdscli_ctx *mdscli_ctx,
		       const char *mds_query,
		       const char *path_scope,
		       bool live,
		       struct mdscli_search_ctx **search)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct tevent_req *req = NULL;
	struct tevent_context *ev = NULL;
	NTSTATUS status = NT_STATUS_NO_MEMORY;

	if (mdscli_ctx->async_pending != 0) {
		status = NT_STATUS_INVALID_PARAMETER;
		goto fail;
	}

	ev = samba_tevent_context_init(frame);
	if (ev == NULL) {
		goto fail;
	}

	req = mdscli_search_send(frame,
				 ev,
				 mdscli_ctx,
				 mds_query,
				 path_scope,
				 live);
	if (req == NULL) {
		goto fail;
	}
	if (!tevent_req_poll_ntstatus(req, ev, &status)) {
		goto fail;
	}

	status = mdscli_search_recv(req, mem_ctx, search);
fail:
	TALLOC_FREE(frame);
	return status;
}

struct mdscli_get_results_state {
	struct mdscli_search_ctx *search;
	struct mdssvc_blob request_blob;
	struct mdssvc_blob response_blob;
	uint64_t *cnids;
};

static void mdscli_get_results_cmd_done(struct tevent_req *subreq);

struct tevent_req *mdscli_get_results_send(
			TALLOC_CTX *mem_ctx,
			struct tevent_context *ev,
			struct mdscli_search_ctx *search)
{
	struct tevent_req *req = NULL;
	struct mdscli_get_results_state *state = NULL;
	struct tevent_req *subreq = NULL;
	struct mdscli_ctx *mdscli_ctx = search->mdscli_ctx;
	NTSTATUS status;

	req = tevent_req_create(req, &state, struct mdscli_get_results_state);
	if (req == NULL) {
		return NULL;
	}

	*state = (struct mdscli_get_results_state) {
		.search = search,
	};

	status = mdscli_blob_get_results(state,
					 search,
					 &state->request_blob);
	if (tevent_req_nterror(req, status)) {
		return tevent_req_post(req, ev);
	}

	state->response_blob.spotlight_blob = talloc_array(
		state,
		uint8_t,
		mdscli_ctx->max_fragment_size);
	if (tevent_req_nomem(state->response_blob.spotlight_blob, req)) {
		return tevent_req_post(req, ev);
	}
	state->response_blob.size = mdscli_ctx->max_fragment_size;

	subreq = dcerpc_mdssvc_cmd_send(state,
					ev,
					mdscli_ctx->bh,
					&mdscli_ctx->ph,
					0,
					mdscli_ctx->dev,
					mdscli_ctx->mdscmd_open.unkn2,
					0,
					mdscli_ctx->flags,
					state->request_blob,
					0,
					mdscli_ctx->max_fragment_size,
					1,
					mdscli_ctx->max_fragment_size,
					0,
					0,
					&mdscli_ctx->mdscmd_cmd.fragment,
					&state->response_blob,
					&mdscli_ctx->mdscmd_cmd.unkn9);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, mdscli_get_results_cmd_done, req);
	mdscli_ctx->async_pending++;
	return req;
}

static void mdscli_get_results_cmd_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct mdscli_get_results_state *state = tevent_req_data(
		req, struct mdscli_get_results_state);
	DALLOC_CTX *d = NULL;
	uint64_t *uint64p = NULL;
	sl_cnids_t *cnids = NULL;
	size_t ncnids;
	size_t i;
	NTSTATUS status;
	bool ok;

	status = dcerpc_mdssvc_cmd_recv(subreq, state);
	TALLOC_FREE(subreq);
	state->search->mdscli_ctx->async_pending--;
	if (tevent_req_nterror(req, status)) {
		return;
	}

	d = dalloc_new(state);
	if (tevent_req_nomem(d, req)) {
		return;
	}

	ok = sl_unpack(d,
		       (char *)state->response_blob.spotlight_blob,
		       state->response_blob.length);
	if (!ok) {
		tevent_req_nterror(req, NT_STATUS_INTERNAL_ERROR);
		return;
	}

	uint64p = dalloc_get(d,
			     "DALLOC_CTX", 0,
			     "uint64_t", 0);
	if (uint64p == NULL) {
		DBG_DEBUG("Unexpected mds reponse: %s", dalloc_dump(d, 0));
		tevent_req_nterror(req, NT_STATUS_INTERNAL_ERROR);
		return;
	}

	if (*uint64p == 35) {
		DBG_DEBUG("search done: %s", dalloc_dump(d, 0));
		tevent_req_done(req);
		return;
	}

	cnids = dalloc_get(d, "DALLOC_CTX", 0, "sl_cnids_t", 1);
	if (cnids == NULL) {
		DBG_DEBUG("cnids error: %s", dalloc_dump(d, 0));
		tevent_req_nterror(req, NT_STATUS_INTERNAL_ERROR);
		return;
	}

	ncnids = dalloc_size(cnids->ca_cnids);
	if (ncnids == 0) {
		tevent_req_nterror(req, NT_STATUS_NO_MORE_MATCHES);
		return;
	}

	if (cnids->ca_unkn1 != 0xadd) {
		/*
		 * Whatever 0xadd means... but it seems to be the standard value
		 * macOS mdssvc returns here.
		 */
		DBG_DEBUG("unexpected ca_unkn1: %s", dalloc_dump(d, 0));
		tevent_req_nterror(req, NT_STATUS_INTERNAL_ERROR);
		return;
	}

	if (cnids->ca_context != state->search->ctx_id.connection ) {
		DBG_DEBUG("unexpected ca_context: %s", dalloc_dump(d, 0));
		tevent_req_nterror(req, NT_STATUS_INTERNAL_ERROR);
		return;
	}

	state->cnids = talloc_zero_array(state, uint64_t, ncnids);
	if (tevent_req_nomem(state->cnids, req)) {
		return;
	}

	for (i = 0; i < ncnids; i++) {
		uint64_t *cnid = NULL;

		cnid = dalloc_get(cnids->ca_cnids, "uint64_t", i);
		if (cnid == NULL) {
			DBG_DEBUG("cnids error: %s", dalloc_dump(d, 0));
			tevent_req_nterror(req, NT_STATUS_INTERNAL_ERROR);
			return;
		}
		state->cnids[i] = *cnid;
	}

	tevent_req_done(req);
	return;
}

NTSTATUS mdscli_get_results_recv(struct tevent_req *req,
				 TALLOC_CTX *mem_ctx,
				 uint64_t **cnids)
{
	struct mdscli_get_results_state *state = tevent_req_data(
		req, struct mdscli_get_results_state);
	NTSTATUS status;

	if (tevent_req_is_nterror(req, &status)) {
		tevent_req_received(req);
		return status;
	}

	*cnids = talloc_move(mem_ctx, &state->cnids);

	tevent_req_received(req);
	return NT_STATUS_OK;
}

NTSTATUS mdscli_get_results(TALLOC_CTX *mem_ctx,
			    struct mdscli_search_ctx *search,
			    uint64_t **_cnids)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct tevent_req *req = NULL;
	struct tevent_context *ev = NULL;
	NTSTATUS status = NT_STATUS_NO_MEMORY;

	if (search->mdscli_ctx->async_pending != 0) {
		status = NT_STATUS_INVALID_PARAMETER;
		goto fail;
	}

	ev = samba_tevent_context_init(frame);
	if (ev == NULL) {
		goto fail;
	}

	req = mdscli_get_results_send(frame,
				      ev,
				      search);
	if (req == NULL) {
		goto fail;
	}
	if (!tevent_req_poll_ntstatus(req, ev, &status)) {
		goto fail;
	}

	status = mdscli_get_results_recv(req, mem_ctx, _cnids);
fail:
	TALLOC_FREE(frame);
	return status;
}

struct mdscli_get_path_state {
	struct mdscli_ctx *mdscli_ctx;
	struct mdssvc_blob request_blob;
	struct mdssvc_blob response_blob;
	char *path;
};

static void mdscli_get_path_done(struct tevent_req *subreq);

struct tevent_req *mdscli_get_path_send(TALLOC_CTX *mem_ctx,
					struct tevent_context *ev,
					struct mdscli_ctx *mdscli_ctx,
					uint64_t cnid)
{
	struct tevent_req *req = NULL;
	struct mdscli_get_path_state *state = NULL;
	struct tevent_req *subreq = NULL;
	NTSTATUS status;

	req = tevent_req_create(req, &state, struct mdscli_get_path_state);
	if (req == NULL) {
		return NULL;
	}
	*state = (struct mdscli_get_path_state) {
		.mdscli_ctx = mdscli_ctx,
	};

	status = mdscli_blob_get_path(state,
				      mdscli_ctx,
				      cnid,
				      &state->request_blob);
	if (tevent_req_nterror(req, status)) {
		return tevent_req_post(req, ev);
	}

	state->response_blob.spotlight_blob = talloc_array(
		state,
		uint8_t,
		mdscli_ctx->max_fragment_size);
	if (tevent_req_nomem(state->response_blob.spotlight_blob, req)) {
		return tevent_req_post(req, ev);
	}
	state->response_blob.size = mdscli_ctx->max_fragment_size;

	subreq = dcerpc_mdssvc_cmd_send(state,
					ev,
					mdscli_ctx->bh,
					&mdscli_ctx->ph,
					0,
					mdscli_ctx->dev,
					mdscli_ctx->mdscmd_open.unkn2,
					0,
					mdscli_ctx->flags,
					state->request_blob,
					0,
					mdscli_ctx->max_fragment_size,
					1,
					mdscli_ctx->max_fragment_size,
					0,
					0,
					&mdscli_ctx->mdscmd_cmd.fragment,
					&state->response_blob,
					&mdscli_ctx->mdscmd_cmd.unkn9);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, mdscli_get_path_done, req);
	mdscli_ctx->async_pending++;
	return req;
}

static void mdscli_get_path_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct mdscli_get_path_state *state = tevent_req_data(
		req, struct mdscli_get_path_state);
	DALLOC_CTX *d = NULL;
	char *path = NULL;
	NTSTATUS status;
	bool ok;

	status = dcerpc_mdssvc_cmd_recv(subreq, state);
	TALLOC_FREE(subreq);
	state->mdscli_ctx->async_pending--;
	if (tevent_req_nterror(req, status)) {
		return;
	}

	d = dalloc_new(state);
	if (tevent_req_nomem(d, req)) {
		return;
	}

	ok = sl_unpack(d,
		       (char *)state->response_blob.spotlight_blob,
		       state->response_blob.length);
	if (!ok) {
		tevent_req_nterror(req, NT_STATUS_INTERNAL_ERROR);
		return;
	}

	path = dalloc_get(d,
			  "DALLOC_CTX", 0,
			  "DALLOC_CTX", 2,
			  "DALLOC_CTX", 0,
			  "DALLOC_CTX", 1,
			  "char *", 0);
	if (path == NULL) {
		DBG_DEBUG("No path in mds reponse: %s", dalloc_dump(d, 0));
		tevent_req_nterror(req, NT_STATUS_INTERNAL_ERROR);
		return;
	}
	state->path = talloc_move(state, &path);
	DBG_DEBUG("path: %s\n", state->path);

	tevent_req_done(req);
	return;
}

NTSTATUS mdscli_get_path_recv(struct tevent_req *req,
			      TALLOC_CTX *mem_ctx,
			      char **path)
{
	struct mdscli_get_path_state *state = tevent_req_data(
		req, struct mdscli_get_path_state);
	NTSTATUS status;

	if (tevent_req_is_nterror(req, &status)) {
		tevent_req_received(req);
		return status;
	}

	*path = talloc_move(mem_ctx, &state->path);
	tevent_req_received(req);
	return NT_STATUS_OK;
}

NTSTATUS mdscli_get_path(TALLOC_CTX *mem_ctx,
			 struct mdscli_ctx *mdscli_ctx,
			 uint64_t cnid,
			 char **path)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct tevent_req *req = NULL;
	struct tevent_context *ev = NULL;
	NTSTATUS status = NT_STATUS_NO_MEMORY;

	if (mdscli_ctx->async_pending != 0) {
		status = NT_STATUS_INVALID_PARAMETER;
		goto fail;
	}

	ev = samba_tevent_context_init(frame);
	if (ev == NULL) {
		goto fail;
	}

	req = mdscli_get_path_send(frame, ev, mdscli_ctx, cnid);
	if (req == NULL) {
		goto fail;
	}
	if (!tevent_req_poll_ntstatus(req, ev, &status)) {
		goto fail;
	}

	status = mdscli_get_path_recv(req, mem_ctx, path);
fail:
	TALLOC_FREE(frame);
	return status;
}

struct mdscli_close_search_state {
	struct mdscli_search_ctx *search;
	struct mdssvc_blob request_blob;
	struct mdssvc_blob response_blob;
};

static void mdscli_close_search_done(struct tevent_req *subreq);

struct tevent_req *mdscli_close_search_send(TALLOC_CTX *mem_ctx,
					    struct tevent_context *ev,
					    struct mdscli_search_ctx **search)
{
	struct mdscli_ctx *mdscli_ctx = NULL;
	struct tevent_req *req = NULL;
	struct mdscli_close_search_state *state = NULL;
	struct tevent_req *subreq = NULL;
	NTSTATUS status;

	req = tevent_req_create(req, &state, struct mdscli_close_search_state);
	if (req == NULL) {
		return NULL;
	}
	*state = (struct mdscli_close_search_state) {
		.search = talloc_move(state, search),
	};
	mdscli_ctx = state->search->mdscli_ctx;

	status = mdscli_blob_close_search(state,
					  state->search,
					  &state->request_blob);
	if (tevent_req_nterror(req, status)) {
		return tevent_req_post(req, ev);
	}

	state->response_blob.spotlight_blob = talloc_array(
		state,
		uint8_t,
		mdscli_ctx->max_fragment_size);
	if (tevent_req_nomem(state->response_blob.spotlight_blob, req)) {
		return tevent_req_post(req, ev);
	}
	state->response_blob.size = mdscli_ctx->max_fragment_size;

	subreq = dcerpc_mdssvc_cmd_send(state,
					ev,
					mdscli_ctx->bh,
					&mdscli_ctx->ph,
					0,
					mdscli_ctx->dev,
					mdscli_ctx->mdscmd_open.unkn2,
					0,
					mdscli_ctx->flags,
					state->request_blob,
					0,
					mdscli_ctx->max_fragment_size,
					1,
					mdscli_ctx->max_fragment_size,
					0,
					0,
					&mdscli_ctx->mdscmd_cmd.fragment,
					&state->response_blob,
					&mdscli_ctx->mdscmd_cmd.unkn9);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, mdscli_close_search_done, req);
	mdscli_ctx->async_pending++;
	return req;
}

static void mdscli_close_search_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct mdscli_close_search_state *state = tevent_req_data(
		req, struct mdscli_close_search_state);
	NTSTATUS status;

	status = dcerpc_mdssvc_cmd_recv(subreq, state);
	TALLOC_FREE(subreq);
	state->search->mdscli_ctx->async_pending--;
	if (tevent_req_nterror(req, status)) {
		return;
	}

	tevent_req_done(req);
	return;
}

NTSTATUS mdscli_close_search_recv(struct tevent_req *req)
{
	return tevent_req_simple_recv_ntstatus(req);
}

NTSTATUS mdscli_close_search(struct mdscli_search_ctx **search)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct tevent_req *req = NULL;
	struct tevent_context *ev = NULL;
	NTSTATUS status = NT_STATUS_NO_MEMORY;

	if ((*search)->mdscli_ctx->async_pending != 0) {
		status = NT_STATUS_INVALID_PARAMETER;
		goto fail;
	}

	ev = samba_tevent_context_init(frame);
	if (ev == NULL) {
		goto fail;
	}

	req = mdscli_close_search_send(frame, ev, search);
	if (req == NULL) {
		goto fail;
	}
	if (!tevent_req_poll_ntstatus(req, ev, &status)) {
		goto fail;
	}

	status = mdscli_close_search_recv(req);
fail:
	TALLOC_FREE(frame);
	return status;
}

struct mdscli_disconnect_state {
	struct mdscli_ctx *mdscli_ctx;
};

static void mdscli_disconnect_done(struct tevent_req *subreq);

struct tevent_req *mdscli_disconnect_send(TALLOC_CTX *mem_ctx,
					  struct tevent_context *ev,
					  struct mdscli_ctx *mdscli_ctx)
{
	struct tevent_req *req = NULL;
	struct mdscli_disconnect_state *state = NULL;
	struct tevent_req *subreq = NULL;

	req = tevent_req_create(req, &state, struct mdscli_disconnect_state);
	if (req == NULL) {
		return NULL;
	}
	*state = (struct mdscli_disconnect_state) {
		.mdscli_ctx = mdscli_ctx,
	};

	subreq = dcerpc_mdssvc_close_send(state,
					  ev,
					  mdscli_ctx->bh,
					  &mdscli_ctx->ph,
					  0,
					  mdscli_ctx->dev,
					  mdscli_ctx->mdscmd_open.unkn2,
					  0,
					  &mdscli_ctx->ph,
					  &mdscli_ctx->mdscmd_close.status);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, mdscli_disconnect_done, req);
	mdscli_ctx->async_pending++;
	return req;
}

static void mdscli_disconnect_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct mdscli_disconnect_state *state = tevent_req_data(
		req, struct mdscli_disconnect_state);
	NTSTATUS status;

	status = dcerpc_mdssvc_close_recv(subreq, state);
	TALLOC_FREE(subreq);
	state->mdscli_ctx->async_pending--;
	if (tevent_req_nterror(req, status)) {
		return;
	}

	tevent_req_done(req);
	return;
}

NTSTATUS mdscli_disconnect_recv(struct tevent_req *req)
{
	return tevent_req_simple_recv_ntstatus(req);
}

NTSTATUS mdscli_disconnect(struct mdscli_ctx *mdscli_ctx)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct tevent_req *req = NULL;
	struct tevent_context *ev = NULL;
	NTSTATUS status = NT_STATUS_NO_MEMORY;

	if (mdscli_ctx->async_pending != 0) {
		status = NT_STATUS_INVALID_PARAMETER;
		goto fail;
	}

	ev = samba_tevent_context_init(frame);
	if (ev == NULL) {
		goto fail;
	}

	req = mdscli_disconnect_send(frame, ev, mdscli_ctx);
	if (req == NULL) {
		goto fail;
	}
	if (!tevent_req_poll_ntstatus(req, ev, &status)) {
		goto fail;
	}

	status = mdscli_disconnect_recv(req);
fail:
	TALLOC_FREE(frame);
	return status;
}
