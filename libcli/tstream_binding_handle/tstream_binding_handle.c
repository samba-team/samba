/*
   Unix SMB/CIFS implementation.

   Copyright (C) Ralph Boehme 2016

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
#include <tevent.h>
#include "libcli/tstream_binding_handle/tstream_binding_handle.h"
#include "system/filesys.h"
#include "lib/util/tevent_ntstatus.h"
#include "lib/tsocket/tsocket.h"
#include "lib/util/debug.h"
#include "lib/util/tevent_ntstatus.h"
#include "libcli/smb/tstream_smbXcli_np.h"

struct tstream_bh_state {
	struct tstream_context *stream;
	struct tevent_queue *write_queue;
	const struct ndr_interface_table *table;
	uint32_t request_timeout;
	size_t call_initial_read_size;
	tstream_read_pdu_blob_full_fn_t *complete_pdu_fn;
	void *complete_pdu_fn_private;
	const struct dcerpc_binding *binding;
};

static const struct dcerpc_binding *tstream_bh_get_binding(struct dcerpc_binding_handle *h)
{
	struct tstream_bh_state *hs = dcerpc_binding_handle_data(
		h, struct tstream_bh_state);

	return hs->binding;
}

static bool tstream_bh_is_connected(struct dcerpc_binding_handle *h)
{
	struct tstream_bh_state *hs = dcerpc_binding_handle_data(
		h, struct tstream_bh_state);
	ssize_t ret;

	if (hs->stream == NULL) {
		return false;
	}

	ret = tstream_pending_bytes(hs->stream);
	if (ret == -1) {
		return false;
	}

	return true;
}

static uint32_t tstream_bh_set_timeout(struct dcerpc_binding_handle *h,
				       uint32_t timeout)
{
	struct tstream_bh_state *hs = dcerpc_binding_handle_data(
		h, struct tstream_bh_state);
	uint32_t old;

	old = hs->request_timeout;
	hs->request_timeout = timeout;

	return old;
}

struct tstream_bh_disconnect_state {
	struct tstream_bh_state *hs;
};

static void tstream_bh_disconnect_done(struct tevent_req *subreq);

static struct tevent_req *tstream_bh_disconnect_send(
	TALLOC_CTX *mem_ctx,
	struct tevent_context *ev,
	struct dcerpc_binding_handle *h)
{
	struct tstream_bh_state *hs = dcerpc_binding_handle_data(
		h, struct tstream_bh_state);
	struct tevent_req *req = NULL;
	struct tstream_bh_disconnect_state *state = NULL;
	struct tevent_req *subreq = NULL;
	bool ok;

	req = tevent_req_create(mem_ctx, &state,
				struct tstream_bh_disconnect_state);
	if (req == NULL) {
		return NULL;
	}

	state->hs = hs;

	ok = tstream_bh_is_connected(h);
	if (!ok) {
		tevent_req_nterror(req, NT_STATUS_CONNECTION_DISCONNECTED);
		return tevent_req_post(req, ev);
	}

	subreq = tstream_disconnect_send(state, ev, hs->stream);
	if (tevent_req_nomem(subreq, req)) {
		tevent_req_post(req, ev);
		return req;
	}
	tevent_req_set_callback(subreq, tstream_bh_disconnect_done, req);

	return req;
}

static void tstream_bh_disconnect_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct tstream_bh_disconnect_state *state = tevent_req_data(
		req, struct tstream_bh_disconnect_state);
	int ret, err;

	ret = tstream_disconnect_recv(subreq, &err);
	TALLOC_FREE(subreq);
	if (ret != 0) {
		DBG_ERR("tstream_bh_disconnect failed [%s]\n", strerror(err));
		tevent_req_nterror(req, map_nt_error_from_unix_common(err));
		return;
	}

	state->hs->stream = NULL;
}

static NTSTATUS tstream_bh_disconnect_recv(struct tevent_req *req)
{
	NTSTATUS status;

	if (tevent_req_is_nterror(req, &status)) {
		tevent_req_received(req);
		return status;
	}

	tevent_req_received(req);
	return NT_STATUS_OK;
}

struct tstream_bh_call_state {
	struct tevent_context *ev;
	struct tstream_context *stream;
	struct tstream_bh_state *hs;
	struct iovec out_data;
	DATA_BLOB in_data;
};

static void tstream_bh_call_writev_done(struct tevent_req *subreq);
static void tstream_bh_call_read_pdu_done(struct tevent_req *subreq);

static struct tevent_req *tstream_bh_call_send(TALLOC_CTX *mem_ctx,
					       struct tevent_context *ev,
					       struct dcerpc_binding_handle *h,
					       const struct GUID *object,
					       uint32_t opnum,
					       uint32_t in_flags,
					       const uint8_t *out_data,
					       size_t out_length)
{
	struct tstream_bh_state *hs = dcerpc_binding_handle_data(
		h, struct tstream_bh_state);
	struct tevent_req *req = NULL;
	struct tevent_req *subreq = NULL;
	struct tstream_bh_call_state* state = NULL;
	struct timeval timeout;
	bool ok;

	req = tevent_req_create(mem_ctx, &state,
				struct tstream_bh_call_state);
	if (req == NULL) {
		return NULL;
	}

	*state = (struct tstream_bh_call_state) {
		.ev = ev,
		.stream = hs->stream,
		.hs = hs,
		.out_data = {
			.iov_base = discard_const_p(uint8_t, out_data),
			.iov_len = out_length,
		},
	};

	ok = tstream_bh_is_connected(h);
	if (!ok) {
		tevent_req_nterror(req, NT_STATUS_CONNECTION_DISCONNECTED);
		return tevent_req_post(req, ev);
	}

	if (tstream_is_smbXcli_np(hs->stream)) {
		tstream_smbXcli_np_use_trans(hs->stream);
	}
	if (tevent_queue_length(hs->write_queue) > 0) {
		tevent_req_nterror(req, NT_STATUS_PIPE_BUSY);
	}

	timeout = timeval_current_ofs(hs->request_timeout, 0);

	subreq = tstream_writev_queue_send(state, ev,
					   state->stream,
					   hs->write_queue,
					   &state->out_data, 1);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	if (!tevent_req_set_endtime(subreq, ev, timeout)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, tstream_bh_call_writev_done, req);

	subreq = tstream_read_pdu_blob_send(state,
					    ev,
					    hs->stream,
					    hs->call_initial_read_size,
					    hs->complete_pdu_fn,
					    hs->complete_pdu_fn_private);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	if (!tevent_req_set_endtime(subreq, ev, timeout)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, tstream_bh_call_read_pdu_done, req);

	return req;
}

static void tstream_bh_call_writev_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct tstream_bh_call_state *state = tevent_req_data(
		req, struct tstream_bh_call_state);
	int ret, err;

	ret = tstream_writev_queue_recv(subreq, &err);
	TALLOC_FREE(subreq);
	if (ret == -1) {
		state->hs->stream = NULL;
		tevent_req_nterror(req, map_nt_error_from_unix_common(err));
		return;
	}
}

static void tstream_bh_call_read_pdu_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct tstream_bh_call_state *state = tevent_req_data(
		req, struct tstream_bh_call_state);
	NTSTATUS status;

	status = tstream_read_pdu_blob_recv(subreq, state, &state->in_data);
	TALLOC_FREE(subreq);
	if (!NT_STATUS_IS_OK(status)) {
		state->hs->stream = NULL;
		tevent_req_nterror(req, status);
		return;
	}

	tevent_req_done(req);
}

static NTSTATUS tstream_bh_call_recv(struct tevent_req *req,
				     TALLOC_CTX *mem_ctx,
				     uint8_t **in_data,
				     size_t *in_length,
				     uint32_t *in_flags)
{
	NTSTATUS status;
	struct tstream_bh_call_state *state = tevent_req_data(
		req, struct tstream_bh_call_state);

	if (tevent_req_is_nterror(req, &status)) {
		tevent_req_received(req);
		return status;
	}

	*in_data = talloc_move(mem_ctx, &state->in_data.data);
	*in_length = state->in_data.length;

	tevent_req_received(req);
	return NT_STATUS_OK;
}

static const struct dcerpc_binding_handle_ops tstream_bh_ops = {
	.name			= "tstream_binding_handle",
	.get_binding		= tstream_bh_get_binding,
	.is_connected		= tstream_bh_is_connected,
	.set_timeout		= tstream_bh_set_timeout,
	.raw_call_send		= tstream_bh_call_send,
	.raw_call_recv		= tstream_bh_call_recv,
	.disconnect_send	= tstream_bh_disconnect_send,
	.disconnect_recv	= tstream_bh_disconnect_recv,
};

struct dcerpc_binding_handle *tstream_binding_handle_create(
	TALLOC_CTX *mem_ctx,
	const struct ndr_interface_table *table,
	struct tstream_context **stream,
	size_t call_initial_read_size,
	tstream_read_pdu_blob_full_fn_t *complete_pdu_fn,
	void *complete_pdu_fn_private,
	uint32_t max_data)
{
	struct dcerpc_binding_handle *h = NULL;
	struct tstream_bh_state *hs = NULL;
	struct dcerpc_binding *b = NULL;
	NTSTATUS status;

	h = dcerpc_binding_handle_create(mem_ctx,
					 &tstream_bh_ops,
					 NULL,
					 table,
					 &hs,
					 struct tstream_bh_state,
					 __location__);
	if (h == NULL) {
		return NULL;
	}

	hs->table = table;
	hs->stream = talloc_move(hs, stream);
	hs->call_initial_read_size = call_initial_read_size;
	hs->complete_pdu_fn = complete_pdu_fn;
	hs->complete_pdu_fn_private = complete_pdu_fn_private;

	hs->write_queue = tevent_queue_create(hs, "write_queue");
	if (hs->write_queue == NULL) {
		TALLOC_FREE(h);
		return NULL;
	}

	status = dcerpc_parse_binding(hs, "", &b);
	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(h);
		return NULL;
	}
	hs->binding = b;

	if (max_data > 0) {
		tstream_smbXcli_np_set_max_data(hs->stream, max_data);
	}

	return h;
}
