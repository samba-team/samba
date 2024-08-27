/*
 *  Unix SMB/CIFS implementation.
 *  RPC Pipe client / server routines
 *  Copyright (C) Andrew Tridgell              1992-1998,
 *  Largely re-written : 2005
 *  Copyright (C) Jeremy Allison		1998 - 2005
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
#include "fake_file.h"
#include "rpc_dce.h"
#include "ntdomain.h"
#include "rpc_server/rpc_ncacn_np.h"
#include "rpc_server/srv_pipe_hnd.h"
#include "rpc_client/local_np.h"
#include "rpc_server/rpc_server.h"
#include "rpc_server/rpc_config.h"
#include "../lib/tsocket/tsocket.h"
#include "../lib/util/tevent_ntstatus.h"
#include "librpc/ndr/ndr_table.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_RPC_SRV

bool fsp_is_np(struct files_struct *fsp)
{
	enum FAKE_FILE_TYPE type;

	if ((fsp == NULL) || (fsp->fake_file_handle == NULL)) {
		return false;
	}

	type = fsp->fake_file_handle->type;

	return (type == FAKE_FILE_TYPE_NAMED_PIPE_PROXY);
}

NTSTATUS np_open(TALLOC_CTX *mem_ctx, const char *name,
		 const struct tsocket_address *remote_client_address,
		 const struct tsocket_address *local_server_address,
		 struct auth_session_info *session_info,
		 struct tevent_context *ev_ctx,
		 struct messaging_context *msg_ctx,
		 struct dcesrv_context *dce_ctx,
		 struct fake_file_handle **phandle)
{
	struct fake_file_handle *handle;
	struct npa_state *npa = NULL;
	int ret;

	handle = talloc(mem_ctx, struct fake_file_handle);
	if (handle == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	npa = npa_state_init(handle);
	if (npa == NULL) {
		TALLOC_FREE(handle);
		return NT_STATUS_NO_MEMORY;
	}
	*handle = (struct fake_file_handle) {
		.type = FAKE_FILE_TYPE_NAMED_PIPE_PROXY,
		.private_data = npa,
	};

	ret = local_np_connect(
		name,
		NCACN_NP,
		NULL,
		remote_client_address,
		NULL,
		local_server_address,
		session_info,
		false,
		npa,
		&npa->stream);
	if (ret != 0) {
		DBG_DEBUG("local_np_connect failed: %s\n",
			  strerror(ret));
		TALLOC_FREE(handle);
		return map_nt_error_from_unix(ret);
	}

	*phandle = handle;

	return NT_STATUS_OK;
}

bool np_read_in_progress(struct fake_file_handle *handle)
{
	if (handle->type == FAKE_FILE_TYPE_NAMED_PIPE_PROXY) {
		struct npa_state *p =
			talloc_get_type_abort(handle->private_data,
					      struct npa_state);
		size_t read_count;

		read_count = tevent_queue_length(p->read_queue);
		if (read_count > 0) {
			return true;
		}

		return false;
	}

	return false;
}

struct np_write_state {
	struct tevent_context *ev;
	struct npa_state *p;
	struct iovec iov;
	ssize_t nwritten;
};

static void np_write_done(struct tevent_req *subreq);

struct tevent_req *np_write_send(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
				 struct fake_file_handle *handle,
				 const uint8_t *data, size_t len)
{
	struct tevent_req *req;
	struct np_write_state *state;
	struct npa_state *p = NULL;
	struct tevent_req *subreq = NULL;

	DBG_INFO("len: %zu\n", len);
	dump_data(50, data, len);

	req = tevent_req_create(mem_ctx, &state, struct np_write_state);
	if (req == NULL) {
		return NULL;
	}

	if (handle->type != FAKE_FILE_TYPE_NAMED_PIPE_PROXY) {
		tevent_req_nterror(req, NT_STATUS_INVALID_HANDLE);
		return tevent_req_post(req, ev);
	}

	if (len == 0) {
		state->nwritten = 0;
		tevent_req_done(req);
		return tevent_req_post(req, ev);
	}

	p = talloc_get_type_abort(handle->private_data, struct npa_state);

	state->ev = ev;
	state->p = p;
	state->iov.iov_base = discard_const_p(void, data);
	state->iov.iov_len = len;

	subreq = tstream_writev_queue_send(
		state, ev, p->stream, p->write_queue, &state->iov, 1);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, np_write_done, req);
	return req;
}

static void np_write_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct np_write_state *state = tevent_req_data(
		req, struct np_write_state);
	ssize_t received;
	int err;

	received = tstream_writev_queue_recv(subreq, &err);
	if (received < 0) {
		tevent_req_nterror(req, map_nt_error_from_unix(err));
		return;
	}
	state->nwritten = received;
	tevent_req_done(req);
}

NTSTATUS np_write_recv(struct tevent_req *req, ssize_t *pnwritten)
{
	struct np_write_state *state = tevent_req_data(
		req, struct np_write_state);
	NTSTATUS status;

	if (tevent_req_is_nterror(req, &status)) {
		return status;
	}
	*pnwritten = state->nwritten;
	return NT_STATUS_OK;
}

struct np_ipc_readv_next_vector_state {
	uint8_t *buf;
	size_t len;
	off_t ofs;
	size_t remaining;
};

static void np_ipc_readv_next_vector_init(struct np_ipc_readv_next_vector_state *s,
					  uint8_t *buf, size_t len)
{
	ZERO_STRUCTP(s);

	s->buf = buf;
	s->len = MIN(len, UINT16_MAX);
}

static int np_ipc_readv_next_vector(struct tstream_context *stream,
				    void *private_data,
				    TALLOC_CTX *mem_ctx,
				    struct iovec **_vector,
				    size_t *count)
{
	struct np_ipc_readv_next_vector_state *state =
		(struct np_ipc_readv_next_vector_state *)private_data;
	struct iovec *vector;
	ssize_t pending;
	size_t wanted;

	if (state->ofs == state->len) {
		*_vector = NULL;
		*count = 0;
		return 0;
	}

	pending = tstream_pending_bytes(stream);
	if (pending == -1) {
		return -1;
	}

	if (pending == 0 && state->ofs != 0) {
		/* return a short read */
		*_vector = NULL;
		*count = 0;
		return 0;
	}

	if (pending == 0) {
		/* we want at least one byte and recheck again */
		wanted = 1;
	} else {
		size_t missing = state->len - state->ofs;
		if (pending > missing) {
			/* there's more available */
			state->remaining = pending - missing;
			wanted = missing;
		} else {
			/* read what we can get and recheck in the next cycle */
			wanted = pending;
		}
	}

	vector = talloc_array(mem_ctx, struct iovec, 1);
	if (!vector) {
		return -1;
	}

	vector[0].iov_base = state->buf + state->ofs;
	vector[0].iov_len = wanted;

	state->ofs += wanted;

	*_vector = vector;
	*count = 1;
	return 0;
}

struct np_read_zero_state;

struct np_read_state {
	struct npa_state *p;
	struct np_ipc_readv_next_vector_state next_vector;

	ssize_t nread;
	bool is_data_outstanding;

	struct np_read_zero_state *zs;
};

struct np_read_zero_state {
	struct np_read_state *state;
	struct tevent_req *req;
};

static int np_read_zero_state_destructor(struct np_read_zero_state *zs)
{
	if (zs->state != NULL) {
		zs->state->zs = NULL;
		zs->state = NULL;
	}
	tevent_req_nterror(zs->req, NT_STATUS_PIPE_BROKEN);
	return 0;
}

static void np_read_send_cleanup(struct tevent_req *req,
				 enum tevent_req_state req_state)
{
	struct np_read_state *state = tevent_req_data(
		req, struct np_read_state);

	if (state->zs != NULL) {
		talloc_set_destructor(state->zs, NULL);
		TALLOC_FREE(state->zs);
	}
}

static void np_read_done(struct tevent_req *subreq);

struct tevent_req *np_read_send(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
				struct fake_file_handle *handle,
				uint8_t *data, size_t len)
{
	struct tevent_req *req;
	struct np_read_state *state;
	struct npa_state *p = NULL;
	struct tevent_req *subreq = NULL;

	req = tevent_req_create(mem_ctx, &state, struct np_read_state);
	if (req == NULL) {
		return NULL;
	}

	tevent_req_set_cleanup_fn(req, np_read_send_cleanup);

	if (handle->type != FAKE_FILE_TYPE_NAMED_PIPE_PROXY) {
		tevent_req_nterror(req, NT_STATUS_INVALID_HANDLE);
		return tevent_req_post(req, ev);
	}

	p = talloc_get_type_abort(handle->private_data, struct npa_state);

	if (len == 0) {
		state->zs = talloc_zero(p, struct np_read_zero_state);
		if (tevent_req_nomem(state->zs, req)) {
			return tevent_req_post(req, ev);
		}
		talloc_set_destructor(state->zs,
				      np_read_zero_state_destructor);
		state->zs->state = state;
		state->zs->req = req;
		return req;
	}

	np_ipc_readv_next_vector_init(&state->next_vector, data, len);

	subreq = tstream_readv_pdu_queue_send(
		state,
		ev,
		p->stream,
		p->read_queue,
		np_ipc_readv_next_vector,
		&state->next_vector);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, np_read_done, req);
	return req;
}

static void np_read_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct np_read_state *state = tevent_req_data(
		req, struct np_read_state);
	ssize_t ret;
	int err;

	ret = tstream_readv_pdu_queue_recv(subreq, &err);
	TALLOC_FREE(subreq);
	if (ret == -1) {
		tevent_req_nterror(req, map_nt_error_from_unix(err));
		return;
	}

	state->nread = ret;
	state->is_data_outstanding = (state->next_vector.remaining > 0);

	tevent_req_done(req);
	return;
}

NTSTATUS np_read_recv(struct tevent_req *req, ssize_t *nread,
		      bool *is_data_outstanding)
{
	struct np_read_state *state = tevent_req_data(
		req, struct np_read_state);
	NTSTATUS status;

	if (tevent_req_is_nterror(req, &status)) {
		return status;
	}

	DEBUG(10, ("Received %d bytes. There is %smore data outstanding\n",
		   (int)state->nread, state->is_data_outstanding?"":"no "));

	*nread = state->nread;
	*is_data_outstanding = state->is_data_outstanding;
	return NT_STATUS_OK;
}
