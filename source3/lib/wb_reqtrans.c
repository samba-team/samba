/*
   Unix SMB/CIFS implementation.

   Async transfer of winbindd_request and _response structs

   Copyright (C) Volker Lendecke 2008

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
#include "wbc_async.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_WINBIND

struct req_read_state {
	struct winbindd_request *wb_req;
	struct tevent_context *ev;
	size_t max_extra_data;
	int fd;
};

bool async_req_is_wbcerr(struct async_req *req, wbcErr *pwbc_err)
{
	enum async_req_state state;
	uint64_t error;
	if (!async_req_is_error(req, &state, &error)) {
		*pwbc_err = WBC_ERR_SUCCESS;
		return false;
	}

	switch (state) {
	case ASYNC_REQ_USER_ERROR:
		*pwbc_err = error;
		break;
	case ASYNC_REQ_TIMED_OUT:
		*pwbc_err = WBC_ERR_UNKNOWN_FAILURE;
		break;
	case ASYNC_REQ_NO_MEMORY:
		*pwbc_err = WBC_ERR_NO_MEMORY;
		break;
	default:
		*pwbc_err = WBC_ERR_UNKNOWN_FAILURE;
		break;
	}
	return true;
}

wbcErr map_wbc_err_from_errno(int error)
{
	switch(error) {
	case EPERM:
	case EACCES:
		return WBC_ERR_AUTH_ERROR;
	case ENOMEM:
		return WBC_ERR_NO_MEMORY;
	case EIO:
	default:
		return WBC_ERR_UNKNOWN_FAILURE;
	}
}

wbcErr async_req_simple_recv_wbcerr(struct async_req *req)
{
	wbcErr wbc_err;

	if (async_req_is_wbcerr(req, &wbc_err)) {
		return wbc_err;
	}

	return WBC_ERR_SUCCESS;
}

static void wb_req_read_len(struct async_req *subreq);
static void wb_req_read_main(struct async_req *subreq);
static void wb_req_read_extra(struct async_req *subreq);

struct async_req *wb_req_read_send(TALLOC_CTX *mem_ctx,
				   struct tevent_context *ev,
				   int fd, size_t max_extra_data)
{
	struct async_req *result, *subreq;
	struct req_read_state *state;

	if (!async_req_setup(mem_ctx, &result, &state,
			     struct req_read_state)) {
		return NULL;
	}
	state->fd = fd;
	state->ev = ev;
	state->max_extra_data = max_extra_data;
	state->wb_req = talloc(state, struct winbindd_request);
	if (state->wb_req == NULL) {
		goto nomem;
	}

	subreq = recvall_send(state, ev, state->fd, &(state->wb_req->length),
			      sizeof(state->wb_req->length), 0);
	if (subreq == NULL) {
		goto nomem;
	}

	subreq->async.fn = wb_req_read_len;
	subreq->async.priv = result;
	return result;

 nomem:
	TALLOC_FREE(result);
	return NULL;
}

static void wb_req_read_len(struct async_req *subreq)
{
	struct async_req *req = talloc_get_type_abort(
		subreq->async.priv, struct async_req);
	struct req_read_state *state = talloc_get_type_abort(
		req->private_data, struct req_read_state);
	int err;
	ssize_t ret;

	ret = recvall_recv(subreq, &err);
	TALLOC_FREE(subreq);
	if (ret < 0) {
		async_req_error(req, map_wbc_err_from_errno(err));
		return;
	}

	if (state->wb_req->length != sizeof(struct winbindd_request)) {
		DEBUG(0, ("wb_req_read_len: Invalid request size received: "
			  "%d (expected %d)\n", (int)state->wb_req->length,
			  (int)sizeof(struct winbindd_request)));
		async_req_error(req, WBC_ERR_INVALID_RESPONSE);
		return;
	}

	subreq = recvall_send(
		req, state->ev, state->fd, (uint32 *)(state->wb_req)+1,
		sizeof(struct winbindd_request) - sizeof(uint32), 0);
	if (async_req_nomem(subreq, req)) {
		return;
	}

	subreq->async.fn = wb_req_read_main;
	subreq->async.priv = req;
}

static void wb_req_read_main(struct async_req *subreq)
{
	struct async_req *req = talloc_get_type_abort(
		subreq->async.priv, struct async_req);
	struct req_read_state *state = talloc_get_type_abort(
		req->private_data, struct req_read_state);
	int err;
	ssize_t ret;

	ret = recvall_recv(subreq, &err);
	TALLOC_FREE(subreq);
	if (ret < 0) {
		async_req_error(req, map_wbc_err_from_errno(err));
		return;
	}

	if ((state->max_extra_data != 0)
	    && (state->wb_req->extra_len > state->max_extra_data)) {
		DEBUG(3, ("Got request with %d bytes extra data on "
			  "unprivileged socket\n",
			  (int)state->wb_req->extra_len));
		async_req_error(req, WBC_ERR_INVALID_RESPONSE);
		return;
	}

	if (state->wb_req->extra_len == 0) {
		async_req_done(req);
		return;
	}

	state->wb_req->extra_data.data = TALLOC_ARRAY(
		state->wb_req, char, state->wb_req->extra_len + 1);
	if (async_req_nomem(state->wb_req->extra_data.data, req)) {
		return;
	}

	state->wb_req->extra_data.data[state->wb_req->extra_len] = 0;

	subreq = recvall_send(
		req, state->ev, state->fd, state->wb_req->extra_data.data,
		state->wb_req->extra_len, 0);
	if (async_req_nomem(subreq, req)) {
		return;
	}

	subreq->async.fn = wb_req_read_extra;
	subreq->async.priv = req;
}

static void wb_req_read_extra(struct async_req *subreq)
{
	struct async_req *req = talloc_get_type_abort(
		subreq->async.priv, struct async_req);
	int err;
	ssize_t ret;

	ret = recvall_recv(subreq, &err);
	TALLOC_FREE(subreq);
	if (ret < 0) {
		async_req_error(req, map_wbc_err_from_errno(err));
		return;
	}
	async_req_done(req);
}


wbcErr wb_req_read_recv(struct async_req *req, TALLOC_CTX *mem_ctx,
			struct winbindd_request **preq)
{
	struct req_read_state *state = talloc_get_type_abort(
		req->private_data, struct req_read_state);
	wbcErr wbc_err;

	if (async_req_is_wbcerr(req, &wbc_err)) {
		return wbc_err;
	}
	*preq = talloc_move(mem_ctx, &state->wb_req);
	return WBC_ERR_SUCCESS;
}

struct req_write_state {
	struct iovec iov[2];
};

static void wb_req_write_done(struct tevent_req *subreq);

struct async_req *wb_req_write_send(TALLOC_CTX *mem_ctx,
				    struct tevent_context *ev, int fd,
				    struct winbindd_request *wb_req)
{
	struct async_req *result;
	struct tevent_req *subreq;
	struct req_write_state *state;
	int count = 1;

	if (!async_req_setup(mem_ctx, &result, &state,
			     struct req_write_state)) {
		return NULL;
	}

	state->iov[0].iov_base = wb_req;
	state->iov[0].iov_len = sizeof(struct winbindd_request);

	if (wb_req->extra_len != 0) {
		state->iov[1].iov_base = wb_req->extra_data.data;
		state->iov[1].iov_len = wb_req->extra_len;
		count = 2;
	}

	subreq = writev_send(state, ev, fd, state->iov, count);
	if (subreq == NULL) {
		goto fail;
	}
	subreq->async.fn = wb_req_write_done;
	subreq->async.private_data = result;
	return result;

 fail:
	TALLOC_FREE(result);
	return NULL;
}

static void wb_req_write_done(struct tevent_req *subreq)
{
	struct async_req *req = talloc_get_type_abort(
		subreq->async.private_data, struct async_req);
	int err;
	ssize_t ret;

	ret = writev_recv(subreq, &err);
	TALLOC_FREE(subreq);
	if (ret < 0) {
		async_req_error(req, map_wbc_err_from_errno(err));
		return;
	}
	async_req_done(req);
}

wbcErr wb_req_write_recv(struct async_req *req)
{
	return async_req_simple_recv_wbcerr(req);
}

struct resp_read_state {
	struct winbindd_response *wb_resp;
	struct tevent_context *ev;
	size_t max_extra_data;
	int fd;
};

static void wb_resp_read_len(struct async_req *subreq);
static void wb_resp_read_main(struct async_req *subreq);
static void wb_resp_read_extra(struct async_req *subreq);

struct async_req *wb_resp_read_send(TALLOC_CTX *mem_ctx,
				    struct tevent_context *ev, int fd)
{
	struct async_req *result, *subreq;
	struct resp_read_state *state;

	if (!async_req_setup(mem_ctx, &result, &state,
			     struct resp_read_state)) {
		return NULL;
	}
	state->fd = fd;
	state->ev = ev;
	state->wb_resp = talloc(state, struct winbindd_response);
	if (state->wb_resp == NULL) {
		goto nomem;
	}

	subreq = recvall_send(state, ev, state->fd, &(state->wb_resp->length),
			      sizeof(state->wb_resp->length), 0);
	if (subreq == NULL) {
		goto nomem;
	}

	subreq->async.fn = wb_resp_read_len;
	subreq->async.priv = result;
	return result;

 nomem:
	TALLOC_FREE(result);
	return NULL;
}

static void wb_resp_read_len(struct async_req *subreq)
{
	struct async_req *req = talloc_get_type_abort(
		subreq->async.priv, struct async_req);
	struct resp_read_state *state = talloc_get_type_abort(
		req->private_data, struct resp_read_state);
	int err;
	ssize_t ret;

	ret = recvall_recv(subreq, &err);
	TALLOC_FREE(subreq);
	if (ret < 0) {
		async_req_error(req, map_wbc_err_from_errno(err));
		return;
	}

	if (state->wb_resp->length < sizeof(struct winbindd_response)) {
		DEBUG(0, ("wb_resp_read_len: Invalid response size received: "
			  "%d (expected at least%d)\n",
			  (int)state->wb_resp->length,
			  (int)sizeof(struct winbindd_response)));
		async_req_error(req, WBC_ERR_INVALID_RESPONSE);
		return;
	}

	subreq = recvall_send(
		req, state->ev, state->fd, (uint32 *)(state->wb_resp)+1,
		sizeof(struct winbindd_response) - sizeof(uint32), 0);
	if (async_req_nomem(subreq, req)) {
		return;
	}

	subreq->async.fn = wb_resp_read_main;
	subreq->async.priv = req;
}

static void wb_resp_read_main(struct async_req *subreq)
{
	struct async_req *req = talloc_get_type_abort(
		subreq->async.priv, struct async_req);
	struct resp_read_state *state = talloc_get_type_abort(
		req->private_data, struct resp_read_state);
	int err;
	ssize_t ret;
	size_t extra_len;

	ret = recvall_recv(subreq, &err);
	TALLOC_FREE(subreq);
	if (ret < 0) {
		async_req_error(req, map_wbc_err_from_errno(err));
		return;
	}

	extra_len = state->wb_resp->length - sizeof(struct winbindd_response);
	if (extra_len == 0) {
		async_req_done(req);
		return;
	}

	state->wb_resp->extra_data.data = TALLOC_ARRAY(
		state->wb_resp, char, extra_len+1);
	if (async_req_nomem(state->wb_resp->extra_data.data, req)) {
		return;
	}
	((char *)state->wb_resp->extra_data.data)[extra_len] = 0;

	subreq = recvall_send(
		req, state->ev, state->fd, state->wb_resp->extra_data.data,
		extra_len, 0);
	if (async_req_nomem(subreq, req)) {
		return;
	}

	subreq->async.fn = wb_resp_read_extra;
	subreq->async.priv = req;
}

static void wb_resp_read_extra(struct async_req *subreq)
{
	struct async_req *req = talloc_get_type_abort(
		subreq->async.priv, struct async_req);
	int err;
	ssize_t ret;

	ret = recvall_recv(subreq, &err);
	TALLOC_FREE(subreq);
	if (ret < 0) {
		async_req_error(req, map_wbc_err_from_errno(err));
		return;
	}
	async_req_done(req);
}


wbcErr wb_resp_read_recv(struct async_req *req, TALLOC_CTX *mem_ctx,
			 struct winbindd_response **presp)
{
	struct resp_read_state *state = talloc_get_type_abort(
		req->private_data, struct resp_read_state);
	wbcErr wbc_err;

	if (async_req_is_wbcerr(req, &wbc_err)) {
		return wbc_err;
	}
	*presp = talloc_move(mem_ctx, &state->wb_resp);
	return WBC_ERR_SUCCESS;
}

struct resp_write_state {
	struct iovec iov[2];
};

static void wb_resp_write_done(struct tevent_req *subreq);

struct async_req *wb_resp_write_send(TALLOC_CTX *mem_ctx,
				    struct tevent_context *ev, int fd,
				    struct winbindd_response *wb_resp)
{
	struct async_req *result;
	struct tevent_req *subreq;
	struct resp_write_state *state;
	int count = 1;

	if (!async_req_setup(mem_ctx, &result, &state,
			     struct resp_write_state)) {
		return NULL;
	}

	state->iov[0].iov_base = wb_resp;
	state->iov[0].iov_len = sizeof(struct winbindd_response);

	if (wb_resp->length > sizeof(struct winbindd_response)) {
		state->iov[1].iov_base = wb_resp->extra_data.data;
		state->iov[1].iov_len =
			wb_resp->length - sizeof(struct winbindd_response);
		count = 2;
	}

	subreq = writev_send(state, ev, fd, state->iov, count);
	if (subreq == NULL) {
		goto fail;
	}
	subreq->async.fn = wb_resp_write_done;
	subreq->async.private_data = result;
	return result;

 fail:
	TALLOC_FREE(result);
	return NULL;
}

static void wb_resp_write_done(struct tevent_req *subreq)
{
	struct async_req *req = talloc_get_type_abort(
		subreq->async.private_data, struct async_req);
	int err;
	ssize_t ret;

	ret = writev_recv(subreq, &err);
	TALLOC_FREE(subreq);
	if (ret < 0) {
		async_req_error(req, map_wbc_err_from_errno(err));
		return;
	}
	async_req_done(req);
}

wbcErr wb_resp_write_recv(struct async_req *req)
{
	return async_req_simple_recv_wbcerr(req);
}
