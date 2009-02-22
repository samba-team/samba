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
	size_t max_extra_data;
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

static ssize_t wb_req_more(uint8_t *buf, size_t buflen, void *private_data);
static void wb_req_read_done(struct tevent_req *subreq);

struct async_req *wb_req_read_send(TALLOC_CTX *mem_ctx,
				   struct tevent_context *ev,
				   int fd, size_t max_extra_data)
{
	struct async_req *result;
	struct tevent_req *subreq;
	struct req_read_state *state;

	if (!async_req_setup(mem_ctx, &result, &state,
			     struct req_read_state)) {
		return NULL;
	}
	state->max_extra_data = max_extra_data;

	subreq = read_packet_send(state, ev, fd, 4, wb_req_more, state);
	if (subreq == NULL) {
		goto nomem;
	}

	subreq->async.fn = wb_req_read_done;
	subreq->async.private_data = result;
	return result;
 nomem:
	TALLOC_FREE(result);
	return NULL;
}

static ssize_t wb_req_more(uint8_t *buf, size_t buflen, void *private_data)
{
	struct req_read_state *state = talloc_get_type_abort(
		private_data, struct req_read_state);
	struct winbindd_request *req = (struct winbindd_request *)buf;

	if (buflen == 4) {
		if (req->length != sizeof(struct winbindd_request)) {
			DEBUG(0, ("wb_req_read_len: Invalid request size "
				  "received: %d (expected %d)\n",
				  (int)req->length,
				  (int)sizeof(struct winbindd_request)));
			return -1;
		}
		return sizeof(struct winbindd_request) - 4;
	}

	if ((state->max_extra_data != 0)
	    && (req->extra_len > state->max_extra_data)) {
		DEBUG(3, ("Got request with %d bytes extra data on "
			  "unprivileged socket\n", (int)req->extra_len));
		return -1;
	}

	return req->extra_len;
}

static void wb_req_read_done(struct tevent_req *subreq)
{
	struct async_req *req = talloc_get_type_abort(
		subreq->async.private_data, struct async_req);
	struct req_read_state *state = talloc_get_type_abort(
		req->private_data, struct req_read_state);
	int err;
	ssize_t ret;
	uint8_t *buf;

	ret = read_packet_recv(subreq, state, &buf, &err);
	TALLOC_FREE(subreq);
	if (ret == -1) {
		async_req_error(req, map_wbc_err_from_errno(err));
		return;
	}

	state->wb_req = (struct winbindd_request *)buf;

	if (state->wb_req->extra_len != 0) {
		state->wb_req->extra_data.data =
			(char *)buf + sizeof(struct winbindd_request);
	} else {
		state->wb_req->extra_data.data = NULL;
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
};

static ssize_t wb_resp_more(uint8_t *buf, size_t buflen, void *private_data);
static void wb_resp_read_done(struct tevent_req *subreq);

struct async_req *wb_resp_read_send(TALLOC_CTX *mem_ctx,
				    struct tevent_context *ev, int fd)
{
	struct async_req *result;
	struct tevent_req *subreq;
	struct resp_read_state *state;

	if (!async_req_setup(mem_ctx, &result, &state,
			     struct resp_read_state)) {
		return NULL;
	}

	subreq = read_packet_send(state, ev, fd, 4, wb_resp_more, state);
	if (subreq == NULL) {
		goto nomem;
	}
	subreq->async.fn = wb_resp_read_done;
	subreq->async.private_data = result;
	return result;

 nomem:
	TALLOC_FREE(result);
	return NULL;
}

static ssize_t wb_resp_more(uint8_t *buf, size_t buflen, void *private_data)
{
	struct winbindd_response *resp = (struct winbindd_response *)buf;

	if (buflen == 4) {
		if (resp->length < sizeof(struct winbindd_response)) {
			DEBUG(0, ("wb_resp_read_len: Invalid response size "
				  "received: %d (expected at least%d)\n",
				  (int)resp->length,
				  (int)sizeof(struct winbindd_response)));
			return -1;
		}
	}
	return resp->length - 4;
}

static void wb_resp_read_done(struct tevent_req *subreq)
{
	struct async_req *req = talloc_get_type_abort(
		subreq->async.private_data, struct async_req);
	struct resp_read_state *state = talloc_get_type_abort(
		req->private_data, struct resp_read_state);
	uint8_t *buf;
	int err;
	ssize_t ret;

	ret = read_packet_recv(subreq, state, &buf, &err);
	TALLOC_FREE(subreq);
	if (ret == -1) {
		async_req_error(req, map_wbc_err_from_errno(err));
		return;
	}

	state->wb_resp = (struct winbindd_response *)buf;

	if (state->wb_resp->length > sizeof(struct winbindd_response)) {
		state->wb_resp->extra_data.data =
			(char *)buf + sizeof(struct winbindd_response);
	} else {
		state->wb_resp->extra_data.data = NULL;
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
