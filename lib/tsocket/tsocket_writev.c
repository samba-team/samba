/*
   Unix SMB/CIFS implementation.

   Copyright (C) Stefan Metzmacher 2009

     ** NOTE! The following LGPL license applies to the tevent
     ** library. This does NOT imply that all of Samba is released
     ** under the LGPL

   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 3 of the License, or (at your option) any later version.

   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with this library; if not, see <http://www.gnu.org/licenses/>.
*/

#include "replace.h"
#include "system/network.h"
#include "tsocket.h"
#include "tsocket_internal.h"

struct tsocket_writev_state {
	/* this structs are owned by the caller */
	struct {
		struct tsocket_context *sock;
		const struct iovec *vector;
		size_t count;
	} caller;

	struct iovec *iov;
	size_t count;
	int total_written;
};

static int tsocket_writev_state_destructor(struct tsocket_writev_state *state)
{
	if (state->caller.sock) {
		tsocket_set_writeable_handler(state->caller.sock, NULL, NULL);
	}
	ZERO_STRUCT(state->caller);

	return 0;
}

static void tsocket_writev_handler(struct tsocket_context *sock,
				   void *private_data);

struct tevent_req *tsocket_writev_send(struct tsocket_context *sock,
				       TALLOC_CTX *mem_ctx,
				       const struct iovec *vector,
				       size_t count)
{
	struct tevent_req *req;
	struct tsocket_writev_state *state;
	int ret;
	int err;
	bool dummy;
	int to_write = 0;
	size_t i;

	req = tevent_req_create(mem_ctx, &state,
				struct tsocket_writev_state);
	if (!req) {
		return NULL;
	}

	state->caller.sock	= sock;
	state->caller.vector	= vector;
	state->caller.count	= count;

	state->iov		= NULL;
	state->count		= count;
	state->total_written	= 0;

	state->iov = talloc_array(state, struct iovec, count);
	if (tevent_req_nomem(state->iov, req)) {
		goto post;
	}
	memcpy(state->iov, vector, sizeof(struct iovec) * count);

	for (i=0; i < count; i++) {
		int tmp = to_write;

		tmp += state->iov[i].iov_len;

		if (tmp < to_write) {
			tevent_req_error(req, EMSGSIZE);
			goto post;
		}

		to_write = tmp;
	}

	if (to_write == 0) {
		tevent_req_done(req);
		goto post;
	}

	/*
	 * this is a fast path, not waiting for the
	 * socket to become explicit writeable gains
	 * about 10%-20% performance in benchmark tests.
	 */
	tsocket_writev_handler(sock, req);
	if (!tevent_req_is_in_progress(req)) {
		goto post;
	}

	talloc_set_destructor(state, tsocket_writev_state_destructor);

	ret = tsocket_set_writeable_handler(sock,
					    tsocket_writev_handler,
					    req);
	err = tsocket_error_from_errno(ret, errno, &dummy);
	if (tevent_req_error(req, err)) {
		goto post;
	}

	return req;

 post:
	return tevent_req_post(req, sock->event.ctx);
}

static void tsocket_writev_handler(struct tsocket_context *sock,
				   void *private_data)
{
	struct tevent_req *req = talloc_get_type(private_data,
				 struct tevent_req);
	struct tsocket_writev_state *state = tevent_req_data(req,
					     struct tsocket_writev_state);
	int ret;
	int err;
	bool retry;

	ret = tsocket_writev(state->caller.sock,
			     state->iov,
			     state->count);
	err = tsocket_error_from_errno(ret, errno, &retry);
	if (retry) {
		/* retry later */
		return;
	}
	if (tevent_req_error(req, err)) {
		return;
	}

	state->total_written += ret;

	/*
	 * we have not written everything yet, so we need to truncate
	 * the already written bytes from our iov copy
	 */
	while (ret > 0) {
		if (ret < state->iov[0].iov_len) {
			uint8_t *base;
			base = (uint8_t *)state->iov[0].iov_base;
			base += ret;
			state->iov[0].iov_base = base;
			state->iov[0].iov_len -= ret;
			break;
		}
		ret -= state->iov[0].iov_len;
		state->iov += 1;
		state->count -= 1;
	}

	if (state->count > 0) {
		/* more to write */
		return;
	}

	tevent_req_done(req);
}

int tsocket_writev_recv(struct tevent_req *req, int *perrno)
{
	struct tsocket_writev_state *state = tevent_req_data(req,
					     struct tsocket_writev_state);
	int ret;

	ret = tsocket_simple_int_recv(req, perrno);
	if (ret == 0) {
		ret = state->total_written;
	}

	tevent_req_received(req);
	return ret;
}

struct tsocket_writev_queue_state {
	/* this structs are owned by the caller */
	struct {
		struct tsocket_context *sock;
		const struct iovec *vector;
		size_t count;
	} caller;
	int ret;
};

static void tsocket_writev_queue_trigger(struct tevent_req *req,
					 void *private_data);
static void tsocket_writev_queue_done(struct tevent_req *subreq);

/**
 * @brief Queue a dgram blob for sending through the socket
 * @param[in] mem_ctx	The memory context for the result
 * @param[in] sock	The socket to send data through
 * @param[in] queue	The existing send queue
 * @param[in] vector	The iovec vector so write
 * @param[in] count	The size of the vector
 * @retval		The async request handle
 *
 * This function queues a blob for sending to destination through an existing
 * dgram socket. The async callback is triggered when the whole blob is
 * delivered to the underlying system socket.
 *
 * The caller needs to make sure that all non-scalar input parameters hang
 * arround for the whole lifetime of the request.
 */
struct tevent_req *tsocket_writev_queue_send(TALLOC_CTX *mem_ctx,
					     struct tsocket_context *sock,
					     struct tevent_queue *queue,
					     const struct iovec *vector,
					     size_t count)
{
	struct tevent_req *req;
	struct tsocket_writev_queue_state *state;
	bool ok;

	req = tevent_req_create(mem_ctx, &state,
				struct tsocket_writev_queue_state);
	if (!req) {
		return NULL;
	}

	state->caller.sock	= sock;
	state->caller.vector	= vector;
	state->caller.count	= count;
	state->ret		= -1;

	ok = tevent_queue_add(queue,
			      sock->event.ctx,
			      req,
			      tsocket_writev_queue_trigger,
			      NULL);
	if (!ok) {
		tevent_req_nomem(NULL, req);
		goto post;
	}

	return req;

 post:
	return tevent_req_post(req, sock->event.ctx);
}

static void tsocket_writev_queue_trigger(struct tevent_req *req,
					 void *private_data)
{
	struct tsocket_writev_queue_state *state = tevent_req_data(req,
					struct tsocket_writev_queue_state);
	struct tevent_req *subreq;

	subreq = tsocket_writev_send(state->caller.sock,
				     state,
				     state->caller.vector,
				     state->caller.count);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, tsocket_writev_queue_done ,req);
}

static void tsocket_writev_queue_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(subreq,
				 struct tevent_req);
	struct tsocket_writev_queue_state *state = tevent_req_data(req,
					struct tsocket_writev_queue_state);
	int ret;
	int sys_errno;

	ret = tsocket_writev_recv(subreq, &sys_errno);
	talloc_free(subreq);
	if (ret == -1) {
		tevent_req_error(req, sys_errno);
		return;
	}
	state->ret = ret;

	tevent_req_done(req);
}

int tsocket_writev_queue_recv(struct tevent_req *req, int *perrno)
{
	struct tsocket_writev_queue_state *state = tevent_req_data(req,
					struct tsocket_writev_queue_state);
	int ret;

	ret = tsocket_simple_int_recv(req, perrno);
	if (ret == 0) {
		ret = state->ret;
	}

	tevent_req_received(req);
	return ret;
}

