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

struct tsocket_readv_state {
	/* this structs are owned by the caller */
	struct {
		struct tsocket_context *sock;
		tsocket_readv_next_iovec_t next_iovec_fn;
		void *private_data;
	} caller;

	/*
	 * Each call to the callback resets iov and count
	 * the callback allocated the iov as child of our state,
	 * that means we are allowed to modify and free it.
	 *
	 * we should call the callback every time we filled the given
	 * vector and ask for a new vector. We return if the callback
	 * ask for 0 bytes.
	 */
	struct iovec *iov;
	size_t count;

	/*
	 * the total number of bytes we read,
	 * the return value of the _recv function
	 */
	int total_read;
};

static int tsocket_readv_state_destructor(struct tsocket_readv_state *state)
{
	if (state->caller.sock) {
		tsocket_set_readable_handler(state->caller.sock, NULL, NULL);
	}
	ZERO_STRUCT(state->caller);

	return 0;
}

static bool tsocket_readv_ask_for_next_vector(struct tevent_req *req,
					      struct tsocket_readv_state *state)
{
	int ret;
	int err;
	bool dummy;
	size_t to_read = 0;
	size_t i;

	talloc_free(state->iov);
	state->iov = NULL;
	state->count = 0;

	ret = state->caller.next_iovec_fn(state->caller.sock,
					  state->caller.private_data,
					  state, &state->iov, &state->count);
	err = tsocket_error_from_errno(ret, errno, &dummy);
	if (tevent_req_error(req, err)) {
		return false;
	}

	for (i=0; i < state->count; i++) {
		size_t tmp = to_read;
		tmp += state->iov[i].iov_len;

		if (tmp < to_read) {
			tevent_req_error(req, EMSGSIZE);
			return false;
		}

		to_read = tmp;
	}

	if (to_read == 0) {
		tevent_req_done(req);
		return false;
	}

	if (state->total_read + to_read < state->total_read) {
		tevent_req_error(req, EMSGSIZE);
		return false;
	}

	return true;
}

static void tsocket_readv_handler(struct tsocket_context *sock,
				  void *private_data);

struct tevent_req *tsocket_readv_send(struct tsocket_context *sock,
				      TALLOC_CTX *mem_ctx,
				      tsocket_readv_next_iovec_t next_iovec_fn,
				      void *private_data)
{
	struct tevent_req *req;
	struct tsocket_readv_state *state;
	int ret;
	int err;
	bool dummy;

	req = tevent_req_create(mem_ctx, &state,
				struct tsocket_readv_state);
	if (!req) {
		return NULL;
	}

	state->caller.sock		= sock;
	state->caller.next_iovec_fn	= next_iovec_fn;
	state->caller.private_data	= private_data;

	state->iov		= NULL;
	state->count		= 0;
	state->total_read	= 0;

	if (!tsocket_readv_ask_for_next_vector(req, state)) {
		goto post;
	}

	talloc_set_destructor(state, tsocket_readv_state_destructor);

	ret = tsocket_set_readable_handler(sock,
					   tsocket_readv_handler,
					   req);
	err = tsocket_error_from_errno(ret, errno, &dummy);
	if (tevent_req_error(req, err)) {
		goto post;
	}

	return req;

 post:
	return tevent_req_post(req, sock->event.ctx);
}

static void tsocket_readv_handler(struct tsocket_context *sock,
				  void *private_data)
{
	struct tevent_req *req = talloc_get_type(private_data,
				 struct tevent_req);
	struct tsocket_readv_state *state = tevent_req_data(req,
					    struct tsocket_readv_state);
	ssize_t ret;
	int err;
	bool retry;

	ret = tsocket_readv(state->caller.sock,
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

	state->total_read += ret;

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

	if (state->count) {
		/* we have more to read */
		return;
	}

	/* ask the callback for a new vector we should fill */
	tsocket_readv_ask_for_next_vector(req, state);
}

int tsocket_readv_recv(struct tevent_req *req, int *perrno)
{
	struct tsocket_readv_state *state = tevent_req_data(req,
					    struct tsocket_readv_state);
	int ret;

	ret = tsocket_simple_int_recv(req, perrno);
	if (ret == 0) {
		ret = state->total_read;
	}

	tevent_req_received(req);
	return ret;
}

