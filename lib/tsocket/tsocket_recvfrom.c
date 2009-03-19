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

struct tsocket_recvfrom_state {
	/* this structs are owned by the caller */
	struct {
		struct tsocket_context *sock;
	} caller;

	uint8_t *buf;
	size_t len;
	struct tsocket_address *src;
};

static int tsocket_recvfrom_state_destructor(struct tsocket_recvfrom_state *state)
{
	if (state->caller.sock) {
		tsocket_set_readable_handler(state->caller.sock, NULL, NULL);
	}
	ZERO_STRUCT(state->caller);

	return 0;
}

static void tsocket_recvfrom_handler(struct tsocket_context *sock,
				     void *private_data);

struct tevent_req *tsocket_recvfrom_send(struct tsocket_context *sock,
					 TALLOC_CTX *mem_ctx)
{
	struct tevent_req *req;
	struct tsocket_recvfrom_state *state;
	int ret;
	int err;
	bool dummy;

	req = tevent_req_create(mem_ctx, &state,
				struct tsocket_recvfrom_state);
	if (!req) {
		return NULL;
	}

	state->caller.sock	= sock;
	state->buf		= NULL;
	state->len		= 0;
	state->src		= NULL;

	talloc_set_destructor(state, tsocket_recvfrom_state_destructor);

	ret = tsocket_set_readable_handler(sock,
					   tsocket_recvfrom_handler,
					   req);
	err = tsocket_error_from_errno(ret, errno, &dummy);
	if (tevent_req_error(req, err)) {
		goto post;
	}

	return req;

 post:
	return tevent_req_post(req, sock->event.ctx);
}

static void tsocket_recvfrom_handler(struct tsocket_context *sock,
				     void *private_data)
{
	struct tevent_req *req = talloc_get_type(private_data,
				 struct tevent_req);
	struct tsocket_recvfrom_state *state = tevent_req_data(req,
					       struct tsocket_recvfrom_state);
	ssize_t ret;
	int err;
	bool retry;

	ret = tsocket_pending(state->caller.sock);
	if (ret == 0) {
		/* retry later */
		return;
	}
	err = tsocket_error_from_errno(ret, errno, &retry);
	if (retry) {
		/* retry later */
		return;
	}
	if (tevent_req_error(req, err)) {
		return;
	}

	state->buf = talloc_array(state, uint8_t, ret);
	if (tevent_req_nomem(state->buf, req)) {
		return;
	}
	state->len = ret;

	ret = tsocket_recvfrom(state->caller.sock,
			       state->buf,
			       state->len,
			       state,
			       &state->src);
	err = tsocket_error_from_errno(ret, errno, &retry);
	if (retry) {
		/* retry later */
		return;
	}
	if (tevent_req_error(req, err)) {
		return;
	}

	if (ret != state->len) {
		tevent_req_error(req, EIO);
		return;
	}

	tevent_req_done(req);
}

ssize_t tsocket_recvfrom_recv(struct tevent_req *req,
			      int *perrno,
			      TALLOC_CTX *mem_ctx,
			      uint8_t **buf,
			      struct tsocket_address **src)
{
	struct tsocket_recvfrom_state *state = tevent_req_data(req,
					       struct tsocket_recvfrom_state);
	ssize_t ret;

	ret = tsocket_simple_int_recv(req, perrno);
	if (ret == 0) {
		*buf = talloc_move(mem_ctx, &state->buf);
		ret = state->len;
		if (src) {
			*src = talloc_move(mem_ctx, &state->src);
		}
	}

	tevent_req_received(req);
	return ret;
}

