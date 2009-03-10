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

struct tsocket_sendto_state {
	/* this structs are owned by the caller */
	struct {
		struct tsocket_context *sock;
		const uint8_t *buf;
		size_t len;
		const struct tsocket_address *dst;
	} caller;

	ssize_t ret;
};

static int tsocket_sendto_state_destructor(struct tsocket_sendto_state *state)
{
	if (state->caller.sock) {
		tsocket_set_writeable_handler(state->caller.sock, NULL, NULL);
	}
	ZERO_STRUCT(state->caller);

	return 0;
}

static void tsocket_sendto_handler(struct tsocket_context *sock,
				   void *private_data);

struct tevent_req *tsocket_sendto_send(struct tsocket_context *sock,
				       TALLOC_CTX *mem_ctx,
				       const uint8_t *buf,
				       size_t len,
				       const struct tsocket_address *dst)
{
	struct tevent_req *req;
	struct tsocket_sendto_state *state;
	int ret;
	int err;
	bool dummy;

	req = tevent_req_create(mem_ctx, &state,
				struct tsocket_sendto_state);
	if (!req) {
		return NULL;
	}

	state->caller.sock	= sock;
	state->caller.buf	= buf;
	state->caller.len	= len;
	state->caller.dst	= dst;
	state->ret		= -1;

	talloc_set_destructor(state, tsocket_sendto_state_destructor);

	ret = tsocket_set_writeable_handler(sock,
					    tsocket_sendto_handler,
					    req);
	err = tsocket_error_from_errno(ret, errno, &dummy);
	if (tevent_req_error(req, err)) {
		goto post;
	}

	return req;

 post:
	return tevent_req_post(req, sock->event.ctx);
}

static void tsocket_sendto_handler(struct tsocket_context *sock,
				   void *private_data)
{
	struct tevent_req *req = talloc_get_type(private_data,
				 struct tevent_req);
	struct tsocket_sendto_state *state = tevent_req_data(req,
					     struct tsocket_sendto_state);
	ssize_t ret;
	int err;
	bool retry;

	ret = tsocket_sendto(state->caller.sock,
			     state->caller.buf,
			     state->caller.len,
			     state->caller.dst);
	err = tsocket_error_from_errno(ret, errno, &retry);
	if (retry) {
		/* retry later */
		return;
	}
	if (tevent_req_error(req, err)) {
		return;
	}

	state->ret = ret;

	tevent_req_done(req);
}

ssize_t tsocket_sendto_recv(struct tevent_req *req, int *perrno)
{
	struct tsocket_sendto_state *state = tevent_req_data(req,
					     struct tsocket_sendto_state);
	ssize_t ret;

	ret = tsocket_simple_int_recv(req, perrno);
	if (ret == 0) {
		ret = state->ret;
	}

	tevent_req_received(req);
	return ret;
}
