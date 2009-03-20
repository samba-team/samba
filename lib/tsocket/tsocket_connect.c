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

struct tsocket_connect_state {
	/* this structs are owned by the caller */
	struct {
		struct tsocket_context *sock;
		const struct tsocket_address *dst;
	} caller;
};

static void tsocket_connect_handler(struct tsocket_context *sock,
				    void *private_data);

struct tevent_req *tsocket_connect_send(struct tsocket_context *sock,
					TALLOC_CTX *mem_ctx,
					const struct tsocket_address *dst)
{
	struct tevent_req *req;
	struct tsocket_connect_state *state;
	int ret;
	int err;
	bool retry;
	bool dummy;

	req = tevent_req_create(mem_ctx, &state,
				struct tsocket_connect_state);
	if (!req) {
		return NULL;
	}

	state->caller.sock	= sock;
	state->caller.dst	= dst;

	ret = tsocket_connect(state->caller.sock,
			      state->caller.dst);
	err = tsocket_error_from_errno(ret, errno, &retry);
	if (retry) {
		/* retry later */
		goto async;
	}
	if (tevent_req_error(req, err)) {
		goto post;
	}

	tevent_req_done(req);
	goto post;

 async:
	ret = tsocket_set_readable_handler(state->caller.sock,
					   tsocket_connect_handler,
					   req);
	err = tsocket_error_from_errno(ret, errno, &dummy);
	if (tevent_req_error(req, err)) {
		goto post;
	}

	return req;

 post:
	return tevent_req_post(req, sock->event.ctx);
}

static void tsocket_connect_handler(struct tsocket_context *sock,
				    void *private_data)
{
	struct tevent_req *req = talloc_get_type(private_data,
				 struct tevent_req);
	struct tsocket_connect_state *state = tevent_req_data(req,
					      struct tsocket_connect_state);
	int ret;
	int err;
	bool retry;

	ret = tsocket_get_status(state->caller.sock);
	err = tsocket_error_from_errno(ret, errno, &retry);
	if (retry) {
		/* retry later */
		return;
	}
	if (tevent_req_error(req, err)) {
		return;
	}

	tevent_req_done(req);
}

int tsocket_connect_recv(struct tevent_req *req, int *perrno)
{
	int ret;

	ret = tsocket_simple_int_recv(req, perrno);

	tevent_req_received(req);
	return ret;
}

