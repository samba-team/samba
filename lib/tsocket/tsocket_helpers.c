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
#include "tsocket.h"
#include "tsocket_internal.h"

struct tdgram_sendto_queue_state {
	/* this structs are owned by the caller */
	struct {
		struct tevent_context *ev;
		struct tdgram_context *dgram;
		const uint8_t *buf;
		size_t len;
		const struct tsocket_address *dst;
	} caller;
	ssize_t ret;
};

static void tdgram_sendto_queue_trigger(struct tevent_req *req,
					 void *private_data);
static void tdgram_sendto_queue_done(struct tevent_req *subreq);

/**
 * @brief Queue a dgram blob for sending through the socket
 * @param[in] mem_ctx	The memory context for the result
 * @param[in] ev	The event context the operation should work on
 * @param[in] dgram	The tdgram_context to send the message buffer
 * @param[in] queue	The existing dgram queue
 * @param[in] buf	The message buffer
 * @param[in] len	The message length
 * @param[in] dst	The destination socket address
 * @retval		The async request handle
 *
 * This function queues a blob for sending to destination through an existing
 * dgram socket. The async callback is triggered when the whole blob is
 * delivered to the underlying system socket.
 *
 * The caller needs to make sure that all non-scalar input parameters hang
 * arround for the whole lifetime of the request.
 */
struct tevent_req *tdgram_sendto_queue_send(TALLOC_CTX *mem_ctx,
					    struct tevent_context *ev,
					    struct tdgram_context *dgram,
					    struct tevent_queue *queue,
					    const uint8_t *buf,
					    size_t len,
					    struct tsocket_address *dst)
{
	struct tevent_req *req;
	struct tdgram_sendto_queue_state *state;
	bool ok;

	req = tevent_req_create(mem_ctx, &state,
				struct tdgram_sendto_queue_state);
	if (!req) {
		return NULL;
	}

	state->caller.ev	= ev;
	state->caller.dgram	= dgram;
	state->caller.buf	= buf;
	state->caller.len	= len;
	state->caller.dst	= dst;
	state->ret		= -1;

	ok = tevent_queue_add(queue,
			      ev,
			      req,
			      tdgram_sendto_queue_trigger,
			      NULL);
	if (!ok) {
		tevent_req_nomem(NULL, req);
		goto post;
	}

	return req;

 post:
	tevent_req_post(req, ev);
	return req;
}

static void tdgram_sendto_queue_trigger(struct tevent_req *req,
					 void *private_data)
{
	struct tdgram_sendto_queue_state *state = tevent_req_data(req,
					struct tdgram_sendto_queue_state);
	struct tevent_req *subreq;

	subreq = tdgram_sendto_send(state,
				    state->caller.ev,
				    state->caller.dgram,
				    state->caller.buf,
				    state->caller.len,
				    state->caller.dst);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, tdgram_sendto_queue_done, req);
}

static void tdgram_sendto_queue_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(subreq,
				 struct tevent_req);
	struct tdgram_sendto_queue_state *state = tevent_req_data(req,
					struct tdgram_sendto_queue_state);
	ssize_t ret;
	int sys_errno;

	ret = tdgram_sendto_recv(subreq, &sys_errno);
	talloc_free(subreq);
	if (ret == -1) {
		tevent_req_error(req, sys_errno);
		return;
	}
	state->ret = ret;

	tevent_req_done(req);
}

ssize_t tdgram_sendto_queue_recv(struct tevent_req *req, int *perrno)
{
	struct tdgram_sendto_queue_state *state = tevent_req_data(req,
					struct tdgram_sendto_queue_state);
	ssize_t ret;

	ret = tsocket_simple_int_recv(req, perrno);
	if (ret == 0) {
		ret = state->ret;
	}

	tevent_req_received(req);
	return ret;
}

