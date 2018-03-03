/*
   CTDB event daemon - handle requests

   Copyright (C) Amitay Isaacs  2018

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, see <http://www.gnu.org/licenses/>.
*/

#include "replace.h"

#include "lib/util/debug.h"
#include "lib/util/tevent_unix.h"

#include "common/logging.h"

#include "event/event_private.h"
#include "event/event_protocol_api.h"

struct event_request_state {
	struct ctdb_event_request *request;
	struct ctdb_event_reply *reply;
};

static void event_request_done(struct tevent_req *subreq);

static struct tevent_req *event_request_send(
					TALLOC_CTX *mem_ctx,
					struct tevent_context *ev,
					struct event_context *eventd,
					struct ctdb_event_header *header,
					struct ctdb_event_request *request)
{
	struct tevent_req *req, *subreq;
	struct event_request_state *state;

	req = tevent_req_create(mem_ctx, &state, struct event_request_state);
	if (req == NULL) {
		return NULL;
	}

	state->request = request;

	subreq = event_cmd_dispatch_send(state, ev, eventd, request);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, event_request_done, req);

	return req;
}

static void event_request_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct event_request_state *state = tevent_req_data(
		req, struct event_request_state);
	int ret;
	bool ok;

	ok = event_cmd_dispatch_recv(subreq, &ret, state, &state->reply);
	TALLOC_FREE(subreq);
	if (!ok) {
		D_ERR("Command %s failed, ret=%d\n",
		      ctdb_event_command_to_string(state->request->cmd), ret);

		state->reply = talloc_zero(state, struct ctdb_event_reply);
		if (tevent_req_nomem(state->reply, req)) {
			return;
		}

		state->reply->cmd = state->request->cmd;
		state->reply->result = EIO;
	}

	tevent_req_done(req);
}

static bool event_request_recv(struct tevent_req *req,
			       int *perr,
			       TALLOC_CTX *mem_ctx,
			       struct ctdb_event_reply **reply)
{
	struct event_request_state *state = tevent_req_data(
		req, struct event_request_state);

	if (tevent_req_is_unix_error(req, perr)) {
		return false;
	}

	*reply = talloc_steal(mem_ctx, state->reply);

	return true;
}

struct event_pkt_state {
	struct ctdb_event_header header;
	struct ctdb_event_request *request;
	uint8_t *buf;
	size_t buflen;
};

static void event_pkt_done(struct tevent_req *subreq);

struct tevent_req *event_pkt_send(TALLOC_CTX *mem_ctx,
				  struct tevent_context *ev,
				  struct event_context *eventd,
				  uint8_t *buf,
				  size_t buflen)
{
	struct tevent_req *req, *subreq;
	struct event_pkt_state *state;
	int ret;

	req = tevent_req_create(mem_ctx, &state, struct event_pkt_state);
	if (req == NULL) {
		return NULL;
	}

	ret = ctdb_event_request_pull(buf,
				      buflen,
				      &state->header,
				      state,
				      &state->request);
	if (ret != 0) {
		/* Ignore invalid packets */
		D_ERR("Invalid packet received, buflen=%zu\n", buflen);
		tevent_req_error(req, EPROTO);
		return tevent_req_post(req, ev);
	}

	subreq = event_request_send(state,
				  ev,
				  eventd,
				  &state->header,
				  state->request);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, event_pkt_done, req);

	return req;
}

static void event_pkt_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct event_pkt_state *state = tevent_req_data(
		req, struct event_pkt_state);
	struct ctdb_event_header header;
	struct ctdb_event_reply *reply;
	int ret;
	bool ok;

	ok = event_request_recv(subreq, &ret, state, &reply);
	TALLOC_FREE(subreq);
	TALLOC_FREE(state->request);
	if (!ok) {
		tevent_req_error(req, ret);
		return;
	}

	header = (struct ctdb_event_header) {
		.reqid = state->header.reqid,
	};

	state->buflen = ctdb_event_reply_len(&header, reply);
	state->buf = talloc_zero_size(state, state->buflen);
	if (tevent_req_nomem(state->buf, req)) {
		talloc_free(reply);
		return;
	}

	ret = ctdb_event_reply_push(&header,
				    reply,
				    state->buf,
				    &state->buflen);
	talloc_free(reply);
	if (ret != 0) {
		talloc_free(state->buf);
		tevent_req_error(req, ret);
		return;
	}

	tevent_req_done(req);
}

bool event_pkt_recv(struct tevent_req *req,
		    int *perr,
		    TALLOC_CTX *mem_ctx,
		    uint8_t **buf,
		    size_t *buflen)
{
	struct event_pkt_state *state = tevent_req_data(
		req, struct event_pkt_state);

	if (tevent_req_is_unix_error(req, perr)) {
		return false;
	}

	*buf = talloc_steal(mem_ctx, state->buf);
	*buflen = state->buflen;

	return true;
}
