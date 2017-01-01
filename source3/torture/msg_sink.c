/*
 *  Unix SMB/CIFS implementation.
 *  Receive and count messages
 *  Copyright (C) Volker Lendecke 2014
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
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "replace.h"
#include "includes.h"
#include "lib/util/server_id.h"
#include "messages.h"
#include "lib/util/tevent_unix.h"
#include <stdio.h>

struct sink_state {
	struct tevent_context *ev;
	struct messaging_context *msg_ctx;
	int msg_type;
	unsigned *counter;
};

static void sink_done(struct tevent_req *subreq);

static struct tevent_req *sink_send(TALLOC_CTX *mem_ctx,
				    struct tevent_context *ev,
				    struct messaging_context *msg_ctx,
				    int msg_type, unsigned *counter)
{
	struct tevent_req *req, *subreq;
	struct sink_state *state;

	req = tevent_req_create(mem_ctx, &state, struct sink_state);
	if (req == NULL) {
		return NULL;
	}
	state->ev = ev;
	state->msg_ctx = msg_ctx;
	state->msg_type = msg_type;
	state->counter = counter;

	subreq = messaging_read_send(state, state->ev, state->msg_ctx,
				     state->msg_type);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, sink_done, req);
	return req;
}

static void sink_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct sink_state *state = tevent_req_data(
		req, struct sink_state);
	int ret;

	ret = messaging_read_recv(subreq, NULL, NULL);
	TALLOC_FREE(subreq);
	if (tevent_req_error(req, ret)) {
		return;
	}

	*state->counter += 1;

	subreq = messaging_read_send(state, state->ev, state->msg_ctx,
				     state->msg_type);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, sink_done, req);
}

static int sink_recv(struct tevent_req *req)
{
	int err;

	if (tevent_req_is_unix_error(req, &err)) {
		return err;
	}
	return 0;
}

struct prcount_state {
	struct tevent_context *ev;
	struct timeval interval;
	unsigned *counter;
};

static void prcount_waited(struct tevent_req *subreq);

static struct tevent_req *prcount_send(TALLOC_CTX *mem_ctx,
				       struct tevent_context *ev,
				       struct timeval interval,
				       unsigned *counter)
{
	struct tevent_req *req, *subreq;
	struct prcount_state *state;

	req = tevent_req_create(mem_ctx, &state, struct prcount_state);
	if (req == NULL) {
		return NULL;
	}
	state->ev = ev;
	state->interval = interval;
	state->counter = counter;

	subreq = tevent_wakeup_send(
		state, state->ev,
		timeval_current_ofs(state->interval.tv_sec,
				    state->interval.tv_usec));
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, prcount_waited, req);
	return req;
}

static void prcount_waited(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct prcount_state *state = tevent_req_data(
		req, struct prcount_state);
	bool ok;

	ok = tevent_wakeup_recv(subreq);
	TALLOC_FREE(subreq);
	if (!ok) {
		tevent_req_error(req, ENOMEM);
		return;
	}

	printf("%u\n", *state->counter);

	subreq = tevent_wakeup_send(
		state, state->ev,
		timeval_current_ofs(state->interval.tv_sec,
				    state->interval.tv_usec));
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, prcount_waited, req);
}

static int prcount_recv(struct tevent_req *req)
{
	int err;

	if (tevent_req_is_unix_error(req, &err)) {
		return err;
	}
	return 0;
}

struct msgcount_state {
	unsigned count;
};

static void msgcount_sunk(struct tevent_req *subreq);
static void msgcount_printed(struct tevent_req *subreq);

static struct tevent_req *msgcount_send(TALLOC_CTX *mem_ctx,
					struct tevent_context *ev,
					struct messaging_context *msg_ctx,
					int msg_type, struct timeval interval)
{
	struct tevent_req *req, *subreq;
	struct msgcount_state *state;

	req = tevent_req_create(mem_ctx, &state, struct msgcount_state);
	if (req == NULL) {
		return NULL;
	}

	subreq = sink_send(state, ev, msg_ctx, msg_type, &state->count);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, msgcount_sunk, req);

	subreq = prcount_send(state, ev, interval, &state->count);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, msgcount_printed, req);

	return req;
}

static void msgcount_sunk(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	int ret;

	ret = sink_recv(subreq);
	TALLOC_FREE(subreq);
	if (tevent_req_error(req, ret)) {
		return;
	}
	tevent_req_done(req);
}

static void msgcount_printed(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	int ret;

	ret = prcount_recv(subreq);
	TALLOC_FREE(subreq);
	if (tevent_req_error(req, ret)) {
		return;
	}
	tevent_req_done(req);
}

static int msgcount_recv(struct tevent_req *req)
{
	int err;

	if (tevent_req_is_unix_error(req, &err)) {
		return err;
	}
	return 0;
}

int main(void)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct tevent_context *ev;
	struct messaging_context *msg_ctx;
	struct tevent_req *req;
	int ret;
	struct server_id id;
	struct server_id_buf tmp;

	lp_load_global(get_dyn_CONFIGFILE());

	ev = tevent_context_init(frame);
	if (ev == NULL) {
		perror("tevent_context_init failed");
		return -1;
	}

	msg_ctx = messaging_init(ev, ev);
	if (msg_ctx == NULL) {
		perror("messaging_init failed");
		return -1;
	}

	id = messaging_server_id(msg_ctx);

	printf("server_id: %s\n", server_id_str_buf(id, &tmp));

	req = msgcount_send(ev, ev, msg_ctx, MSG_SMB_NOTIFY,
			    timeval_set(1, 0));
	if (req == NULL) {
		perror("msgcount_send failed");
		return -1;
	}

	if (!tevent_req_poll(req, ev)) {
		perror("tevent_req_poll failed");
		return -1;
	}

	ret = msgcount_recv(req);
	printf("msgcount_recv returned %d\n", ret);

	return 0;
}
