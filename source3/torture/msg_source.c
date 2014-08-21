/*
 *  Unix SMB/CIFS implementation.
 *  Send messages once a second
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
#include "messages.h"
#include "lib/util/tevent_unix.h"
#include <stdio.h>

struct source_state {
	struct tevent_context *ev;
	struct messaging_context *msg_ctx;
	int msg_type;
	struct timeval interval;
	struct server_id dst;
};

static void source_waited(struct tevent_req *subreq);

static struct tevent_req *source_send(TALLOC_CTX *mem_ctx,
				      struct tevent_context *ev,
				      struct messaging_context *msg_ctx,
				      int msg_type,
				      struct timeval interval,
				      struct server_id dst)
{
	struct tevent_req *req, *subreq;
	struct source_state *state;

	req = tevent_req_create(mem_ctx, &state, struct source_state);
	if (req == NULL) {
		return NULL;
	}
	state->ev = ev;
	state->msg_ctx = msg_ctx;
	state->msg_type = msg_type;
	state->interval = interval;
	state->dst = dst;

	subreq = tevent_wakeup_send(
		state, state->ev,
		timeval_current_ofs(state->interval.tv_sec,
				    state->interval.tv_usec));
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, source_waited, req);
	return req;
}

static void source_waited(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct source_state *state = tevent_req_data(
		req, struct source_state);
	bool ok;
	uint8_t buf[200] = { };

	ok = tevent_wakeup_recv(subreq);
	TALLOC_FREE(subreq);
	if (!ok) {
		tevent_req_error(req, ENOMEM);
		return;
	}

	messaging_send_buf(state->msg_ctx, state->dst, state->msg_type,
			   buf, sizeof(buf));

	subreq = tevent_wakeup_send(
		state, state->ev,
		timeval_current_ofs(state->interval.tv_sec,
				    state->interval.tv_usec));
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, source_waited, req);
}

static int source_recv(struct tevent_req *req)
{
	int err;

	if (tevent_req_is_unix_error(req, &err)) {
		return err;
	}
	return 0;
}

int main(int argc, const char *argv[])
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct tevent_context *ev;
	struct messaging_context *msg_ctx;
	struct tevent_req *req;
	int ret;
	struct server_id id;

	if (argc != 2) {
		fprintf(stderr, "Usage: %s <dst>\n", argv[0]);
		return -1;
	}

	lp_load(get_dyn_CONFIGFILE(), true, false, false, true);

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

	id = server_id_from_string(get_my_vnn(), argv[1]);
	if (!procid_valid(&id)) {
		fprintf(stderr, "pid %s invalid\n", argv[1]);
		return -1;
	}

	req = source_send(ev, ev, msg_ctx, MSG_SMB_NOTIFY,
			  timeval_set(0, 10000), id);
	if (req == NULL) {
		perror("source_send failed");
		return -1;
	}

	if (!tevent_req_poll(req, ev)) {
		perror("tevent_req_poll failed");
		return -1;
	}

	ret = source_recv(req);

	printf("source_recv returned %d\n", ret);

	return 0;
}
