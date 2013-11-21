/*
   Unix SMB/CIFS implementation.
   Test msg_stream API
   Copyright (C) Volker Lendecke 2012

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
#include "torture/proto.h"
#include "lib/util/tevent_unix.h"
#include "msg_channel.h"

struct msg_test_state {
	struct tevent_context *ev;
	struct messaging_context *msg;
	struct msg_channel *channel;
};

static void msg_test_got_channel(struct tevent_req *subreq);
static void msg_test_got_msg(struct tevent_req *subreq);

static struct tevent_req *msg_test_send(TALLOC_CTX *mem_ctx,
					struct tevent_context *ev)
{
	struct tevent_req *req, *subreq;
	struct msg_test_state *state;

	req = tevent_req_create(mem_ctx, &state, struct msg_test_state);
	if (req == NULL) {
		return NULL;
	}
	state->ev = ev;

	state->msg = messaging_init(state, state->ev);
	if (tevent_req_nomem(state->msg, req)) {
		return tevent_req_post(req, ev);
	}
	subreq = msg_channel_init_send(state, state->ev, state->msg, MSG_PING);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, msg_test_got_channel, req);
	return req;
}

static void msg_test_got_channel(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct msg_test_state *state = tevent_req_data(
		req, struct msg_test_state);
	int ret;

	ret = msg_channel_init_recv(subreq, state, &state->channel);
	TALLOC_FREE(subreq);
	if (tevent_req_error(req, ret)) {
		return;
	}
	subreq = msg_read_send(state, state->ev, state->channel);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, msg_test_got_msg, req);
}

static void msg_test_got_msg(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct msg_test_state *state = tevent_req_data(
		req, struct msg_test_state);
	struct messaging_rec *msg;
	int ret;

	ret = msg_read_recv(subreq, state, &msg);
	TALLOC_FREE(subreq);
	if (tevent_req_error(req, ret)) {
		return;
	}
	tevent_req_done(req);
}

static int msg_test_recv(struct tevent_req *req)
{
	int err;

	if (tevent_req_is_unix_error(req, &err)) {
		return err;
	}
	return 0;
}

bool run_msg_test(int dummy)
{
	struct tevent_context *ev;
	struct tevent_req *req;
	int ret;

	ev = samba_tevent_context_init(talloc_tos());
	if (ev == NULL) {
		fprintf(stderr, "tevent_context_init failed\n");
		return false;
	}
	req = msg_test_send(ev, ev);
	if (req == NULL) {
		fprintf(stderr, "msg_test_send failed\n");
		return false;
	}
	if (!tevent_req_poll(req, ev)) {
		fprintf(stderr, "tevent_req_poll failed\n");
		return false;
	}
	ret = msg_test_recv(req);
	TALLOC_FREE(req);
	printf("msg_test_recv returned %s\n",
	       ret ? strerror(ret) : "success");
	TALLOC_FREE(ev);
	return (ret == 0);
}

/*
 * Reproducer for bug 10284
 */

static void msg_callback(struct tevent_req *subreq);

struct msg_test2_state {
	struct tevent_context *ev;
	struct messaging_context *msg;
	struct msg_channel *channel;
	struct messaging_rec *rec;
	struct tevent_req *req;
};

bool run_msg_test2(int dummy)
{
	struct msg_test2_state s;
	NTSTATUS status;
	int i, ret;

	s.ev = samba_tevent_context_init(talloc_tos());
	if (s.ev == NULL) {
		fprintf(stderr, "tevent_context_init failed\n");
		return false;
	}

	s.msg = messaging_init(s.ev, s.ev);
	if (s.msg == NULL) {
		fprintf(stderr, "messaging_init failed\n");
		return false;
	}

	ret = msg_channel_init(s.ev, s.msg, MSG_PING, &s.channel);
	if (ret != 0) {
		fprintf(stderr, "msg_channel_init returned %s\n",
			strerror(ret));
		return false;
	}

	status = messaging_send(s.msg, messaging_server_id(s.msg), MSG_PING,
				&data_blob_null);
	if (!NT_STATUS_IS_OK(status)) {
		fprintf(stderr, "messaging_send returned %s\n",
			nt_errstr(status));
		return false;
	}

	ret = tevent_loop_once(s.ev);
	if (ret == -1) {
		fprintf(stderr, "tevent_loop_once failed: %s\n",
			strerror(errno));
		return false;
	}

	s.req = msg_read_send(s.ev, s.ev, s.channel);
	if (s.req == NULL) {
		fprintf(stderr, "msg_read_send failed\n");
		return false;
	}
	tevent_req_set_callback(s.req, msg_callback, &s);

	status = messaging_send(s.msg, messaging_server_id(s.msg), MSG_PING,
				&data_blob_null);
	if (!NT_STATUS_IS_OK(status)) {
		fprintf(stderr, "messaging_send returned %s\n",
			nt_errstr(status));
		return false;
	}

	for (i=0; i<5; i++) {
		tevent_loop_once(s.ev);
	}

	return true;
}

static void msg_callback(struct tevent_req *subreq)
{
	struct msg_test2_state *s = _tevent_req_callback_data(subreq);
	struct messaging_rec *rec;
	msg_read_recv(subreq, NULL, &rec);
	TALLOC_FREE(subreq);
	subreq = msg_read_send(s->ev, s->ev, s->channel);
	tevent_req_set_callback(subreq, msg_callback, s);
}
