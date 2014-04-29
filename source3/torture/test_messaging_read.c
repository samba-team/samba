/*
   Unix SMB/CIFS implementation.
   Test for a messaging_read bug
   Copyright (C) Volker Lendecke 2014

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
#include "messages.h"

struct msg_count_state {
	struct tevent_context *ev;
	struct messaging_context *msg_ctx;
	uint32_t msg_type;
	unsigned *count;
};

static void msg_count_done(struct tevent_req *subreq);

static struct tevent_req *msg_count_send(TALLOC_CTX *mem_ctx,
					 struct tevent_context *ev,
					 struct messaging_context *msg_ctx,
					 uint32_t msg_type,
					 unsigned *count)
{
	struct tevent_req *req, *subreq;
	struct msg_count_state *state;

	req = tevent_req_create(mem_ctx, &state, struct msg_count_state);
	if (req == NULL) {
		return NULL;
	}
	state->ev = ev;
	state->msg_ctx = msg_ctx;
	state->msg_type = msg_type;
	state->count = count;

	subreq = messaging_read_send(state, state->ev, state->msg_ctx,
				     state->msg_type);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, msg_count_done, req);
	return req;
}

static void msg_count_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct msg_count_state *state = tevent_req_data(
		req, struct msg_count_state);
	int ret;

	ret = messaging_read_recv(subreq, NULL, NULL);
	TALLOC_FREE(subreq);
	if (tevent_req_error(req, ret)) {
		return;
	}
	*state->count += 1;

	subreq = messaging_read_send(state, state->ev, state->msg_ctx,
				     state->msg_type);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, msg_count_done, req);
}

bool run_messaging_read1(int dummy)
{
	struct tevent_context *ev = NULL;
	struct messaging_context *msg_ctx = NULL;
	struct tevent_req *req1 = NULL;
	unsigned count1 = 0;
	struct tevent_req *req2 = NULL;
	unsigned count2 = 0;
	NTSTATUS status;
	bool retval = false;

	ev = samba_tevent_context_init(talloc_tos());
	if (ev == NULL) {
		fprintf(stderr, "tevent_context_init failed\n");
		goto fail;
	}
	msg_ctx = messaging_init(ev, ev);
	if (msg_ctx == NULL) {
		fprintf(stderr, "messaging_init failed\n");
		goto fail;
	}

	req1 = msg_count_send(ev, ev, msg_ctx, MSG_SMB_NOTIFY, &count1);
	if (req1 == NULL) {
		fprintf(stderr, "msg_count_send failed\n");
		goto fail;
	}
	req2 = msg_count_send(ev, ev, msg_ctx, MSG_SMB_NOTIFY, &count2);
	if (req1 == NULL) {
		fprintf(stderr, "msg_count_send failed\n");
		goto fail;
	}
	status = messaging_send_buf(msg_ctx, messaging_server_id(msg_ctx),
				    MSG_SMB_NOTIFY, NULL, 0);
	if (!NT_STATUS_IS_OK(status)) {
		fprintf(stderr, "messaging_send_buf failed: %s\n",
			nt_errstr(status));
		goto fail;
	}

	if (tevent_loop_once(ev) != 0) {
		fprintf(stderr, "tevent_loop_once failed\n");
		goto fail;
	}

	printf("%u/%u\n", count1, count2);

	if ((count1 != 1) || (count2 != 1)){
		fprintf(stderr, "Got %u/%u msgs, expected 1 each\n",
			count1, count2);
		goto fail;
	}

	retval = true;
fail:
	TALLOC_FREE(req1);
	TALLOC_FREE(req2);
	TALLOC_FREE(msg_ctx);
	TALLOC_FREE(ev);
	return retval;
}

struct msg_free_state {
	struct tevent_req **to_free;
};

static void msg_free_done(struct tevent_req *subreq);

static struct tevent_req *msg_free_send(TALLOC_CTX *mem_ctx,
					struct tevent_context *ev,
					struct messaging_context *msg_ctx,
					uint32_t msg_type,
					struct tevent_req **to_free)
{
	struct tevent_req *req, *subreq;
	struct msg_free_state *state;

	req = tevent_req_create(mem_ctx, &state, struct msg_free_state);
	if (req == NULL) {
		return NULL;
	}
	state->to_free = to_free;

	subreq = messaging_read_send(state, ev, msg_ctx, msg_type);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, msg_free_done, req);
	return req;
}

static void msg_free_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct msg_free_state *state = tevent_req_data(
		req, struct msg_free_state);
	int ret;

	ret = messaging_read_recv(subreq, NULL, NULL);
	TALLOC_FREE(subreq);
	if (tevent_req_error(req, ret)) {
		return;
	}
	TALLOC_FREE(*state->to_free);
	tevent_req_done(req);
}

bool run_messaging_read2(int dummy)
{
	struct tevent_context *ev = NULL;
	struct messaging_context *msg_ctx = NULL;
	struct tevent_req *req1 = NULL;
	struct tevent_req *req2 = NULL;
	unsigned count = 0;
	NTSTATUS status;
	bool retval = false;

	ev = samba_tevent_context_init(talloc_tos());
	if (ev == NULL) {
		fprintf(stderr, "tevent_context_init failed\n");
		goto fail;
	}
	msg_ctx = messaging_init(ev, ev);
	if (msg_ctx == NULL) {
		fprintf(stderr, "messaging_init failed\n");
		goto fail;
	}

	req1 = msg_free_send(ev, ev, msg_ctx, MSG_SMB_NOTIFY, &req2);
	if (req1 == NULL) {
		fprintf(stderr, "msg_count_send failed\n");
		goto fail;
	}
	req2 = msg_count_send(ev, ev, msg_ctx, MSG_SMB_NOTIFY, &count);
	if (req1 == NULL) {
		fprintf(stderr, "msg_count_send failed\n");
		goto fail;
	}
	status = messaging_send_buf(msg_ctx, messaging_server_id(msg_ctx),
				    MSG_SMB_NOTIFY, NULL, 0);
	if (!NT_STATUS_IS_OK(status)) {
		fprintf(stderr, "messaging_send_buf failed: %s\n",
			nt_errstr(status));
		goto fail;
	}

	if (!tevent_req_poll(req1, ev) != 0) {
		fprintf(stderr, "tevent_req_poll failed\n");
		goto fail;
	}

	if (count != 0) {
		fprintf(stderr, "Got %u msgs, expected none\n", count);
		goto fail;
	}

	retval = true;
fail:
	TALLOC_FREE(req1);
	TALLOC_FREE(msg_ctx);
	TALLOC_FREE(ev);
	return retval;
}
