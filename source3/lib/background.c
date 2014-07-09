/*
   Unix SMB/CIFS implementation.
   Regular background jobs as forked helpers
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
#include "lib/util/tevent_ntstatus.h"
#include "lib/async_req/async_sock.h"
#include "include/messages.h"
#include "background.h"

struct background_job_state {
	struct tevent_context *ev;
	struct messaging_context *msg;
	uint32_t *trigger_msgs;
	size_t num_trigger_msgs;
	bool parent_longlived;
	int (*fn)(void *private_data);
	void *private_data;

	struct tevent_req *wakeup_req;
	int pipe_fd;
};

static int background_job_state_destructor(struct background_job_state *s);
static void background_job_waited(struct tevent_req *subreq);
static void background_job_done(struct tevent_req *subreq);
static void background_job_trigger(
	struct messaging_context *msg, void *private_data, uint32_t msg_type,
	struct server_id server_id, DATA_BLOB *data);

struct tevent_req *background_job_send(TALLOC_CTX *mem_ctx,
				       struct tevent_context *ev,
				       struct messaging_context *msg,
				       uint32_t *trigger_msgs,
				       size_t num_trigger_msgs,
				       time_t initial_wait_sec,
				       int (*fn)(void *private_data),
				       void *private_data)
{
	struct tevent_req *req, *subreq;
	struct background_job_state *state;
	size_t i;

	req = tevent_req_create(mem_ctx, &state,
				struct background_job_state);
	if (req == NULL) {
		return NULL;
	}

	state->ev = ev;
	state->msg = msg;

	if (num_trigger_msgs != 0) {
		state->trigger_msgs = (uint32_t *)talloc_memdup(
			state, trigger_msgs,
			sizeof(uint32_t) * num_trigger_msgs);
		if (tevent_req_nomem(state->trigger_msgs, req)) {
			return tevent_req_post(req, ev);
		}
		state->num_trigger_msgs = num_trigger_msgs;
	}

	state->fn = fn;
	state->private_data = private_data;

	state->pipe_fd = -1;
	talloc_set_destructor(state, background_job_state_destructor);

	for (i=0; i<num_trigger_msgs; i++) {
		NTSTATUS status;
		status = messaging_register(msg, state, trigger_msgs[i],
					    background_job_trigger);
		if (tevent_req_nterror(req, status)) {
			return tevent_req_post(req, ev);
		}
	}

	subreq = tevent_wakeup_send(
		state, state->ev, timeval_current_ofs(initial_wait_sec, 0));
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, background_job_waited, req);
	state->wakeup_req = subreq;
	return req;
}

static int background_job_state_destructor(struct background_job_state *state)
{
	size_t i;
	if (state->pipe_fd != -1) {
		close(state->pipe_fd);
		state->pipe_fd = -1;
	}
	for (i=0; i<state->num_trigger_msgs; i++) {
		messaging_deregister(state->msg, state->trigger_msgs[i],
				     state);
	}
	return 0;
}

static void background_job_trigger(
	struct messaging_context *msg, void *private_data, uint32_t msg_type,
	struct server_id server_id, DATA_BLOB *data)
{
	struct background_job_state *state = talloc_get_type_abort(
		private_data, struct background_job_state);

	if (state->wakeup_req == NULL) {
		return;
	}
	if (!tevent_req_set_endtime(state->wakeup_req, state->ev,
				    timeval_zero())) {
		DEBUG(10, ("tevent_req_set_endtime failed\n"));
	}
}

static void background_job_waited(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct background_job_state *state = tevent_req_data(
		req, struct background_job_state);
	int fds[2];
	int res;
	bool ret;

	ret = tevent_wakeup_recv(subreq);
	TALLOC_FREE(subreq);
	state->wakeup_req = NULL;
	if (!ret) {
		tevent_req_nterror(req, NT_STATUS_INTERNAL_ERROR);
		return;
	}

	res = pipe(fds);
	if (res == -1) {
		tevent_req_nterror(req, map_nt_error_from_unix(errno));
		return;
	}

	res = fork();
	if (res == -1) {
		int err = errno;
		close(fds[0]);
		close(fds[1]);
		tevent_req_nterror(req, map_nt_error_from_unix(err));
		return;
	}

	if (res == 0) {
		/* child */

		NTSTATUS status;
		ssize_t written;

		close(fds[0]);

		status = reinit_after_fork(state->msg, state->ev, true);
		if (NT_STATUS_IS_OK(status)) {
			res = state->fn(state->private_data);
		} else {
			res = -1;
		}
		written = write(fds[1], &res, sizeof(res));
		if (written == -1) {
			_exit(1);
		}

		/*
		 * No TALLOC_FREE here, messaging_parent_dgm_cleanup_init for
		 * example calls background_job_send with "messaging_context"
		 * as talloc parent. Thus "state" will be freed with the
		 * following talloc_free will have removed "state" when it
		 * returns. TALLOC_FREE will then write a NULL into free'ed
		 * memory. talloc_free() is required although we immediately
		 * exit, the messaging_context's destructor will want to clean
		 * up.
		 */
		talloc_free(state->msg);
		_exit(0);
	}

	/* parent */

	close(fds[1]);
	state->pipe_fd = fds[0];

	subreq = read_packet_send(state, state->ev, state->pipe_fd,
				  sizeof(int), NULL, NULL);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, background_job_done, req);
}

static void background_job_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct background_job_state *state = tevent_req_data(
		req, struct background_job_state);
	ssize_t ret;
	uint8_t *buf;
	int err;
	int wait_secs;

	ret = read_packet_recv(subreq, talloc_tos(), &buf, &err);
	TALLOC_FREE(subreq);
	if (ret == -1) {
		tevent_req_nterror(req, map_nt_error_from_unix(err));
		return;
	}
	close(state->pipe_fd);
	state->pipe_fd = -1;
	memcpy(&wait_secs, buf, sizeof(wait_secs));
	if (wait_secs == -1) {
		tevent_req_done(req);
		return;
	}
	subreq = tevent_wakeup_send(
		state, state->ev, timeval_current_ofs(wait_secs, 0));
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, background_job_waited, req);
	state->wakeup_req = subreq;
}

NTSTATUS background_job_recv(struct tevent_req *req)
{
	return tevent_req_simple_recv_ntstatus(req);
}
