/*
 * Unix SMB/CIFS implementation.
 * Wait for process death
 * Copyright (C) Volker Lendecke 2016
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "replace.h"
#include <tevent.h>
#include <talloc.h>
#include "serverid.h"
#include "server_id_watch.h"
#include "lib/util/tevent_unix.h"

struct server_id_watch_state {
	struct tevent_context *ev;
	struct server_id pid;
};

static void server_id_watch_waited(struct tevent_req *subreq);

struct tevent_req *server_id_watch_send(TALLOC_CTX *mem_ctx,
					struct tevent_context *ev,
					struct server_id pid)
{
	struct tevent_req *req, *subreq;
	struct server_id_watch_state *state;

	req = tevent_req_create(mem_ctx, &state, struct server_id_watch_state);
	if (req == NULL) {
		return NULL;
	}
	state->ev = ev;
	state->pid = pid;

	if (!serverid_exists(&state->pid)) {
		tevent_req_done(req);
		return tevent_req_post(req, ev);
	}

	subreq = tevent_wakeup_send(
		state, ev, tevent_timeval_current_ofs(0, 500000));
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, server_id_watch_waited, req);

	return req;
}

static void server_id_watch_waited(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct server_id_watch_state *state = tevent_req_data(
		req, struct server_id_watch_state);
	bool ok;

	ok = tevent_wakeup_recv(subreq);
	TALLOC_FREE(subreq);
	if (!ok) {
		tevent_req_oom(req);
		return;
	}

	if (!serverid_exists(&state->pid)) {
		tevent_req_done(req);
		return;
	}

	subreq = tevent_wakeup_send(
		state, state->ev, tevent_timeval_current_ofs(0, 500000));
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, server_id_watch_waited, req);
}

int server_id_watch_recv(struct tevent_req *req, struct server_id *pid)
{
	struct server_id_watch_state *state = tevent_req_data(
		req, struct server_id_watch_state);
	int err;

	if (tevent_req_is_unix_error(req, &err)) {
		return err;
	}
	if (pid) {
		*pid = state->pid;
	}
	return 0;
}
