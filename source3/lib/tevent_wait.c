/*
   Unix SMB/CIFS implementation.
   Implement a send/recv interface to wait for an external trigger
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

#include "lib/replace/replace.h"
#include "talloc.h"
#include "tevent.h"
#include "tevent_wait.h"
#include "lib/util/tevent_unix.h"

struct tevent_wait_state {
	struct tevent_immediate *im;
	struct tevent_context *ev;
};

struct tevent_req *tevent_wait_send(TALLOC_CTX *mem_ctx,
				    struct tevent_context *ev)
{
	struct tevent_req *req;
	struct tevent_wait_state *state;

	req = tevent_req_create(mem_ctx, &state, struct tevent_wait_state);
	if (req == NULL) {
		return NULL;
	}
	state->ev = ev;
	state->im = tevent_create_immediate(state);
	if (tevent_req_nomem(state->im, req)) {
		return tevent_req_post(req, ev);
	}
	return req;
}

static void tevent_wait_trigger(struct tevent_context *ctx,
				struct tevent_immediate *im,
				void *private_data);

void tevent_wait_done(struct tevent_req *req)
{
	struct tevent_wait_state *state;

	if (req == NULL) {
		return;
	}
	state = tevent_req_data(req, struct tevent_wait_state);

	tevent_schedule_immediate(state->im, state->ev,
				  tevent_wait_trigger, req);
}

static void tevent_wait_trigger(struct tevent_context *ctx,
				struct tevent_immediate *im,
				void *private_data)
{
	struct tevent_req *req = talloc_get_type_abort(
		private_data, struct tevent_req);
	tevent_req_done(req);
}

int tevent_wait_recv(struct tevent_req *req)
{
	int err;

	if (tevent_req_is_unix_error(req, &err)) {
		return err;
	}
	return 0;
}
