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
	uint8_t _dummy_;
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

	tevent_req_defer_callback(req, ev);
	return req;
}

void tevent_wait_done(struct tevent_req *req)
{
	if (req == NULL) {
		return;
	}

	tevent_req_done(req);
}

int tevent_wait_recv(struct tevent_req *req)
{
	return tevent_req_simple_recv_unix(req);
}
