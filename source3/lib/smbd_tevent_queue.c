/*
   Unix SMB/CIFS implementation.
   Infrastructure for async requests
   Copyright (C) Volker Lendecke 2008
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

/* Back-port of missing API from 4.2.x for tevent_queues. */

#include "replace.h"
#include <tevent.h>
#include "source3/lib/smbd_tevent_queue.h"

struct tevent_queue_wait_state {
	uint8_t dummy;
};

static void tevent_queue_wait_trigger(struct tevent_req *req,
				      void *private_data);

struct tevent_req *smbd_tevent_queue_wait_send(TALLOC_CTX *mem_ctx,
					  struct tevent_context *ev,
					  struct tevent_queue *queue)
{
	struct tevent_req *req;
	struct tevent_queue_wait_state *state;
	bool ok;

	req = tevent_req_create(mem_ctx, &state,
				struct tevent_queue_wait_state);
	if (req == NULL) {
		return NULL;
	}

	ok = tevent_queue_add(queue, ev, req,
			      tevent_queue_wait_trigger,
			      NULL);
	if (!ok) {
		tevent_req_oom(req);
		return tevent_req_post(req, ev);
	}

	return req;
}

static void tevent_queue_wait_trigger(struct tevent_req *req,
					 void *private_data)
{
	tevent_req_done(req);
}

bool smbd_tevent_queue_wait_recv(struct tevent_req *req)
{
	enum tevent_req_state state;
	uint64_t err;

	if (tevent_req_is_error(req, &state, &err)) {
		tevent_req_received(req);
		return false;
	}

	tevent_req_received(req);
	return true;
}
