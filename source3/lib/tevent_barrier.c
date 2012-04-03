/*
   Unix SMB/CIFS implementation.
   Implement a barrier
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
#include "tevent_barrier.h"
#include "lib/util/tevent_unix.h"

struct tevent_barrier_waiter {
	struct tevent_immediate *im;
	struct tevent_context *ev;
	struct tevent_req *req;
};

struct tevent_barrier {
	unsigned count;
	struct tevent_barrier_waiter *waiters;
	void (*trigger_cb)(void *private_data);
	void *private_data;
};

static int tevent_barrier_destructor(struct tevent_barrier *b);
static void tevent_barrier_release(struct tevent_barrier *b);
static void tevent_barrier_release_one(struct tevent_context *ctx,
				       struct tevent_immediate *im,
				       void *private_data);
static void tevent_barrier_release_trigger(struct tevent_context *ctx,
					   struct tevent_immediate *im,
					   void *private_data);

struct tevent_barrier *tevent_barrier_init(
	TALLOC_CTX *mem_ctx, unsigned count,
	void (*trigger_cb)(void *private_data), void *private_data)
{
	struct tevent_barrier *b;
	unsigned i;

	if (count == 0) {
		return NULL;
	}

	b = talloc(mem_ctx, struct tevent_barrier);
	if (b == NULL) {
		return NULL;
	}
	b->count = 0;
	b->trigger_cb = trigger_cb;
	b->private_data = private_data;

	b->waiters = talloc_array(b, struct tevent_barrier_waiter, count);
	if (b->waiters == NULL) {
		goto fail;
	}
	for (i=0; i<count; i++) {
		struct tevent_barrier_waiter *w = &b->waiters[i];

		w->im = tevent_create_immediate(b->waiters);
		if (w->im == NULL) {
			goto fail;
		}
		w->req = NULL;
	}
	talloc_set_destructor(b, tevent_barrier_destructor);
	return b;
fail:
	TALLOC_FREE(b);
	return NULL;
}

static int tevent_barrier_destructor(struct tevent_barrier *b)
{
	tevent_barrier_release(b);
	return 0;
}

struct tevent_barrier_wait_state {
	struct tevent_barrier *b;
	int index;
};

static void tevent_barrier_release(struct tevent_barrier *b)
{
	unsigned i;

	for (i=0; i<b->count; i++) {
		struct tevent_barrier_waiter *w = &b->waiters[i];
		struct tevent_barrier_wait_state *state;

		if (w->req == NULL) {
			continue;
		}
		tevent_schedule_immediate(
			w->im, w->ev, tevent_barrier_release_one, w->req);

		state = tevent_req_data(
			w->req, struct tevent_barrier_wait_state);
		talloc_set_destructor(state, NULL);

		w->req = NULL;
		w->ev = NULL;
	}
	b->count = 0;
	if (b->trigger_cb != NULL) {
		b->trigger_cb(b->private_data);
	}
}

static void tevent_barrier_release_one(struct tevent_context *ctx,
				       struct tevent_immediate *im,
				       void *private_data)
{
	struct tevent_req *req = talloc_get_type_abort(
		private_data, struct tevent_req);
	tevent_req_done(req);
}

static int tevent_barrier_wait_state_destructor(
	struct tevent_barrier_wait_state *s);

struct tevent_req *tevent_barrier_wait_send(TALLOC_CTX *mem_ctx,
					    struct tevent_context *ev,
					    struct tevent_barrier *b)
{
	struct tevent_req *req;
	struct tevent_barrier_wait_state *state;
	struct tevent_barrier_waiter *w;
	struct tevent_immediate *im;

	req = tevent_req_create(mem_ctx, &state,
				struct tevent_barrier_wait_state);
	if (req == NULL) {
		return NULL;
	}
	state->b = b;
	state->index = b->count;

	w = &b->waiters[b->count];
	w->ev = ev;
	w->req = req;
	b->count += 1;

	talloc_set_destructor(state, tevent_barrier_wait_state_destructor);

	if (b->count < talloc_array_length(b->waiters)) {
		return req;
	}

	im = tevent_create_immediate(req);
	if (tevent_req_nomem(im, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_schedule_immediate(im, ev, tevent_barrier_release_trigger, b);
	return req;
}

static int tevent_barrier_wait_state_destructor(
	struct tevent_barrier_wait_state *s)
{
	struct tevent_barrier *b = s->b;
	b->waiters[s->index].req = b->waiters[b->count-1].req;
	b->count -= 1;
	return 0;
}

static void tevent_barrier_release_trigger(struct tevent_context *ctx,
					   struct tevent_immediate *im,
					   void *private_data)
{
	struct tevent_barrier *b = talloc_get_type_abort(
		private_data, struct tevent_barrier);
	tevent_barrier_release(b);
}

int tevent_barrier_wait_recv(struct tevent_req *req)
{
	int err;

	if (tevent_req_is_unix_error(req, &err)) {
		return err;
	}
	return 0;
}
