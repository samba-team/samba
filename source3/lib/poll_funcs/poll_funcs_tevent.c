/*
 * Unix SMB/CIFS implementation.
 * Copyright (C) Volker Lendecke 2013,2014
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

#include "poll_funcs_tevent.h"
#include "tevent.h"
#include "system/select.h"

/*
 * A poll_watch is asked for by the engine using this library via
 * funcs->watch_new(). It represents interest in "fd" becoming readable or
 * writable.
 */

struct poll_watch {
	struct poll_funcs_state *state;
	unsigned slot; 		/* index into state->watches[] */
	int fd;
	int events;
	void (*callback)(struct poll_watch *w, int fd, short events,
			 void *private_data);
	void *private_data;
};

struct poll_funcs_state {
	/*
	 * "watches" is the array of all watches that we have handed out via
	 * funcs->watch_new(). The "watches" array can contain NULL pointers.
	 */
	unsigned num_watches;
	struct poll_watch **watches;

	/*
	 * "contexts is the array of tevent_contexts that serve
	 * "watches". "contexts" can contain NULL pointers.
	 */
	unsigned num_contexts;
	struct poll_funcs_tevent_context **contexts;
};

struct poll_funcs_tevent_context {
	unsigned refcount;
	struct poll_funcs_state *state;
	unsigned slot;		/* index into state->contexts[] */
	struct tevent_context *ev;
	struct tevent_fd **fdes; /* same indexes as state->watches[] */
};

/*
 * poll_funcs_tevent_register() hands out a struct poll_funcs_tevent_handle as
 * a void *. poll_funcs_tevent_register allows tevent_contexts to be
 * registered multiple times, and we can't add a tevent_fd for the same fd's
 * multiple times. So we have to share one poll_funcs_tevent_context.
 */
struct poll_funcs_tevent_handle {
	struct poll_funcs_tevent_context *ctx;
};

static uint16_t poll_events_to_tevent(short events)
{
	uint16_t ret = 0;

	if (events & POLLIN) {
		ret |= TEVENT_FD_READ;
	}
	if (events & POLLOUT) {
		ret |= TEVENT_FD_WRITE;
	}
	return ret;
}

static short tevent_to_poll_events(uint16_t flags)
{
	short ret = 0;

	if (flags & TEVENT_FD_READ) {
		ret |= POLLIN;
	}
	if (flags & TEVENT_FD_WRITE) {
		ret |= POLLOUT;
	}
	return ret;
}

/*
 * Find or create a free slot in state->watches[]
 */
static bool poll_funcs_watch_find_slot(struct poll_funcs_state *state,
				       unsigned *slot)
{
	struct poll_watch **watches;
	unsigned i;

	for (i=0; i<state->num_watches; i++) {
		if (state->watches[i] == NULL) {
			*slot = i;
			return true;
		}
	}

	watches = talloc_realloc(state, state->watches, struct poll_watch *,
				 state->num_watches + 1);
	if (watches == NULL) {
		return false;
	}
	watches[state->num_watches] = NULL;
	state->watches = watches;

	for (i=0; i<state->num_contexts; i++) {
		struct tevent_fd **fdes;
		struct poll_funcs_tevent_context *c = state->contexts[i];
		if (c == NULL) {
			continue;
		}
		fdes = talloc_realloc(c, c->fdes, struct tevent_fd *,
				      state->num_watches + 1);
		if (fdes == NULL) {
			return false;
		}
		c->fdes = fdes;

		fdes[state->num_watches] = NULL;
	}

	*slot = state->num_watches;
	state->num_watches += 1;

	return true;
}

static void poll_funcs_fde_handler(struct tevent_context *ev,
				   struct tevent_fd *fde, uint16_t flags,
				   void *private_data);
static int poll_watch_destructor(struct poll_watch *w);

static struct poll_watch *tevent_watch_new(
	const struct poll_funcs *funcs, int fd, short events,
	void (*callback)(struct poll_watch *w, int fd, short events,
			 void *private_data),
	void *private_data)
{
	struct poll_funcs_state *state = talloc_get_type_abort(
		funcs->private_data, struct poll_funcs_state);
	struct poll_watch *w;
	unsigned i, slot;

	if (!poll_funcs_watch_find_slot(state, &slot)) {
		return NULL;
	}

	w = talloc(state->watches, struct poll_watch);
	if (w == NULL) {
		return NULL;
	}
	w->state = state;
	w->slot = slot;
	w->fd = fd;
	w->events = poll_events_to_tevent(events);
	w->fd = fd;
	w->callback = callback;
	w->private_data = private_data;
	state->watches[slot] = w;

	talloc_set_destructor(w, poll_watch_destructor);

	for (i=0; i<state->num_contexts; i++) {
		struct poll_funcs_tevent_context *c = state->contexts[i];
		if (c == NULL) {
			continue;
		}
		c->fdes[slot] = tevent_add_fd(c->ev, c->fdes, w->fd, w->events,
					      poll_funcs_fde_handler, w);
		if (c->fdes[slot] == NULL) {
			goto fail;
		}
	}
	return w;

fail:
	TALLOC_FREE(w);
	return NULL;
}

static int poll_watch_destructor(struct poll_watch *w)
{
	struct poll_funcs_state *state = w->state;
	unsigned slot = w->slot;
	unsigned i;

	TALLOC_FREE(state->watches[slot]);

	for (i=0; i<state->num_contexts; i++) {
		struct poll_funcs_tevent_context *c = state->contexts[i];
		if (c == NULL) {
			continue;
		}
		TALLOC_FREE(c->fdes[slot]);
	}

	return 0;
}

static void tevent_watch_update(struct poll_watch *w, short events)
{
	struct poll_funcs_state *state = w->state;
	unsigned slot = w->slot;
	unsigned i;

	w->events = poll_events_to_tevent(events);

	for (i=0; i<state->num_contexts; i++) {
		struct poll_funcs_tevent_context *c = state->contexts[i];
		if (c == NULL) {
			continue;
		}
		tevent_fd_set_flags(c->fdes[slot], w->events);
	}
}

static short tevent_watch_get_events(struct poll_watch *w)
{
	return tevent_to_poll_events(w->events);
}

static void tevent_watch_free(struct poll_watch *w)
{
	TALLOC_FREE(w);
}

static struct poll_timeout *tevent_timeout_new(
	const struct poll_funcs *funcs, const struct timeval *tv,
	void (*callback)(struct poll_timeout *t, void *private_data),
	void *private_data)
{
	/* not implemented yet */
	return NULL;
}

static void tevent_timeout_update(struct poll_timeout *t,
				  const struct timespec *ts)
{
	return;
}

static void tevent_timeout_free(struct poll_timeout *t)
{
	return;
}

static int poll_funcs_state_destructor(struct poll_funcs_state *state);

struct poll_funcs *poll_funcs_init_tevent(TALLOC_CTX *mem_ctx)
{
	struct poll_funcs *f;
	struct poll_funcs_state *state;

	f = talloc(mem_ctx, struct poll_funcs);
	if (f == NULL) {
		return NULL;
	}
	state = talloc_zero(f, struct poll_funcs_state);
	if (state == NULL) {
		TALLOC_FREE(f);
		return NULL;
	}
	talloc_set_destructor(state, poll_funcs_state_destructor);

	f->watch_new = tevent_watch_new;
	f->watch_update = tevent_watch_update;
	f->watch_get_events = tevent_watch_get_events;
	f->watch_free = tevent_watch_free;
	f->timeout_new = tevent_timeout_new;
	f->timeout_update = tevent_timeout_update;
	f->timeout_free = tevent_timeout_free;
	f->private_data = state;
	return f;
}

static int poll_funcs_state_destructor(struct poll_funcs_state *state)
{
	unsigned i;
	/*
	 * Make sure the watches are cleared before the contexts. The watches
	 * have destructors attached to them that clean up the fde's
	 */
	for (i=0; i<state->num_watches; i++) {
		TALLOC_FREE(state->watches[i]);
	}
	return 0;
}

/*
 * Find or create a free slot in state->contexts[]
 */
static bool poll_funcs_context_slot_find(struct poll_funcs_state *state,
					 struct tevent_context *ev,
					 unsigned *slot)
{
	struct poll_funcs_tevent_context **contexts;
	unsigned i;

	for (i=0; i<state->num_contexts; i++) {
		struct poll_funcs_tevent_context *ctx = state->contexts[i];

		if ((ctx == NULL) || (ctx->ev == ev)) {
			*slot = i;
			return true;
		}
	}

	contexts = talloc_realloc(state, state->contexts,
				  struct poll_funcs_tevent_context *,
				  state->num_contexts + 1);
	if (contexts == NULL) {
		return false;
	}
	state->contexts = contexts;
	state->contexts[state->num_contexts] = NULL;

	*slot = state->num_contexts;
	state->num_contexts += 1;

	return true;
}

static int poll_funcs_tevent_context_destructor(
	struct poll_funcs_tevent_context *ctx);

static struct poll_funcs_tevent_context *poll_funcs_tevent_context_new(
	TALLOC_CTX *mem_ctx, struct poll_funcs_state *state,
	struct tevent_context *ev, unsigned slot)
{
	struct poll_funcs_tevent_context *ctx;
	unsigned i;

	ctx = talloc(mem_ctx, struct poll_funcs_tevent_context);
	if (ctx == NULL) {
		return NULL;
	}

	ctx->refcount = 0;
	ctx->state = state;
	ctx->ev = ev;
	ctx->slot = slot;

	ctx->fdes = talloc_array(ctx, struct tevent_fd *, state->num_watches);
	if (ctx->fdes == NULL) {
		goto fail;
	}

	for (i=0; i<state->num_watches; i++) {
		struct poll_watch *w = state->watches[i];

		if (w == NULL) {
			ctx->fdes[i] = NULL;
			continue;
		}
		ctx->fdes[i] = tevent_add_fd(ev, ctx->fdes, w->fd, w->events,
					     poll_funcs_fde_handler, w);
		if (ctx->fdes[i] == NULL) {
			goto fail;
		}
	}
	talloc_set_destructor(ctx, poll_funcs_tevent_context_destructor);
	return ctx;
fail:
	TALLOC_FREE(ctx);
	return NULL;
}

static int poll_funcs_tevent_context_destructor(
	struct poll_funcs_tevent_context *ctx)
{
	ctx->state->contexts[ctx->slot] = NULL;
	return 0;
}

static void poll_funcs_fde_handler(struct tevent_context *ev,
				   struct tevent_fd *fde, uint16_t flags,
				   void *private_data)
{
	struct poll_watch *w = talloc_get_type_abort(
		private_data, struct poll_watch);
	short events = tevent_to_poll_events(flags);
	w->callback(w, w->fd, events, w->private_data);
}

static int poll_funcs_tevent_handle_destructor(
	struct poll_funcs_tevent_handle *handle);

void *poll_funcs_tevent_register(TALLOC_CTX *mem_ctx, struct poll_funcs *f,
				 struct tevent_context *ev)
{
	struct poll_funcs_state *state = talloc_get_type_abort(
		f->private_data, struct poll_funcs_state);
	struct poll_funcs_tevent_handle *handle;
	unsigned slot;

	handle = talloc(mem_ctx, struct poll_funcs_tevent_handle);
	if (handle == NULL) {
		return NULL;
	}

	if (!poll_funcs_context_slot_find(state, ev, &slot)) {
		goto fail;
	}
	if (state->contexts[slot] == NULL) {
		state->contexts[slot] = poll_funcs_tevent_context_new(
			state->contexts, state, ev, slot);
		if (state->contexts[slot] == NULL) {
			goto fail;
		}
	}

	handle->ctx = state->contexts[slot];
	handle->ctx->refcount += 1;
	talloc_set_destructor(handle, poll_funcs_tevent_handle_destructor);
	return handle;
fail:
	TALLOC_FREE(handle);
	return NULL;
}

static int poll_funcs_tevent_handle_destructor(
	struct poll_funcs_tevent_handle *handle)
{
	if (handle->ctx->refcount == 0) {
		abort();
	}
	handle->ctx->refcount -= 1;

	if (handle->ctx->refcount != 0) {
		return 0;
	}
	TALLOC_FREE(handle->ctx);
	return 0;
}
