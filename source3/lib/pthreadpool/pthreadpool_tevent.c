/*
 * Unix SMB/CIFS implementation.
 * threadpool implementation based on pthreads
 * Copyright (C) Volker Lendecke 2009,2011
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
#include "pthreadpool_tevent.h"
#include "pthreadpool.h"
#include "lib/util/tevent_unix.h"
#include "lib/util/dlinklist.h"

struct pthreadpool_tevent_job_state;

struct pthreadpool_tevent {
	struct pthreadpool *pool;

	struct pthreadpool_tevent_job_state *jobs;
};

struct pthreadpool_tevent_job_state {
	struct pthreadpool_tevent_job_state *prev, *next;
	struct pthreadpool_tevent *pool;
	struct tevent_context *ev;
	struct tevent_threaded_context *tctx;
	struct tevent_immediate *im;
	struct tevent_req *req;

	void (*fn)(void *private_data);
	void *private_data;
};

static int pthreadpool_tevent_destructor(struct pthreadpool_tevent *pool);

static int pthreadpool_tevent_job_signal(int jobid,
					 void (*job_fn)(void *private_data),
					 void *job_private_data,
					 void *private_data);

int pthreadpool_tevent_init(TALLOC_CTX *mem_ctx, unsigned max_threads,
			    struct pthreadpool_tevent **presult)
{
	struct pthreadpool_tevent *pool;
	int ret;

	pool = talloc_zero(mem_ctx, struct pthreadpool_tevent);
	if (pool == NULL) {
		return ENOMEM;
	}

	ret = pthreadpool_init(max_threads, &pool->pool,
			       pthreadpool_tevent_job_signal, pool);
	if (ret != 0) {
		TALLOC_FREE(pool);
		return ret;
	}

	talloc_set_destructor(pool, pthreadpool_tevent_destructor);

	*presult = pool;
	return 0;
}

static int pthreadpool_tevent_destructor(struct pthreadpool_tevent *pool)
{
	struct pthreadpool_tevent_job_state *state, *next;
	int ret;

	ret = pthreadpool_destroy(pool->pool);
	if (ret != 0) {
		return ret;
	}
	pool->pool = NULL;

	for (state = pool->jobs; state != NULL; state = next) {
		next = state->next;
		DLIST_REMOVE(pool->jobs, state);
		state->pool = NULL;
	}

	return 0;
}

static void pthreadpool_tevent_job_fn(void *private_data);
static void pthreadpool_tevent_job_done(struct tevent_context *ctx,
					struct tevent_immediate *im,
					void *private_data);

static int pthreadpool_tevent_job_state_destructor(
	struct pthreadpool_tevent_job_state *state)
{
	if (state->pool == NULL) {
		return 0;
	}

	/*
	 * We should never be called with state->req == NULL,
	 * state->pool must be cleared before the 2nd talloc_free().
	 */
	if (state->req == NULL) {
		abort();
	}

	/*
	 * We need to reparent to a long term context.
	 */
	(void)talloc_reparent(state->req, NULL, state);
	state->req = NULL;
	return -1;
}

struct tevent_req *pthreadpool_tevent_job_send(
	TALLOC_CTX *mem_ctx, struct tevent_context *ev,
	struct pthreadpool_tevent *pool,
	void (*fn)(void *private_data), void *private_data)
{
	struct tevent_req *req;
	struct pthreadpool_tevent_job_state *state;
	int ret;

	req = tevent_req_create(mem_ctx, &state,
				struct pthreadpool_tevent_job_state);
	if (req == NULL) {
		return NULL;
	}
	state->pool = pool;
	state->ev = ev;
	state->req = req;
	state->fn = fn;
	state->private_data = private_data;

	state->im = tevent_create_immediate(state);
	if (tevent_req_nomem(state->im, req)) {
		return tevent_req_post(req, ev);
	}

#ifdef HAVE_PTHREAD
	state->tctx = tevent_threaded_context_create(state, ev);
	if (state->tctx == NULL && errno == ENOSYS) {
		/*
		 * Samba build with pthread support but
		 * tevent without???
		 */
		tevent_req_error(req, ENOSYS);
		return tevent_req_post(req, ev);
	}
	if (tevent_req_nomem(state->tctx, req)) {
		return tevent_req_post(req, ev);
	}
#endif

	ret = pthreadpool_add_job(pool->pool, 0,
				  pthreadpool_tevent_job_fn,
				  state);
	if (tevent_req_error(req, ret)) {
		return tevent_req_post(req, ev);
	}

	/*
	 * Once the job is scheduled, we need to protect
	 * our memory.
	 */
	talloc_set_destructor(state, pthreadpool_tevent_job_state_destructor);

	DLIST_ADD_END(pool->jobs, state);

	return req;
}

static void pthreadpool_tevent_job_fn(void *private_data)
{
	struct pthreadpool_tevent_job_state *state = talloc_get_type_abort(
		private_data, struct pthreadpool_tevent_job_state);
	state->fn(state->private_data);
}

static int pthreadpool_tevent_job_signal(int jobid,
					 void (*job_fn)(void *private_data),
					 void *job_private_data,
					 void *private_data)
{
	struct pthreadpool_tevent_job_state *state = talloc_get_type_abort(
		job_private_data, struct pthreadpool_tevent_job_state);

	if (state->tctx != NULL) {
		/* with HAVE_PTHREAD */
		tevent_threaded_schedule_immediate(state->tctx, state->im,
						   pthreadpool_tevent_job_done,
						   state);
	} else {
		/* without HAVE_PTHREAD */
		tevent_schedule_immediate(state->im, state->ev,
					  pthreadpool_tevent_job_done,
					  state);
	}

	return 0;
}

static void pthreadpool_tevent_job_done(struct tevent_context *ctx,
					struct tevent_immediate *im,
					void *private_data)
{
	struct pthreadpool_tevent_job_state *state = talloc_get_type_abort(
		private_data, struct pthreadpool_tevent_job_state);

	if (state->pool != NULL) {
		DLIST_REMOVE(state->pool->jobs, state);
		state->pool = NULL;
	}

	TALLOC_FREE(state->tctx);

	if (state->req == NULL) {
		/*
		 * There was a talloc_free() state->req
		 * while the job was pending,
		 * which mean we're reparented on a longterm
		 * talloc context.
		 *
		 * We just cleanup here...
		 */
		talloc_free(state);
		return;
	}

	tevent_req_done(state->req);
}

int pthreadpool_tevent_job_recv(struct tevent_req *req)
{
	return tevent_req_simple_recv_unix(req);
}
