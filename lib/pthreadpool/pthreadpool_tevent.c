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
#include "system/filesys.h"
#include "pthreadpool_tevent.h"
#include "pthreadpool.h"
#include "lib/util/tevent_unix.h"
#include "lib/util/dlinklist.h"

struct pthreadpool_tevent_job_state;

/*
 * We need one pthreadpool_tevent_glue object per unique combintaion of tevent
 * contexts and pthreadpool_tevent objects. Maintain a list of used tevent
 * contexts in a pthreadpool_tevent.
 */
struct pthreadpool_tevent_glue {
	struct pthreadpool_tevent_glue *prev, *next;
	struct pthreadpool_tevent *pool; /* back-pointer to owning object. */
	/* Tuple we are keeping track of in this list. */
	struct tevent_context *ev;
	struct tevent_threaded_context *tctx;
	/* Pointer to link object owned by *ev. */
	struct pthreadpool_tevent_glue_ev_link *ev_link;
};

/*
 * The pthreadpool_tevent_glue_ev_link and its destructor ensure we remove the
 * tevent context from our list of active event contexts if the event context
 * is destroyed.
 * This structure is talloc()'ed from the struct tevent_context *, and is a
 * back-pointer allowing the related struct pthreadpool_tevent_glue object
 * to be removed from the struct pthreadpool_tevent glue list if the owning
 * tevent_context is talloc_free()'ed.
 */
struct pthreadpool_tevent_glue_ev_link {
	struct pthreadpool_tevent_glue *glue;
};

struct pthreadpool_tevent {
	struct pthreadpool *pool;
	struct pthreadpool_tevent_glue *glue_list;

	struct pthreadpool_tevent_job_state *jobs;
};

struct pthreadpool_tevent_job_state {
	struct pthreadpool_tevent_job_state *prev, *next;
	struct pthreadpool_tevent *pool;
	struct tevent_context *ev;
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

size_t pthreadpool_tevent_max_threads(struct pthreadpool_tevent *pool)
{
	if (pool->pool == NULL) {
		return 0;
	}

	return pthreadpool_max_threads(pool->pool);
}

size_t pthreadpool_tevent_queued_jobs(struct pthreadpool_tevent *pool)
{
	if (pool->pool == NULL) {
		return 0;
	}

	return pthreadpool_queued_jobs(pool->pool);
}

static int pthreadpool_tevent_destructor(struct pthreadpool_tevent *pool)
{
	struct pthreadpool_tevent_job_state *state, *next;
	struct pthreadpool_tevent_glue *glue = NULL;
	int ret;

	ret = pthreadpool_stop(pool->pool);
	if (ret != 0) {
		return ret;
	}

	for (state = pool->jobs; state != NULL; state = next) {
		next = state->next;
		DLIST_REMOVE(pool->jobs, state);
		state->pool = NULL;
	}

	/*
	 * Delete all the registered
	 * tevent_context/tevent_threaded_context
	 * pairs.
	 */
	for (glue = pool->glue_list; glue != NULL; glue = pool->glue_list) {
		/* The glue destructor removes it from the list */
		TALLOC_FREE(glue);
	}
	pool->glue_list = NULL;

	ret = pthreadpool_destroy(pool->pool);
	if (ret != 0) {
		return ret;
	}
	pool->pool = NULL;

	return 0;
}

static int pthreadpool_tevent_glue_destructor(
	struct pthreadpool_tevent_glue *glue)
{
	if (glue->pool->glue_list != NULL) {
		DLIST_REMOVE(glue->pool->glue_list, glue);
	}

	/* Ensure the ev_link destructor knows we're gone */
	glue->ev_link->glue = NULL;

	TALLOC_FREE(glue->ev_link);
	TALLOC_FREE(glue->tctx);

	return 0;
}

/*
 * Destructor called either explicitly from
 * pthreadpool_tevent_glue_destructor(), or indirectly
 * when owning tevent_context is destroyed.
 *
 * When called from pthreadpool_tevent_glue_destructor()
 * ev_link->glue is already NULL, so this does nothing.
 *
 * When called from talloc_free() of the owning
 * tevent_context we must ensure we also remove the
 * linked glue object from the list inside
 * struct pthreadpool_tevent.
 */
static int pthreadpool_tevent_glue_link_destructor(
	struct pthreadpool_tevent_glue_ev_link *ev_link)
{
	TALLOC_FREE(ev_link->glue);
	return 0;
}

static int pthreadpool_tevent_register_ev(struct pthreadpool_tevent *pool,
					  struct tevent_context *ev)
{
	struct pthreadpool_tevent_glue *glue = NULL;
	struct pthreadpool_tevent_glue_ev_link *ev_link = NULL;

	/*
	 * See if this tevent_context was already registered by
	 * searching the glue object list. If so we have nothing
	 * to do here - we already have a tevent_context/tevent_threaded_context
	 * pair.
	 */
	for (glue = pool->glue_list; glue != NULL; glue = glue->next) {
		if (glue->ev == ev) {
			return 0;
		}
	}

	/*
	 * Event context not yet registered - create a new glue
	 * object containing a tevent_context/tevent_threaded_context
	 * pair and put it on the list to remember this registration.
	 * We also need a link object to ensure the event context
	 * can't go away without us knowing about it.
	 */
	glue = talloc_zero(pool, struct pthreadpool_tevent_glue);
	if (glue == NULL) {
		return ENOMEM;
	}
	*glue = (struct pthreadpool_tevent_glue) {
		.pool = pool,
		.ev = ev,
	};
	talloc_set_destructor(glue, pthreadpool_tevent_glue_destructor);

	/*
	 * Now allocate the link object to the event context. Note this
	 * is allocated OFF THE EVENT CONTEXT ITSELF, so if the event
	 * context is freed we are able to cleanup the glue object
	 * in the link object destructor.
	 */

	ev_link = talloc_zero(ev, struct pthreadpool_tevent_glue_ev_link);
	if (ev_link == NULL) {
		TALLOC_FREE(glue);
		return ENOMEM;
	}
	ev_link->glue = glue;
	talloc_set_destructor(ev_link, pthreadpool_tevent_glue_link_destructor);

	glue->ev_link = ev_link;

#ifdef HAVE_PTHREAD
	glue->tctx = tevent_threaded_context_create(glue, ev);
	if (glue->tctx == NULL) {
		TALLOC_FREE(ev_link);
		TALLOC_FREE(glue);
		return ENOMEM;
	}
#endif

	DLIST_ADD(pool->glue_list, glue);
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

	if (pool == NULL) {
		tevent_req_error(req, EINVAL);
		return tevent_req_post(req, ev);
	}
	if (pool->pool == NULL) {
		tevent_req_error(req, EINVAL);
		return tevent_req_post(req, ev);
	}

	state->im = tevent_create_immediate(state);
	if (tevent_req_nomem(state->im, req)) {
		return tevent_req_post(req, ev);
	}

	ret = pthreadpool_tevent_register_ev(pool, ev);
	if (tevent_req_error(req, ret)) {
		return tevent_req_post(req, ev);
	}

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
	struct tevent_threaded_context *tctx = NULL;
	struct pthreadpool_tevent_glue *g = NULL;

	if (state->pool == NULL) {
		/* The pthreadpool_tevent is already gone */
		return 0;
	}

#ifdef HAVE_PTHREAD
	for (g = state->pool->glue_list; g != NULL; g = g->next) {
		if (g->ev == state->ev) {
			tctx = g->tctx;
			break;
		}
	}

	if (tctx == NULL) {
		abort();
	}
#endif

	if (tctx != NULL) {
		/* with HAVE_PTHREAD */
		tevent_threaded_schedule_immediate(tctx, state->im,
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
