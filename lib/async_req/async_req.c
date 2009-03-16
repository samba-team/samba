/*
   Unix SMB/CIFS implementation.
   Infrastructure for async requests
   Copyright (C) Volker Lendecke 2008

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
#include "lib/tevent/tevent.h"
#include "lib/talloc/talloc.h"
#include "lib/util/dlinklist.h"
#include "lib/async_req/async_req.h"

#ifndef TALLOC_FREE
#define TALLOC_FREE(ctx) do { talloc_free(ctx); ctx=NULL; } while(0)
#endif

/**
 * @brief Print an async_req structure
 * @param[in] mem_ctx	The memory context for the result
 * @param[in] req	The request to be printed
 * @retval		Text representation of req
 *
 * This is a default print function for async requests. Implementations should
 * override this with more specific information.
 *
 * This function should not be used by async API users, this is non-static
 * only to allow implementations to easily provide default information in
 * their specific functions.
 */

char *async_req_print(TALLOC_CTX *mem_ctx, struct async_req *req)
{
	return talloc_asprintf(mem_ctx, "async_req: state=%d, error=%d, "
			       "priv=%s", req->state, (int)req->error,
			       talloc_get_name(req->private_data));
}

/**
 * @brief Create an async request
 * @param[in] mem_ctx	The memory context for the result
 * @param[in] ev	The event context this async request will be driven by
 * @retval		A new async request
 *
 * The new async request will be initialized in state ASYNC_REQ_IN_PROGRESS
 */

struct async_req *async_req_new(TALLOC_CTX *mem_ctx)
{
	struct async_req *result;

	result = talloc_zero(mem_ctx, struct async_req);
	if (result == NULL) {
		return NULL;
	}
	result->state = ASYNC_REQ_IN_PROGRESS;
	result->print = async_req_print;
	return result;
}

static void async_req_finish(struct async_req *req, enum async_req_state state)
{
	req->state = state;
	if (req->async.fn != NULL) {
		req->async.fn(req);
	}
}

/**
 * @brief An async request has successfully finished
 * @param[in] req	The finished request
 *
 * async_req_done is to be used by implementors of async requests. When a
 * request is successfully finished, this function calls the user's completion
 * function.
 */

void async_req_done(struct async_req *req)
{
	async_req_finish(req, ASYNC_REQ_DONE);
}

/**
 * @brief An async request has seen an error
 * @param[in] req	The request with an error
 * @param[in] error	The error code
 *
 * async_req_done is to be used by implementors of async requests. When a
 * request can not successfully completed, the implementation should call this
 * function with the appropriate status code.
 */

void async_req_error(struct async_req *req, uint64_t error)
{
	req->error = error;
	async_req_finish(req, ASYNC_REQ_USER_ERROR);
}

/**
 * @brief Timed event callback
 * @param[in] ev	Event context
 * @param[in] te	The timed event
 * @param[in] now	zero time
 * @param[in] priv	The async request to be finished
 */

static void async_trigger(struct tevent_context *ev, struct tevent_timer *te,
			  struct timeval now, void *priv)
{
	struct async_req *req = talloc_get_type_abort(priv, struct async_req);

	TALLOC_FREE(te);
	if (req->error == 0) {
		async_req_done(req);
	}
	else {
		async_req_error(req, req->error);
	}
}

/**
 * @brief Helper function for nomem check
 * @param[in] p		The pointer to be checked
 * @param[in] req	The request being processed
 *
 * Convenience helper to easily check alloc failure within a callback
 * implementing the next step of an async request.
 *
 * Call pattern would be
 * \code
 * p = talloc(mem_ctx, bla);
 * if (async_req_ntnomem(p, req)) {
 *	return;
 * }
 * \endcode
 */

bool async_req_nomem(const void *p, struct async_req *req)
{
	if (p != NULL) {
		return false;
	}
	async_req_finish(req, ASYNC_REQ_NO_MEMORY);
	return true;
}

/**
 * @brief Finish a request before it started processing
 * @param[in] req	The finished request
 * @param[in] status	The success code
 *
 * An implementation of an async request might find that it can either finish
 * the request without waiting for an external event, or it can't even start
 * the engine. To present the illusion of a callback to the user of the API,
 * the implementation can call this helper function which triggers an
 * immediate timed event. This way the caller can use the same calling
 * conventions, independent of whether the request was actually deferred.
 */

bool async_post_error(struct async_req *req, struct tevent_context *ev,
		      uint64_t error)
{
	req->error = error;

	if (tevent_add_timer(ev, req, tevent_timeval_zero(),
			    async_trigger, req) == NULL) {
		return false;
	}
	return true;
}

bool async_req_is_error(struct async_req *req, enum async_req_state *state,
			uint64_t *error)
{
	if (req->state == ASYNC_REQ_DONE) {
		return false;
	}
	if (req->state == ASYNC_REQ_USER_ERROR) {
		*error = req->error;
	}
	*state = req->state;
	return true;
}

struct async_queue_entry {
	struct async_queue_entry *prev, *next;
	struct async_req_queue *queue;
	struct async_req *req;
	void (*trigger)(struct async_req *req);
};

struct async_req_queue {
	struct async_queue_entry *queue;
};

struct async_req_queue *async_req_queue_init(TALLOC_CTX *mem_ctx)
{
	return talloc_zero(mem_ctx, struct async_req_queue);
}

static int async_queue_entry_destructor(struct async_queue_entry *e)
{
	struct async_req_queue *queue = e->queue;

	DLIST_REMOVE(queue->queue, e);

	if (queue->queue != NULL) {
		queue->queue->trigger(queue->queue->req);
	}

	return 0;
}

static void async_req_immediate_trigger(struct tevent_context *ev,
					struct tevent_timer *te,
					struct timeval now,
					void *priv)
{
	struct async_queue_entry *e = talloc_get_type_abort(
		priv, struct async_queue_entry);

	TALLOC_FREE(te);
	e->trigger(e->req);
}

bool async_req_enqueue(struct async_req_queue *queue, struct tevent_context *ev,
		       struct async_req *req,
		       void (*trigger)(struct async_req *req))
{
	struct async_queue_entry *e;
	bool busy;

	busy = (queue->queue != NULL);

	e = talloc(req, struct async_queue_entry);
	if (e == NULL) {
		return false;
	}

	e->req = req;
	e->trigger = trigger;
	e->queue = queue;

	DLIST_ADD_END(queue->queue, e, struct async_queue_entry *);
	talloc_set_destructor(e, async_queue_entry_destructor);

	if (!busy) {
		struct tevent_timer *te;

		te = tevent_add_timer(ev, e, tevent_timeval_zero(),
				     async_req_immediate_trigger,
				     e);
		if (te == NULL) {
			TALLOC_FREE(e);
			return false;
		}
	}

	return true;
}

bool _async_req_setup(TALLOC_CTX *mem_ctx, struct async_req **preq,
		      void *pstate, size_t state_size, const char *typename)
{
	struct async_req *req;
	void **ppstate = (void **)pstate;
	void *state;

	req = async_req_new(mem_ctx);
	if (req == NULL) {
		return false;
	}
	state = talloc_size(req, state_size);
	if (state == NULL) {
		TALLOC_FREE(req);
		return false;
	}
	talloc_set_name_const(state, typename);
	req->private_data = state;

	*preq = req;
	*ppstate = state;

	return true;
}
