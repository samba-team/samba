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
	return talloc_asprintf(mem_ctx, "async_req: state=%d, status=%s, "
			       "priv=%s", req->state, nt_errstr(req->status),
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

	result = TALLOC_ZERO_P(mem_ctx, struct async_req);
	if (result == NULL) {
		return NULL;
	}
	result->state = ASYNC_REQ_IN_PROGRESS;
	result->print = async_req_print;
	return result;
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
	req->status = NT_STATUS_OK;
	req->state = ASYNC_REQ_DONE;
	if (req->async.fn != NULL) {
		req->async.fn(req);
	}
}

/**
 * @brief An async request has seen an error
 * @param[in] req	The request with an error
 * @param[in] status	The error code
 *
 * async_req_done is to be used by implementors of async requests. When a
 * request can not successfully completed, the implementation should call this
 * function with the appropriate status code.
 */

void async_req_error(struct async_req *req, NTSTATUS status)
{
	req->status = status;
	req->state = ASYNC_REQ_ERROR;
	if (req->async.fn != NULL) {
		req->async.fn(req);
	}
}

/**
 * @brief Timed event callback
 * @param[in] ev	Event context
 * @param[in] te	The timed event
 * @param[in] now	current time
 * @param[in] priv	The async request to be finished
 */

static void async_trigger(struct event_context *ev, struct timed_event *te,
			  const struct timeval *now, void *priv)
{
	struct async_req *req = talloc_get_type_abort(priv, struct async_req);

	TALLOC_FREE(te);
	if (NT_STATUS_IS_OK(req->status)) {
		async_req_done(req);
	}
	else {
		async_req_error(req, req->status);
	}
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

bool async_post_status(struct async_req *req, struct event_context *ev,
		       NTSTATUS status)
{
	req->status = status;

	if (event_add_timed(ev, req, timeval_zero(), "async_trigger",
			    async_trigger, req) == NULL) {
		return false;
	}
	return true;
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
 * if (async_req_nomem(p, req)) {
 *	return;
 * }
 * \endcode
 */

bool async_req_nomem(const void *p, struct async_req *req)
{
	if (p != NULL) {
		return false;
	}
	async_req_error(req, NT_STATUS_NO_MEMORY);
	return true;
}

bool async_req_is_error(struct async_req *req, NTSTATUS *status)
{
	if (req->state < ASYNC_REQ_DONE) {
		*status = NT_STATUS_INTERNAL_ERROR;
		return true;
	}
	if (req->state == ASYNC_REQ_ERROR) {
		*status = req->status;
		return true;
	}
	return false;
}

NTSTATUS async_req_simple_recv(struct async_req *req)
{
	NTSTATUS status;

	if (async_req_is_error(req, &status)) {
		return status;
	}
	return NT_STATUS_OK;
}

static void async_req_timedout(struct event_context *ev,
			       struct timed_event *te,
			       const struct timeval *now,
			       void *priv)
{
	struct async_req *req = talloc_get_type_abort(
		priv, struct async_req);
	TALLOC_FREE(te);
	async_req_error(req, NT_STATUS_IO_TIMEOUT);
}

bool async_req_set_timeout(struct async_req *req, struct event_context *ev,
			   struct timeval to)
{
	return (event_add_timed(ev, req,
				timeval_current_ofs(to.tv_sec, to.tv_usec),
				"async_req_timedout", async_req_timedout, req)
		!= NULL);
}

struct async_req *async_wait_send(TALLOC_CTX *mem_ctx,
				  struct event_context *ev,
				  struct timeval to)
{
	struct async_req *result;

	result = async_req_new(mem_ctx);
	if (result == NULL) {
		return result;
	}
	if (!async_req_set_timeout(result, ev, to)) {
		TALLOC_FREE(result);
		return NULL;
	}
	return result;
}

NTSTATUS async_wait_recv(struct async_req *req)
{
	return NT_STATUS_OK;
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
	return TALLOC_ZERO_P(mem_ctx, struct async_req_queue);
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

static void async_req_immediate_trigger(struct event_context *ev,
					struct timed_event *te,
					const struct timeval *now,
					void *priv)
{
	struct async_queue_entry *e = talloc_get_type_abort(
		priv, struct async_queue_entry);

	TALLOC_FREE(te);
	e->trigger(e->req);
}

bool async_req_enqueue(struct async_req_queue *queue, struct event_context *ev,
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
		struct timed_event *te;

		te = event_add_timed(ev, e, timeval_zero(),
				     "async_req_immediate_trigger",
				     async_req_immediate_trigger,
				     e);
		if (te == NULL) {
			TALLOC_FREE(e);
			return false;
		}
	}

	return true;
}
