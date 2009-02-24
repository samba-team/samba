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

struct async_req *async_req_new(TALLOC_CTX *mem_ctx, struct event_context *ev)
{
	struct async_req *result;

	result = TALLOC_ZERO_P(mem_ctx, struct async_req);
	if (result == NULL) {
		return NULL;
	}
	result->state = ASYNC_REQ_IN_PROGRESS;
	result->event_ctx = ev;
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
 * @param[in] now	zero time
 * @param[in] priv	The async request to be finished
 */

static void async_trigger(struct event_context *ev, struct timed_event *te,
			  struct timeval now, void *priv)
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

bool async_post_status(struct async_req *req, NTSTATUS status)
{
	req->status = status;

	if (event_add_timed(req->event_ctx, req, timeval_zero(),
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
