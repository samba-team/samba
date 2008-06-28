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

#ifndef __ASYNC_REQ_H__
#define __ASYNC_REQ_H__

#include "includes.h"

/**
 * An async request moves between the following 4 states:
 */

enum async_req_state {
	/**
	 * we are creating the request
	 */
	ASYNC_REQ_INIT,
	/**
	 * we are waiting the request to complete
	 */
	ASYNC_REQ_IN_PROGRESS,
	/**
	 * the request is finished
	 */
	ASYNC_REQ_DONE,
	/**
	 * an error has occured
	 */
	ASYNC_REQ_ERROR
};

/**
 * @brief An async request
 *
 * This represents an async request being processed by callbacks via an event
 * context. A user can issue for example a write request to a socket, giving
 * an implementation function the fd, the buffer and the number of bytes to
 * transfer. The function issuing the request will immediately return without
 * blocking most likely without having sent anything. The API user then fills
 * in req->async.fn and req->async.priv, functions that are called when the
 * request is finished.
 *
 * It is up to the user of the async request to talloc_free it after it has
 * finished. This can happen while the completion function is called.
 */

struct async_req {
	/**
	 * @brief The external state - will be queried by the caller
	 *
	 * While the async request is being processed, state will remain in
	 * ASYNC_REQ_IN_PROGRESS. A request is finished if
	 * req->state>=ASYNC_REQ_DONE.
	 */
	enum async_req_state state;

	/**
	 * @brief Private pointer for the actual implementation
	 *
	 * The implementation doing the work for the async request needs a
	 * current state like for example a fd event. The user of an async
	 * request should not touch this.
	 */
	void *private_data;

	/**
	 * @brief Print yourself, for debugging purposes
	 *
	 * Async requests are opaque data structures. The implementation of an
	 * async request can define a custom function to print more debug
	 * info.
	 */
	char *(*print)(TALLOC_CTX *mem_ctx, struct async_req *);

	/**
	 * @brief status code when finished
	 *
	 * This status can be queried in the async completion function. It
	 * will be set to NT_STATUS_OK when everything went fine.
	 **/
	NTSTATUS status;

	/**
	 * @brief The event context we are using
	 *
	 * The event context that this async request works on.
	 */
	struct event_context *event_ctx;

	/**
	 * @brief What to do on completion
	 *
	 * This is used for the user of an async request, fn is called when
	 * the request completes, either successfully or with an error.
	 */
	struct {
		/**
		 * @brief Completion function
		 * Completion function, to be filled by the API user
		 */
		void (*fn)(struct async_req *);
		/**
		 * @brief Private data for the completion function
		 */
		void *priv;
	} async;
};

struct async_req *async_req_new(TALLOC_CTX *mem_ctx, struct event_context *ev);

char *async_req_print(TALLOC_CTX *mem_ctx, struct async_req *req);

void async_req_done(struct async_req *req);

void async_req_error(struct async_req *req, NTSTATUS status);

bool async_post_status(struct async_req *req, NTSTATUS status);

bool async_req_nomem(const void *p, struct async_req *req);

#endif
