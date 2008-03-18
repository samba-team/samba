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

/*
 * An async request moves between the following 4 states.
 */
enum async_req_state {
	ASYNC_REQ_INIT,		/* we are creating the request */
	ASYNC_REQ_IN_PROGRESS,	/* we are waiting the request to complete */
	ASYNC_REQ_DONE,		/* the request is finished */
	ASYNC_REQ_ERROR };	/* an error has occured */

struct async_req {
	/* the external state - will be queried by the caller */
	enum async_req_state state;

	/* a private pointer for use by the async function implementation */
	void *private_data;

	/* print yourself, for debugging purposes */
	char *(*print)(TALLOC_CTX *mem_ctx, struct async_req *);

	/* status code when finished */
	NTSTATUS status;

	/* the event context we are using */
	struct event_context *event_ctx;

	/* information on what to do on completion */
	struct {
		void (*fn)(struct async_req *);
		void *priv;
	} async;
};

/*
 * Print an async_req structure for debugging purposes
 */
char *async_req_print(TALLOC_CTX *mem_ctx, struct async_req *req);

/*
 * Create an async request
 */
struct async_req *async_req_new(TALLOC_CTX *mem_ctx, struct event_context *ev);

/*
 * An async request has successfully finished, invoke the callback
 */
void async_req_done(struct async_req *req);

/*
 * An async request has seen an error, invoke the callback
 */
void async_req_error(struct async_req *req, NTSTATUS status);

/*
 * If a request is finished or ends in error even before it has the chance to
 * trigger the event loop, post a status. This creates an immediate timed
 * event to call the async function if there is any.
 */
bool async_post_status(struct async_req *req, NTSTATUS status);

/*
 * Convenience helper to easily check alloc failure within a callback.
 *
 * Call pattern would be
 * p = talloc(mem_ctx, bla);
 * if (async_req_nomem(p, req)) {
 *	return;
 * }
 *
 */
bool async_req_nomem(const void *p, struct async_req *req);

#endif
