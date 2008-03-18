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

char *async_req_print(TALLOC_CTX *mem_ctx, struct async_req *req)
{
	return talloc_asprintf(mem_ctx, "async_req: state=%d, status=%s, "
			       "priv=%s", req->state, nt_errstr(req->status),
			       talloc_get_name(req->private_data));
}

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

void async_req_done(struct async_req *req)
{
	req->status = NT_STATUS_OK;
	req->state = ASYNC_REQ_DONE;
	if (req->async.fn != NULL) {
		req->async.fn(req);
	}
}

void async_req_error(struct async_req *req, NTSTATUS status)
{
	req->status = status;
	req->state = ASYNC_REQ_ERROR;
	if (req->async.fn != NULL) {
		req->async.fn(req);
	}
}

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

bool async_post_status(struct async_req *req, NTSTATUS status)
{
	/*
	 * Used if a request is finished before it even started
	 */

	req->status = status;

	if (event_add_timed(req->event_ctx, req, timeval_zero(),
			    "async_trigger",
			    async_trigger, req) == NULL) {
		return false;
	}
	return true;
}

bool async_req_nomem(const void *p, struct async_req *req)
{
	if (p != NULL) {
		return false;
	}
	async_req_error(req, NT_STATUS_NO_MEMORY);
	return true;
}
