/*
   Unix SMB/CIFS implementation.
   NTSTATUS wrappers for async_req.h
   Copyright (C) Volker Lendecke 2008, 2009

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
#include "lib/async_req/async_req_ntstatus.h"

void async_req_nterror(struct async_req *req, NTSTATUS status)
{
	async_req_error(req, NT_STATUS_V(status));
}

bool async_post_ntstatus(struct async_req *req, struct tevent_context *ev,
			 NTSTATUS status)
{
	return async_post_error(req, ev, NT_STATUS_V(status));
}

bool async_req_is_nterror(struct async_req *req, NTSTATUS *status)
{
	enum async_req_state state;
	uint64_t error;

	if (!async_req_is_error(req, &state, &error)) {
		return false;
	}
	switch (state) {
	case ASYNC_REQ_USER_ERROR:
		*status = NT_STATUS(error);
		break;
	case ASYNC_REQ_TIMED_OUT:
		*status = NT_STATUS_IO_TIMEOUT;
		break;
	case ASYNC_REQ_NO_MEMORY:
		*status = NT_STATUS_NO_MEMORY;
		break;
	default:
		*status = NT_STATUS_INTERNAL_ERROR;
		break;
	}
	return true;
}

NTSTATUS async_req_simple_recv_ntstatus(struct async_req *req)
{
	NTSTATUS status;

	if (async_req_is_nterror(req, &status)) {
		return status;
	}
	return NT_STATUS_OK;
}
