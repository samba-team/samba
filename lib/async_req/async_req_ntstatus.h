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

#ifndef __ASYNC_REQ_NTSTATUS_H__
#define __ASYNC_REQ_NTSTATUS_H__

#include "lib/async_req/async_req.h"
#include "includes.h"

void async_req_nterror(struct async_req *req, NTSTATUS status);

bool async_post_ntstatus(struct async_req *req, struct tevent_context *ev,
			 NTSTATUS status);

bool async_req_is_nterror(struct async_req *req, NTSTATUS *status);

NTSTATUS async_req_simple_recv_ntstatus(struct async_req *req);

#endif
