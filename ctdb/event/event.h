/*
   CTDB event daemon client

   Copyright (C) Amitay Isaacs  2018

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, see <http://www.gnu.org/licenses/>.
*/

#ifndef __CTDB_EVENT_H__
#define __CTDB_EVENT_H__

#include "event/event_protocol.h"

struct ctdb_event_context;

int ctdb_event_init(TALLOC_CTX *mem_ctx,
		    struct tevent_context *ev,
		    struct ctdb_event_context **result);

struct tevent_req *ctdb_event_run_send(TALLOC_CTX *mem_ctx,
				       struct tevent_context *ev,
				       struct ctdb_event_context *eclient,
				       struct ctdb_event_request_run *run);
bool ctdb_event_run_recv(struct tevent_req *req, int *perr, int *result);

struct tevent_req *ctdb_event_status_send(
				TALLOC_CTX *mem_ctx,
				struct tevent_context *ev,
				struct ctdb_event_context *eclient,
				struct ctdb_event_request_status *status);
bool ctdb_event_status_recv(struct tevent_req *req,
			    int *perr,
			    int *result,
			    TALLOC_CTX *mem_ctx,
			    struct ctdb_event_reply_status **status);

struct tevent_req *ctdb_event_script_send(
				TALLOC_CTX *mem_ctx,
				struct tevent_context *ev,
				struct ctdb_event_context *eclient,
				struct ctdb_event_request_script *script);
bool ctdb_event_script_recv(struct tevent_req *req, int *perr, int *result);

#endif /* __CTDB_EVENT_H__ */
