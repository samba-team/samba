/*
   CTDB client code - event daemon

   Copyright (C) Amitay Isaacs  2017

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

#ifndef __CTDB_CLIENT_EVENT_H__
#define __CTDB_CLIENT_EVENT_H__

#include "client/client.h"

/* from client/client_event.c */

struct ctdb_event_context;

int ctdb_event_init(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
		    const char *sockpath, struct ctdb_event_context **out);

void ctdb_event_set_disconnect_callback(struct ctdb_event_context *eclient,
					ctdb_client_callback_func_t callback,
					void *private_data);

struct tevent_req *ctdb_event_msg_send(TALLOC_CTX *mem_ctx,
				       struct tevent_context *ev,
				       struct ctdb_event_context *eclient,
				       struct ctdb_event_request *request);

bool ctdb_event_msg_recv(struct tevent_req *req, int *perr,
			 TALLOC_CTX *mem_ctx,
			 struct ctdb_event_reply **reply);

struct tevent_req *ctdb_event_run_send(TALLOC_CTX *mem_ctx,
				       struct tevent_context *ev,
				       struct ctdb_event_context *eclient,
				       enum ctdb_event event,
				       uint32_t timeout, const char *arg_str);

bool ctdb_event_run_recv(struct tevent_req *req, int *perr, int32_t *result);

struct tevent_req *ctdb_event_status_send(TALLOC_CTX *mem_ctx,
					  struct tevent_context *ev,
					  struct ctdb_event_context *eclient,
					  enum ctdb_event event,
					  enum ctdb_event_status_state state);

bool ctdb_event_status_recv(struct tevent_req *req, int *perr,
			    int32_t *result, int *event_result,
			    TALLOC_CTX *mem_ctx,
			    struct ctdb_script_list **script_list);

struct tevent_req *ctdb_event_script_list_send(
					TALLOC_CTX *mem_ctx,
					struct tevent_context *ev,
					struct ctdb_event_context *eclient);

bool ctdb_event_script_list_recv(struct tevent_req *req, int *perr,
				 int32_t *result, TALLOC_CTX *mem_ctx,
				 struct ctdb_script_list **script_list);

struct tevent_req *ctdb_event_script_enable_send(
					TALLOC_CTX *mem_ctx,
					struct tevent_context *ev,
					struct ctdb_event_context *eclient,
					const char *script_name);

bool ctdb_event_script_enable_recv(struct tevent_req *req, int *perr,
				   int32_t *result);

struct tevent_req *ctdb_event_script_disable_send(
					TALLOC_CTX *mem_ctx,
					struct tevent_context *ev,
					struct ctdb_event_context *eclient,
					const char *script_name);

bool ctdb_event_script_disable_recv(struct tevent_req *req, int *perr,
				    int32_t *result);


#endif /* __CTDB_CLIENT_EVENT_H__ */
