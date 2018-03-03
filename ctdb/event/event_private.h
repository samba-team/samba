/*
   CTDB event daemon

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

#ifndef __CTDB_EVENT_PRIVATE_H__
#define __CTDB_EVENT_PRIVATE_H__

#include <talloc.h>
#include <tevent.h>

#include "common/run_event.h"
#include "common/sock_daemon.h"

#include "event/event_protocol.h"

struct event_config;
struct event_context;

/* From event/event_cmd.c */

struct tevent_req *event_cmd_dispatch_send(
					TALLOC_CTX *mem_ctx,
					struct tevent_context *ev,
					struct event_context *eventd,
					struct ctdb_event_request *request);
bool event_cmd_dispatch_recv(struct tevent_req *req,
			     int *perr,
			     TALLOC_CTX *mem_ctx,
			     struct ctdb_event_reply **reply);

/* From event/event_config.c */

int event_config_init(TALLOC_CTX *mem_ctx, struct event_config **result);

const char *event_config_log_location(struct event_config *config);
const char *event_config_log_level(struct event_config *config);
const char *event_config_debug_script(struct event_config *config);

int event_config_reload(struct event_config *config);

/* From event/event_context.c */

int eventd_client_add(struct event_context *eventd,
		      struct sock_client_context *client);
void eventd_client_del(struct event_context *eventd,
		       struct sock_client_context *client);
bool eventd_client_exists(struct event_context *eventd,
			  struct sock_client_context *client);

int event_context_init(TALLOC_CTX *mem_ctx,
		       struct tevent_context *ev,
		       struct event_config *config,
		       struct event_context **result);

struct event_config *eventd_config(struct event_context *eventd);
int eventd_run_ctx(struct event_context *eventd,
		   const char *comp_name,
		   struct run_event_context **result);

int eventd_set_event_result(struct event_context *eventd,
			    const char *comp_name,
			    const char *event_name,
			    struct run_event_script_list *script_list);
int eventd_get_event_result(struct event_context *eventd,
			    const char *comp_name,
			    const char *event_name,
			    struct run_event_script_list **result);

struct ctdb_event_script_list *eventd_script_list(
				TALLOC_CTX *mem_ctx,
				struct run_event_script_list *script_list);


/* From event/event_request.c */

struct tevent_req *event_pkt_send(TALLOC_CTX *mem_ctx,
				     struct tevent_context *ev,
				     struct event_context *eventd,
				     uint8_t *buf,
				     size_t buflen);

bool event_pkt_recv(struct tevent_req *req,
		    int *perr,
		    TALLOC_CTX *mem_ctx,
		    uint8_t **buf,
		    size_t *buflen);

#endif /* __CTDB_EVENT_PRIVATE_H__ */
