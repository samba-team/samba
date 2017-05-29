/*
   Event script running daemon

   Copyright (C) Amitay Isaacs  2016

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

#include "replace.h"
#include "system/filesys.h"
#include "system/dir.h"
#include "system/wait.h"
#include "system/locale.h"

#include <popt.h>
#include <talloc.h>
#include <tevent.h>

#include "lib/util/debug.h"
#include "lib/util/tevent_unix.h"
#include "lib/util/blocking.h"
#include "lib/util/sys_rw.h"
#include "lib/util/dlinklist.h"
#include "lib/async_req/async_sock.h"

#include "protocol/protocol_api.h"

#include "common/comm.h"
#include "common/logging.h"
#include "common/run_event.h"
#include "common/sock_daemon.h"

struct pending_event {
	struct pending_event *prev, *next;

	struct tevent_req *req;
};

struct eventd_client {
	struct eventd_client *prev, *next;

	struct sock_client_context *client_ctx;
	struct pending_event *pending_list;
};

struct eventd_context {
	struct run_event_context *run_ctx;
	struct tevent_queue *queue;

	/* current state */
	bool running;
	enum ctdb_event event;
	struct tevent_req *req;

	/* result of last execution */
	struct run_event_script_list *status_run[CTDB_EVENT_MAX];
	struct run_event_script_list *status_pass[CTDB_EVENT_MAX];
	struct run_event_script_list *status_fail[CTDB_EVENT_MAX];

	struct eventd_client *client_list;
};

/*
 * Global state manipulation functions
 */

static int eventd_context_init(TALLOC_CTX *mem_ctx,
			       struct tevent_context *ev,
			       const char *script_dir,
			       const char *debug_script,
			       struct eventd_context **result)
{
	struct eventd_context *ectx;
	int ret;

	ectx = talloc_zero(mem_ctx, struct eventd_context);
	if (ectx == NULL) {
		return ENOMEM;
	}

	ret = run_event_init(ectx, ev, script_dir, debug_script,
			     &ectx->run_ctx);
	if (ret != 0) {
		talloc_free(ectx);
		return ret;
	}

	ectx->queue = tevent_queue_create(ectx, "run event queue");
	if (ectx->queue == NULL) {
		talloc_free(ectx);
		return ENOMEM;
	}

	ectx->running = false;
	ectx->event = CTDB_EVENT_INIT;

	*result = ectx;
	return 0;
}

static struct run_event_context *eventd_run_context(struct eventd_context *ectx)
{
	return ectx->run_ctx;
}

static struct tevent_queue *eventd_queue(struct eventd_context *ectx)
{
	return ectx->queue;
}

static void eventd_start_running(struct eventd_context *ectx,
				 enum ctdb_event event,
				 struct tevent_req *req)
{
	ectx->running = true;
	ectx->event = event;
	ectx->req = req;
}

static void eventd_stop_running(struct eventd_context *ectx)
{
	ectx->running = false;
	ectx->req = NULL;
}

static struct tevent_req *eventd_cancel_running(struct eventd_context *ectx)
{
	struct tevent_req *req = ectx->req;

	ectx->req = NULL;
	eventd_stop_running(ectx);

	return req;
}

static bool eventd_is_running(struct eventd_context *ectx,
			      enum ctdb_event *event)
{
	if (event != NULL && ectx->running) {
		*event = ectx->event;
	}

	return ectx->running;
}

static struct run_event_script_list *script_list_copy(
					TALLOC_CTX *mem_ctx,
					struct run_event_script_list *s)
{
	struct run_event_script_list *s2;

	s2 = talloc_zero(mem_ctx, struct run_event_script_list);
	if (s2 == NULL) {
		return NULL;
	}

	s2->num_scripts = s->num_scripts;
	s2->script = talloc_memdup(s2, s->script,
				   s->num_scripts *
				   sizeof(struct run_event_script));
	if (s2->script == NULL) {
		talloc_free(s2);
		return NULL;
	}
	s2->summary = s->summary;

	return s2;
}

static struct ctdb_script_list *script_list_to_ctdb_script_list(
					TALLOC_CTX *mem_ctx,
					struct run_event_script_list *s)
{
	struct ctdb_script_list *sl;
	int i;

	sl = talloc_zero(mem_ctx, struct ctdb_script_list);
	if (sl == NULL) {
		return NULL;
	}

	sl->script = talloc_zero_array(sl, struct ctdb_script, s->num_scripts);
	if (sl->script == NULL) {
		talloc_free(sl);
		return NULL;
	}

	sl->num_scripts = s->num_scripts;

	for (i=0; i<s->num_scripts; i++) {
		struct run_event_script *escript = &s->script[i];
		struct ctdb_script *script = &sl->script[i];

		strlcpy(script->name, escript->name, MAX_SCRIPT_NAME+1);
		script->start = escript->begin;
		script->finished = escript->end;
		script->status = escript->summary;
		if (escript->output != NULL) {
			strlcpy(script->output, escript->output,
				MAX_SCRIPT_OUTPUT+1);
		}
	}

	return sl;
}

static void eventd_set_result(struct eventd_context *ectx,
			      enum ctdb_event event,
			      struct run_event_script_list *script_list)
{
	struct run_event_script_list *s;

	if (script_list == NULL) {
		return;
	}

	TALLOC_FREE(ectx->status_run[event]);
	ectx->status_run[event] = talloc_steal(ectx, script_list);

	s = script_list_copy(ectx, script_list);
	if (s == NULL) {
		return;
	}

	if (s->summary == 0) {
		TALLOC_FREE(ectx->status_pass[event]);
		ectx->status_pass[event] = s;
	} else {
		TALLOC_FREE(ectx->status_fail[event]);
		ectx->status_fail[event] = s;
	}
}

static int eventd_get_result(struct eventd_context *ectx,
			     enum ctdb_event event,
			     enum ctdb_event_status_state state,
			     TALLOC_CTX *mem_ctx,
			     struct ctdb_script_list **out)
{
	struct run_event_script_list *s = NULL;

	switch (state) {
		case CTDB_EVENT_LAST_RUN:
			s = ectx->status_run[event];
			break;

		case CTDB_EVENT_LAST_PASS:
			s = ectx->status_pass[event];
			break;

		case CTDB_EVENT_LAST_FAIL:
			s = ectx->status_fail[event];
			break;
	}

	if (s == NULL) {
		*out = NULL;
		return 0;
	}

	*out = script_list_to_ctdb_script_list(mem_ctx, s);
	return s->summary;
}

/*
 * Process RUN command
 */

struct command_run_state {
	struct tevent_context *ev;
	struct eventd_context *ectx;
	struct eventd_client *client;

	enum ctdb_event event;
	uint32_t timeout;
	const char *arg_str;
	struct ctdb_event_reply *reply;
	struct tevent_req *subreq;
};

static void command_run_trigger(struct tevent_req *req, void *private_data);
static void command_run_done(struct tevent_req *subreq);
static void command_run_cancel(struct tevent_req *req);

static struct tevent_req *command_run_send(TALLOC_CTX *mem_ctx,
					   struct tevent_context *ev,
					   struct eventd_context *ectx,
					   struct eventd_client *client,
					   struct ctdb_event_request *request)
{
	struct tevent_req *req, *mon_req;
	struct command_run_state *state;
	struct pending_event *pending;
	enum ctdb_event running_event;
	bool running, status;

	req = tevent_req_create(mem_ctx, &state, struct command_run_state);
	if (req == NULL) {
		return NULL;
	}

	state->ev = ev;
	state->ectx = ectx;
	state->client = client;

	state->event = request->rdata.data.run->event;
	state->timeout = request->rdata.data.run->timeout;
	state->arg_str = talloc_steal(state, request->rdata.data.run->arg_str);

	state->reply = talloc_zero(state, struct ctdb_event_reply);
	if (tevent_req_nomem(state->reply, req)) {
		return tevent_req_post(req, ev);
	}

	state->reply->rdata.command = request->rdata.command;

	/*
	 * If monitor event is running,
	 *   Cancel the running monitor event and run new event
	 *
	 * If any other event is running,
	 *   If new event is monitor, cancel that event
	 *   Else add new event to the queue
	 */

	running = eventd_is_running(ectx, &running_event);
	if (running) {
		if (running_event == CTDB_EVENT_MONITOR) {
			mon_req = eventd_cancel_running(ectx);
			command_run_cancel(mon_req);
		} else if (state->event == CTDB_EVENT_MONITOR) {
			state->reply->rdata.result = -ECANCELED;
			tevent_req_done(req);
			return tevent_req_post(req, ev);
		}
	}

	pending = talloc_zero(state, struct pending_event);
	if (tevent_req_nomem(pending, req)) {
		return tevent_req_post(req, ev);
	}

	pending->req = req;
	DLIST_ADD(client->pending_list, pending);

	status = tevent_queue_add(eventd_queue(ectx), ev, req,
				  command_run_trigger, pending);
	if (! status) {
		tevent_req_error(req, ENOMEM);
		return tevent_req_post(req, ev);
	}

	return req;
}

static void command_run_trigger(struct tevent_req *req, void *private_data)
{
	struct pending_event *pending = talloc_get_type_abort(
		private_data, struct pending_event);
	struct command_run_state *state = tevent_req_data(
		req, struct command_run_state);

	DLIST_REMOVE(state->client->pending_list, pending);

	if (pending->req != req) {
		tevent_req_error(req, EIO);
		return;
	}

	talloc_free(pending);

	D_DEBUG("Running event %s with args \"%s\"\n",
		ctdb_event_to_string(state->event),
		state->arg_str == NULL ? "(null)" : state->arg_str);

	state->subreq = run_event_send(state, state->ev,
				       eventd_run_context(state->ectx),
				       ctdb_event_to_string(state->event),
				       state->arg_str,
				       tevent_timeval_current_ofs(
					       state->timeout, 0));
	if (tevent_req_nomem(state->subreq, req)) {
		return;
	}
	tevent_req_set_callback(state->subreq, command_run_done, req);

	eventd_start_running(state->ectx, state->event, req);
}

static void command_run_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct command_run_state *state = tevent_req_data(
		req, struct command_run_state);
	struct run_event_script_list *script_list;
	int ret;
	bool status;

	eventd_stop_running(state->ectx);

	status = run_event_recv(subreq, &ret, state, &script_list);
	TALLOC_FREE(subreq);
	if (! status) {
		tevent_req_error(req, ret);
		return;
	}

	if (script_list == NULL) {
		eventd_set_result(state->ectx, state->event, NULL);
		state->reply->rdata.result = 0;
	} else {
		eventd_set_result(state->ectx, state->event, script_list);
		state->reply->rdata.result = script_list->summary;
	}

	tevent_req_done(req);
}

static void command_run_cancel(struct tevent_req *req)
{
	struct command_run_state *state = tevent_req_data(
		req, struct command_run_state);

	eventd_stop_running(state->ectx);

	TALLOC_FREE(state->subreq);

	state->reply->rdata.result = -ECANCELED;

	tevent_req_done(req);
}

static bool command_run_recv(struct tevent_req *req, int *perr,
			     TALLOC_CTX *mem_ctx,
			     struct ctdb_event_reply **reply)
{
	struct command_run_state *state = tevent_req_data(
		req, struct command_run_state);
	int ret;

	if (tevent_req_is_unix_error(req, &ret)) {
		if (perr != NULL) {
			*perr = ret;
		}
		return false;
	}

	if (reply != NULL) {
		*reply = talloc_steal(mem_ctx, state->reply);
	}
	return true;
}

/*
 * Process STATUS command
 */

struct command_status_state {
	struct ctdb_event_reply *reply;
};

static struct tevent_req *command_status_send(
					TALLOC_CTX *mem_ctx,
					struct tevent_context *ev,
					struct eventd_context *ectx,
					struct eventd_client *client,
					struct ctdb_event_request *request)
{
	struct tevent_req *req;
	struct command_status_state *state;
	enum ctdb_event event;
	enum ctdb_event_status_state estate;

	req = tevent_req_create(mem_ctx, &state, struct command_status_state);
	if (req == NULL) {
		return NULL;
	}

	event = request->rdata.data.status->event;
	estate = request->rdata.data.status->state;

	state->reply = talloc_zero(state, struct ctdb_event_reply);
	if (tevent_req_nomem(state->reply, req)) {
		return tevent_req_post(req, ev);
	}

	state->reply->rdata.data.status =
		talloc(state->reply, struct ctdb_event_reply_status);
	if (tevent_req_nomem(state->reply->rdata.data.status, req)) {
		return tevent_req_post(req, ev);
	}

	state->reply->rdata.command = request->rdata.command;
	state->reply->rdata.result = 0;
	state->reply->rdata.data.status->status =
		eventd_get_result(ectx, event, estate, state->reply,
				&state->reply->rdata.data.status->script_list);

	tevent_req_done(req);
	return tevent_req_post(req, ev);
}

static bool command_status_recv(struct tevent_req *req, int *perr,
				TALLOC_CTX *mem_ctx,
				struct ctdb_event_reply **reply)
{
	struct command_status_state *state = tevent_req_data(
		req, struct command_status_state);
	int ret;

	if (tevent_req_is_unix_error(req, &ret)) {
		if (perr != NULL) {
			*perr = ret;
		}
		return false;
	}

	if (reply != NULL) {
		*reply = talloc_steal(mem_ctx, state->reply);
	}
	return true;
}

/*
 * Process SCRIPT_LIST command
 */

struct command_script_list_state {
	struct ctdb_event_reply *reply;
};

static struct tevent_req *command_script_list_send(
					TALLOC_CTX *mem_ctx,
					struct tevent_context *ev,
					struct eventd_context *ectx,
					struct eventd_client *client,
					struct ctdb_event_request *request)
{
	struct tevent_req *req;
	struct command_script_list_state *state;
	struct run_event_script_list *s;
	int ret;

	req = tevent_req_create(mem_ctx, &state,
				struct command_script_list_state);
	if (req == NULL) {
		return NULL;
	}

	state->reply = talloc_zero(state, struct ctdb_event_reply);
	if (tevent_req_nomem(state->reply, req)) {
		return tevent_req_post(req, ev);
	}

	state->reply->rdata.data.script_list =
		talloc(state->reply, struct ctdb_event_reply_script_list);
	if (tevent_req_nomem(state->reply->rdata.data.script_list, req)) {
		return tevent_req_post(req, ev);
	}

	ret = run_event_script_list(eventd_run_context(ectx), state->reply,
				    &s);
	if (ret != 0) {
		tevent_req_error(req, ret);
		return tevent_req_post(req, ev);
	}

	state->reply->rdata.command = request->rdata.command;
	if (s == NULL) {
		state->reply->rdata.result = 0;
		state->reply->rdata.data.script_list->script_list = NULL;
	} else {
		state->reply->rdata.result = s->summary;
		state->reply->rdata.data.script_list->script_list =
			script_list_to_ctdb_script_list(state->reply, s);
	}

	tevent_req_done(req);
	return tevent_req_post(req, ev);
}

static bool command_script_list_recv(struct tevent_req *req, int *perr,
				     TALLOC_CTX *mem_ctx,
				     struct ctdb_event_reply **reply)
{
	struct command_script_list_state *state = tevent_req_data(
		req, struct command_script_list_state);
	int ret;

	if (tevent_req_is_unix_error(req, &ret)) {
		if (perr != NULL) {
			*perr = ret;
		}
		return false;
	}

	if (reply != NULL) {
		*reply = talloc_steal(mem_ctx, state->reply);
	}
	return true;
}

/*
 * Process SCRIPT_ENABLE command
 */

struct command_script_enable_state {
	struct ctdb_event_reply *reply;
};

static struct tevent_req *command_script_enable_send(
					TALLOC_CTX *mem_ctx,
					struct tevent_context *ev,
					struct eventd_context *ectx,
					struct eventd_client *client,
					struct ctdb_event_request *request)
{
	struct tevent_req *req;
	struct command_script_enable_state *state;
	const char *script_name;
	int ret;

	req = tevent_req_create(mem_ctx, &state,
				struct command_script_enable_state);
	if (req == NULL) {
		return NULL;
	}

	script_name = request->rdata.data.script_enable->script_name;

	state->reply = talloc_zero(state, struct ctdb_event_reply);
	if (tevent_req_nomem(state->reply, req)) {
		return tevent_req_post(req, ev);
	}

	state->reply->rdata.command = request->rdata.command;

	ret = run_event_script_enable(eventd_run_context(ectx), script_name);
	state->reply->rdata.result = -ret;

	tevent_req_done(req);
	return tevent_req_post(req, ev);
}

static bool command_script_enable_recv(struct tevent_req *req, int *perr,
				       TALLOC_CTX *mem_ctx,
				       struct ctdb_event_reply **reply)
{
	struct command_script_enable_state *state = tevent_req_data(
		req, struct command_script_enable_state);
	int ret;

	if (tevent_req_is_unix_error(req, &ret)) {
		if (perr != NULL) {
			*perr = ret;
		}
		return false;
	}

	if (reply != NULL) {
		*reply = talloc_steal(mem_ctx, state->reply);
	}
	return true;
}

/*
 * Process SCRIPT_DISABLE command
 */

struct command_script_disable_state {
	struct ctdb_event_reply *reply;
};

static struct tevent_req *command_script_disable_send(
					TALLOC_CTX *mem_ctx,
					struct tevent_context *ev,
					struct eventd_context *ectx,
					struct eventd_client *client,
					struct ctdb_event_request *request)
{
	struct tevent_req *req;
	struct command_script_disable_state *state;
	const char *script_name;
	int ret;

	req = tevent_req_create(mem_ctx, &state,
				struct command_script_disable_state);
	if (req == NULL) {
		return NULL;
	}

	script_name = request->rdata.data.script_disable->script_name;

	state->reply = talloc_zero(state, struct ctdb_event_reply);
	if (tevent_req_nomem(state->reply, req)) {
		return tevent_req_post(req, ev);
	}

	state->reply->rdata.command = request->rdata.command;

	ret = run_event_script_disable(eventd_run_context(ectx), script_name);
	state->reply->rdata.result = -ret;

	tevent_req_done(req);
	return tevent_req_post(req, ev);
}

static bool command_script_disable_recv(struct tevent_req *req, int *perr,
					TALLOC_CTX *mem_ctx,
					struct ctdb_event_reply **reply)
{
	struct command_script_disable_state *state = tevent_req_data(
		req, struct command_script_disable_state);
	int ret;

	if (tevent_req_is_unix_error(req, &ret)) {
		if (perr != NULL) {
			*perr = ret;
		}
		return false;
	}

	if (reply != NULL) {
		*reply = talloc_steal(mem_ctx, state->reply);
	}
	return true;
}

/*
 * Process clients
 */

static struct eventd_client *client_find(struct eventd_context *ectx,
					 struct sock_client_context *client_ctx)
{
	struct eventd_client *client;

	for (client = ectx->client_list;
	     client != NULL;
	     client = client->next) {
		if (client->client_ctx == client_ctx) {
			return client;
		}
	}

	return NULL;
}

static bool client_connect(struct sock_client_context *client_ctx,
			   void *private_data)
{
	struct eventd_context *ectx = talloc_get_type_abort(
		private_data, struct eventd_context);
	struct eventd_client *client;

	client = talloc_zero(ectx, struct eventd_client);
	if (client == NULL) {
		return false;
	}

	client->client_ctx = client_ctx;

	DLIST_ADD(ectx->client_list, client);
	return true;
}

static void client_disconnect(struct sock_client_context *client_ctx,
			      void *private_data)
{
	struct eventd_context *ectx = talloc_get_type_abort(
		private_data, struct eventd_context);
	struct eventd_client *client;
	struct pending_event *pe;

	client = client_find(ectx, client_ctx);
	if (client == NULL) {
		return;
	}

	/* Get rid of pending events */
	while ((pe = client->pending_list) != NULL) {
		DLIST_REMOVE(client->pending_list, pe);
		talloc_free(pe->req);
	}
}

struct client_process_state {
	struct tevent_context *ev;

	struct eventd_client *client;
	struct ctdb_event_request request;
};

static void client_run_done(struct tevent_req *subreq);
static void client_status_done(struct tevent_req *subreq);
static void client_script_list_done(struct tevent_req *subreq);
static void client_script_enable_done(struct tevent_req *subreq);
static void client_script_disable_done(struct tevent_req *subreq);
static void client_process_reply(struct tevent_req *req,
				 struct ctdb_event_reply *reply);
static void client_process_reply_done(struct tevent_req *subreq);

static struct tevent_req *client_process_send(
				TALLOC_CTX *mem_ctx,
				struct tevent_context *ev,
				struct sock_client_context *client_ctx,
				uint8_t *buf, size_t buflen,
				void *private_data)
{
	struct eventd_context *ectx = talloc_get_type_abort(
		private_data, struct eventd_context);
	struct tevent_req *req, *subreq;
	struct client_process_state *state;
	int ret;

	req = tevent_req_create(mem_ctx, &state, struct client_process_state);
	if (req == NULL) {
		return NULL;
	}

	state->ev = ev;

	state->client = client_find(ectx, client_ctx);
	if (state->client == NULL) {
		tevent_req_error(req, EIO);
		return tevent_req_post(req, ev);
	}

	ret = ctdb_event_request_pull(buf, buflen, state, &state->request);
	if (ret != 0) {
		tevent_req_error(req, EPROTO);
		return tevent_req_post(req, ev);
	}

	switch (state->request.rdata.command) {
	case CTDB_EVENT_COMMAND_RUN:
		subreq = command_run_send(state, ev, ectx, state->client,
					  &state->request);
		if (tevent_req_nomem(subreq, req)) {
			return tevent_req_post(req, ev);
		}
		tevent_req_set_callback(subreq, client_run_done, req);
		break;

	case CTDB_EVENT_COMMAND_STATUS:
		subreq = command_status_send(state, ev, ectx, state->client,
					     &state->request);
		if (tevent_req_nomem(subreq, req)) {
			return tevent_req_post(req, ev);
		}
		tevent_req_set_callback(subreq, client_status_done, req);
		break;

	case CTDB_EVENT_COMMAND_SCRIPT_LIST:
		subreq = command_script_list_send(state, ev, ectx,
						  state->client,
						  &state->request);
		if (tevent_req_nomem(subreq, req)) {
			return tevent_req_post(req, ev);
		}
		tevent_req_set_callback(subreq, client_script_list_done, req);
		break;

	case CTDB_EVENT_COMMAND_SCRIPT_ENABLE:
		subreq = command_script_enable_send(state, ev, ectx,
						    state->client,
						    &state->request);
		if (tevent_req_nomem(subreq, req)) {
			return tevent_req_post(req, ev);
		}
		tevent_req_set_callback(subreq, client_script_enable_done,
					req);
		break;

	case CTDB_EVENT_COMMAND_SCRIPT_DISABLE:
		subreq = command_script_disable_send(state, ev, ectx,
						     state->client,
						     &state->request);
		if (tevent_req_nomem(subreq, req)) {
			return tevent_req_post(req, ev);
		}
		tevent_req_set_callback(subreq, client_script_disable_done,
					req);
		break;
	}

	return req;
}

static void client_run_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct client_process_state *state = tevent_req_data(
		req, struct client_process_state);
	struct ctdb_event_reply *reply = NULL;
	int ret = 0;
	bool status;

	status = command_run_recv(subreq, &ret, state, &reply);
	TALLOC_FREE(subreq);
	if (! status) {
		D_ERR("COMMAND_RUN failed\n");
		tevent_req_error(req, ret);
		return;
	}

	client_process_reply(req, reply);
	talloc_free(reply);
}

static void client_status_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct client_process_state *state = tevent_req_data(
		req, struct client_process_state);
	struct ctdb_event_reply *reply = NULL;
	int ret = 0;
	bool status;

	status = command_status_recv(subreq, &ret, state, &reply);
	TALLOC_FREE(subreq);
	if (! status) {
		D_ERR("COMMAND_STATUS failed\n");
		tevent_req_error(req, ret);
		return;
	}

	client_process_reply(req, reply);
	talloc_free(reply);
}

static void client_script_list_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct client_process_state *state = tevent_req_data(
		req, struct client_process_state);
	struct ctdb_event_reply *reply = NULL;
	int ret = 0;
	bool status;

	status = command_script_list_recv(subreq, &ret, state, &reply);
	TALLOC_FREE(subreq);
	if (! status) {
		D_ERR("COMMAND_SCRIPT_LIST failed\n");
		tevent_req_error(req, ret);
		return;
	}

	client_process_reply(req, reply);
	talloc_free(reply);
}

static void client_script_enable_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct client_process_state *state = tevent_req_data(
		req, struct client_process_state);
	struct ctdb_event_reply *reply = NULL;
	int ret = 0;
	bool status;

	status = command_script_enable_recv(subreq, &ret, state, &reply);
	TALLOC_FREE(subreq);
	if (! status) {
		D_ERR("COMMAND_SCRIPT_ENABLE failed\n");
		tevent_req_error(req, ret);
		return;
	}

	client_process_reply(req, reply);
	talloc_free(reply);
}

static void client_script_disable_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct client_process_state *state = tevent_req_data(
		req, struct client_process_state);
	struct ctdb_event_reply *reply = NULL;
	int ret = 0;
	bool status;

	status = command_script_disable_recv(subreq, &ret, state, &reply);
	TALLOC_FREE(subreq);
	if (! status) {
		D_ERR("COMMAND_SCRIPT_DISABLE failed\n");
		tevent_req_error(req, ret);
		return;
	}

	client_process_reply(req, reply);
	talloc_free(reply);
}

static void client_process_reply(struct tevent_req *req,
				 struct ctdb_event_reply *reply)
{
	struct client_process_state *state = tevent_req_data(
		req, struct client_process_state);
	struct tevent_req *subreq;
	uint8_t *buf;
	size_t buflen;
	int ret;

	ctdb_event_header_fill(&reply->header, state->request.header.reqid);

	buflen = ctdb_event_reply_len(reply);
	buf = talloc_zero_size(state, buflen);
	if (tevent_req_nomem(buf, req)) {
		return;
	}

	ret = ctdb_event_reply_push(reply, buf, &buflen);
	if (ret != 0) {
		talloc_free(buf);
		tevent_req_error(req, ret);
		return;
	}

	subreq = sock_socket_write_send(state, state->ev,
					state->client->client_ctx,
					buf, buflen);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, client_process_reply_done, req);
}

static void client_process_reply_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	int ret;
	bool status;

	status = sock_socket_write_recv(subreq, &ret);
	TALLOC_FREE(subreq);
	if (! status) {
		D_ERR("Sending reply failed\n");
		tevent_req_error(req, ret);
		return;
	}

	tevent_req_done(req);
}

static bool client_process_recv(struct tevent_req *req, int *perr)
{
	int ret;

	if (tevent_req_is_unix_error(req, &ret)) {
		if (perr != NULL) {
			*perr = ret;
		}
		return false;
	}

	return true;
}

/*
 * Event daemon
 */

static void eventd_shutdown(void *private_data)
{
	struct eventd_context *ectx = talloc_get_type_abort(
		private_data, struct eventd_context);
	struct eventd_client *client;

	while ((client = ectx->client_list) != NULL) {
		DLIST_REMOVE(ectx->client_list, client);
		talloc_free(client);
	}
}

static struct {
	const char *debug_script;
	const char *script_dir;
	const char *logging;
	const char *debug_level;
	const char *pidfile;
	const char *socket;
	int pid;
} options = {
	.debug_level = "ERR",
};

struct poptOption cmdline_options[] = {
	POPT_AUTOHELP
	{ "debug_script", 'D', POPT_ARG_STRING, &options.debug_script, 0,
		"debug script", "FILE" },
	{ "pid", 'P', POPT_ARG_INT, &options.pid, 0,
		"pid to wait for", "PID" },
	{ "event_script_dir", 'e', POPT_ARG_STRING, &options.script_dir, 0,
		"event script dir", "DIRECTORY" },
	{ "logging", 'l', POPT_ARG_STRING, &options.logging, 0,
		"logging specification" },
	{ "debug", 'd', POPT_ARG_STRING, &options.debug_level, 0,
		"debug level" },
	{ "pidfile", 'p', POPT_ARG_STRING, &options.pidfile, 0,
		"eventd pid file", "FILE" },
	{ "socket", 's', POPT_ARG_STRING, &options.socket, 0,
		"eventd socket path", "FILE" },
	POPT_TABLEEND
};

int main(int argc, const char **argv)
{
	poptContext pc;
	TALLOC_CTX *mem_ctx;
	struct tevent_context *ev;
	struct eventd_context *ectx;
	struct sock_daemon_context *sockd;
	struct sock_daemon_funcs daemon_funcs;
	struct sock_socket_funcs socket_funcs;
	struct stat statbuf;
	int opt, ret;

	/* Set default options */
	options.pid = -1;

	pc = poptGetContext(argv[0], argc, argv, cmdline_options,
			    POPT_CONTEXT_KEEP_FIRST);
	while ((opt = poptGetNextOpt(pc)) != -1) {
		fprintf(stderr, "Invalid options %s: %s\n",
			poptBadOption(pc, 0), poptStrerror(opt));
		exit(1);
	}

	if (options.socket == NULL) {
		fprintf(stderr, "Please specify eventd socket (--socket)\n");
		exit(1);
	}

	if (options.script_dir == NULL) {
		fprintf(stderr,
			"Please specify script dir (--event_script_dir)\n");
		exit(1);
	}

	if (options.logging == NULL) {
		fprintf(stderr,
			"Please specify logging (--logging)\n");
		exit(1);
	}

	ret = stat(options.script_dir, &statbuf);
	if (ret != 0) {
		ret = errno;
		fprintf(stderr, "Error reading script_dir %s, ret=%d\n",
			options.script_dir, ret);
		exit(1);
	}
	if (! S_ISDIR(statbuf.st_mode)) {
		fprintf(stderr, "script_dir %s is not a directory\n",
			options.script_dir);
		exit(1);
	}

	mem_ctx = talloc_new(NULL);
	if (mem_ctx == NULL) {
		exit(1);
	}

	ev = tevent_context_init(mem_ctx);
	if (ev == NULL) {
		ret = 1;
		goto fail;
	}

	ret = eventd_context_init(mem_ctx, ev, options.script_dir,
				  options.debug_script, &ectx);
	if (ret != 0) {
		goto fail;
	}

	daemon_funcs = (struct sock_daemon_funcs) {
		.shutdown = eventd_shutdown,
	};

	ret = sock_daemon_setup(mem_ctx, "ctdb-eventd", options.logging,
				options.debug_level, options.pidfile,
				&daemon_funcs, ectx, &sockd);
	if (ret != 0) {
		goto fail;
	}

	socket_funcs = (struct sock_socket_funcs) {
		.connect = client_connect,
		.disconnect = client_disconnect,
		.read_send = client_process_send,
		.read_recv = client_process_recv,
	};

	ret = sock_daemon_add_unix(sockd, options.socket, &socket_funcs, ectx);
	if (ret != 0) {
		goto fail;
	}

	ret = sock_daemon_run(ev, sockd, options.pid);
	if (ret == EINTR) {
		ret = 0;
	}

fail:
	talloc_free(mem_ctx);
	(void)poptFreeContext(pc);
	exit(ret);
}
