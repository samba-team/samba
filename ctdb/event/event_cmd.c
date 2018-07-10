/*
   CTDB event daemon - command handling

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

#include "replace.h"

#include <talloc.h>
#include <tevent.h>

#include "lib/util/debug.h"
#include "lib/util/tevent_unix.h"

#include "common/logging.h"

#include "event/event_private.h"

struct event_cmd_state {
	struct event_context *eventd;
	struct ctdb_event_request *request;
	struct ctdb_event_reply *reply;
};

/*
 * CTDB_EVENT_CMD_RUN
 */

static void event_cmd_run_done(struct tevent_req *subreq);

static struct tevent_req *event_cmd_run_send(
				TALLOC_CTX *mem_ctx,
				struct tevent_context *ev,
				struct event_context *eventd,
				struct ctdb_event_request *request,
				struct ctdb_event_reply *reply)
{
	struct tevent_req *req, *subreq;
	struct event_cmd_state *state;
	struct run_event_context *run_ctx;
	struct ctdb_event_request_run *rdata;
	int ret;
	bool continue_on_failure = false;

	req = tevent_req_create(mem_ctx, &state, struct event_cmd_state);
	if (req == NULL) {
		return NULL;
	}

	state->eventd = eventd;
	state->request = request;
	state->reply = reply;

	rdata = request->data.run;

	ret = eventd_run_ctx(eventd, rdata->component, &run_ctx);
	if (ret != 0) {
		state->reply->result = ret;
		tevent_req_done(req);
		return tevent_req_post(req, ev);
	}

	if (rdata->flags & CTDB_EVENT_RUN_ALL) {
		continue_on_failure = true;
	}

	subreq = run_event_send(state,
				ev,
				run_ctx,
				rdata->event,
				rdata->args,
				tevent_timeval_current_ofs(rdata->timeout,0),
				continue_on_failure);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, event_cmd_run_done, req);

	return req;
}

static void event_cmd_run_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct event_cmd_state *state = tevent_req_data(
		req, struct event_cmd_state);
	struct run_event_script_list *script_list = NULL;
	struct ctdb_event_request_run *rdata;
	int ret;
	bool ok;

	ok = run_event_recv(subreq, &ret, state, &script_list);
	TALLOC_FREE(subreq);
	if (!ok) {
		state->reply->result = ret;
		goto done;
	}

	if (script_list == NULL) {
		state->reply->result = EIO;
		goto done;
	}

	if (script_list->summary == -ECANCELED) {
		state->reply->result = ECANCELED;
		goto done;
	}

	rdata = state->request->data.run;
	ret = eventd_set_event_result(state->eventd,
				      rdata->component,
				      rdata->event,
				      script_list);
	if (ret != 0) {
		state->reply->result = ret;
		goto done;
	}

	if (script_list->summary == -ETIMEDOUT) {
		state->reply->result = ETIMEDOUT;
	} else if (script_list->summary != 0) {
		state->reply->result = ENOEXEC;
	}

done:
	tevent_req_done(req);
}

/*
 * CTDB_EVENT_CMD_STATUS
 */

static struct tevent_req *event_cmd_status_send(
				TALLOC_CTX *mem_ctx,
				struct tevent_context *ev,
				struct event_context *eventd,
				struct ctdb_event_request *request,
				struct ctdb_event_reply *reply)
{
	struct tevent_req *req;
	struct event_cmd_state *state;
	struct ctdb_event_request_run *rdata;
	struct run_event_script_list *script_list;
	int ret;

	req = tevent_req_create(mem_ctx, &state, struct event_cmd_state);
	if (req == NULL) {
		return NULL;
	}

	reply->data.status = talloc_zero(reply,
					 struct ctdb_event_reply_status);
	if (tevent_req_nomem(reply->data.status, req)) {
		reply->result = ENOMEM;
		goto done;
	}

	rdata = request->data.run;

	ret = eventd_get_event_result(eventd,
				      rdata->component,
				      rdata->event,
				      &script_list);
	if (ret != 0) {
		reply->result = ret;
		goto done;
	}

	reply->data.status->script_list = eventd_script_list(reply,
							     script_list);
	if (reply->data.status->script_list == NULL) {
		reply->result = ENOMEM;
		goto done;
	}
	reply->data.status->summary = script_list->summary;

	reply->result = 0;

done:
	tevent_req_done(req);
	return tevent_req_post(req, ev);
}

/*
 * CTDB_EVENT_CMD_SCRIPT
 */

static struct tevent_req *event_cmd_script_send(
				TALLOC_CTX *mem_ctx,
				struct tevent_context *ev,
				struct event_context *eventd,
				struct ctdb_event_request *request,
				struct ctdb_event_reply *reply)
{
	struct tevent_req *req;
	struct event_cmd_state *state;
	struct run_event_context *run_ctx;
	struct ctdb_event_request_script *rdata;
	int ret;

	req = tevent_req_create(mem_ctx, &state, struct event_cmd_state);
	if (req == NULL) {
		return NULL;
	}

	rdata = request->data.script;

	ret = eventd_run_ctx(eventd, rdata->component, &run_ctx);
	if (ret != 0) {
		reply->result = ret;
		goto done;
	}

	if (rdata->action == CTDB_EVENT_SCRIPT_DISABLE) {
		ret = run_event_script_disable(run_ctx, rdata->script);
	} else if (rdata->action == CTDB_EVENT_SCRIPT_ENABLE) {
		ret = run_event_script_enable(run_ctx, rdata->script);
	} else {
		D_ERR("Invalid action specified\n");
		reply->result = EPROTO;
		goto done;
	}

	if (ret != 0) {
		reply->result = ret;
		goto done;
	}

	reply->result = 0;

done:
	tevent_req_done(req);
	return tevent_req_post(req, ev);
}

static bool event_cmd_recv(struct tevent_req *req, int *perr)
{
	if (tevent_req_is_unix_error(req, perr)) {
		return false;
	}

	return true;
}


struct event_cmd_dispatch_state {
	struct ctdb_event_reply *reply;
};

static void event_cmd_dispatch_done(struct tevent_req *subreq);

struct tevent_req *event_cmd_dispatch_send(TALLOC_CTX *mem_ctx,
					   struct tevent_context *ev,
					   struct event_context *eventd,
					   struct ctdb_event_request *request)
{
	struct tevent_req *req, *subreq;
	struct event_cmd_dispatch_state *state;

	req = tevent_req_create(mem_ctx,
				&state,
				struct event_cmd_dispatch_state);
	if (req == NULL) {
		return NULL;
	}

	state->reply = talloc_zero(state, struct ctdb_event_reply);
	if (tevent_req_nomem(state->reply, req)) {
		return tevent_req_post(req, ev);
	}

	state->reply->cmd = request->cmd;

	switch (request->cmd) {
	case CTDB_EVENT_CMD_RUN:
		subreq = event_cmd_run_send(state,
					    ev,
					    eventd,
					    request,
					    state->reply);
		break;

	case CTDB_EVENT_CMD_STATUS:
		subreq = event_cmd_status_send(state,
					       ev,
					       eventd,
					       request,
					       state->reply);
		break;

	case CTDB_EVENT_CMD_SCRIPT:
		subreq = event_cmd_script_send(state,
					       ev,
					       eventd,
					       request,
					       state->reply);
		break;

	default:
		state->reply->result = EPROTO;
		tevent_req_done(req);
		return tevent_req_post(req, ev);
	}

	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, event_cmd_dispatch_done, req);

	return req;
}

static void event_cmd_dispatch_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	int ret;
	bool ok;

	ok = event_cmd_recv(subreq, &ret);
	TALLOC_FREE(subreq);
	if (!ok) {
		tevent_req_error(req, ret);
		return;
	}

	tevent_req_done(req);
}

bool event_cmd_dispatch_recv(struct tevent_req *req,
			     int *perr,
			     TALLOC_CTX *mem_ctx,
			     struct ctdb_event_reply **reply)
{
	struct event_cmd_dispatch_state *state = tevent_req_data(
		req, struct event_cmd_dispatch_state);

	if (tevent_req_is_unix_error(req, perr)) {
		return false;
	}

	*reply = talloc_steal(mem_ctx, state->reply);
	return true;
}
