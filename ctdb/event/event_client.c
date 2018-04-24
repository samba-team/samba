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

#include "replace.h"

#include <talloc.h>
#include <tevent.h>

#include "lib/util/debug.h"
#include "lib/util/tevent_unix.h"

#include "common/logging.h"
#include "common/path.h"
#include "common/sock_client.h"

#include "event/event_protocol_api.h"
#include "event/event.h"

struct ctdb_event_context {
	char *socket;
	struct sock_client_context *sockc;
};

struct event_request {
	struct ctdb_event_header header;
	struct ctdb_event_request *request;
};

struct event_reply {
	struct ctdb_event_header header;
	struct ctdb_event_reply *reply;
};

static int event_request_push(void *request_data,
			      uint32_t reqid,
			      TALLOC_CTX *mem_ctx,
			      uint8_t **buf,
			      size_t *buflen,
			      void *private_data)
{
	struct event_request *r = (struct event_request *)request_data;
	int ret;

	r->header.reqid = reqid;

	*buflen = ctdb_event_request_len(&r->header, r->request);
	*buf = talloc_size(mem_ctx, *buflen);
	if (*buf == NULL) {
		return ENOMEM;
	}

	ret = ctdb_event_request_push(&r->header, r->request, *buf, buflen);
	if (ret != 0) {
		talloc_free(*buf);
		return ret;
	}

	return 0;
}

static int event_reply_pull(uint8_t *buf,
			    size_t buflen,
			    TALLOC_CTX *mem_ctx,
			    void **reply_data,
			    void *private_data)
{
	struct event_reply *r;
	int ret;

	r = talloc_zero(mem_ctx, struct event_reply);
	if (r == NULL) {
		return ENOMEM;
	}

	ret = ctdb_event_reply_pull(buf, buflen, &r->header, r, &r->reply);
	if (ret != 0) {
		talloc_free(r);
		return ret;
	}

	*reply_data = r;

	return 0;
}

static int event_reply_reqid(uint8_t *buf,
			     size_t buflen,
			     uint32_t *reqid,
			     void *private_data)
{
	struct ctdb_event_header header;
	int ret;

	ret = ctdb_event_header_extract(buf, buflen, &header);
	if (ret != 0) {
		return ret;
	}

	*reqid = header.reqid;
	return 0;
}

struct sock_client_proto_funcs event_proto_funcs = {
	.request_push = event_request_push,
	.reply_pull = event_reply_pull,
	.reply_reqid = event_reply_reqid,
};

int ctdb_event_init(TALLOC_CTX *mem_ctx,
		    struct tevent_context *ev,
		    struct ctdb_event_context **result)
{
	struct ctdb_event_context *eclient;
	int ret;

	eclient = talloc_zero(mem_ctx, struct ctdb_event_context);
	if (eclient == NULL) {
		return ENOMEM;
	}

	eclient->socket = path_socket(eclient, "eventd");
	if (eclient->socket == NULL) {
		talloc_free(eclient);
		return ENOMEM;
	}

	ret = sock_client_setup(eclient,
				ev,
				eclient->socket,
				&event_proto_funcs,
				eclient,
				&eclient->sockc);
	if (ret != 0) {
		talloc_free(eclient);
		return ret;
	}

	*result = eclient;
	return 0;
}

/*
 * Handle request and reply
 */

struct ctdb_event_msg_state {
	struct event_request e_request;
	struct event_reply *e_reply;
};

static void ctdb_event_msg_done(struct tevent_req *subreq);

static struct tevent_req *ctdb_event_msg_send(
				TALLOC_CTX *mem_ctx,
				struct tevent_context *ev,
				struct ctdb_event_context *eclient,
				struct ctdb_event_request *request)
{
	struct tevent_req *req, *subreq;
	struct ctdb_event_msg_state *state;

	req = tevent_req_create(mem_ctx, &state, struct ctdb_event_msg_state);
	if (req == NULL) {
		return NULL;
	}

	state->e_request.request = request;

	subreq = sock_client_msg_send(mem_ctx,
				      ev,
				      eclient->sockc,
				      tevent_timeval_zero(),
				      &state->e_request);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, ctdb_event_msg_done, req);

	return req;
}

static void ctdb_event_msg_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct ctdb_event_msg_state *state = tevent_req_data(
		req, struct ctdb_event_msg_state);
	int ret = 0;
	bool ok;

	ok = sock_client_msg_recv(subreq, &ret, state, &state->e_reply);
	TALLOC_FREE(subreq);
	if (!ok) {
		tevent_req_error(req, ret);
		return;
	}

	tevent_req_done(req);
}

static bool ctdb_event_msg_recv(struct tevent_req *req,
				int *perr,
				TALLOC_CTX *mem_ctx,
				struct ctdb_event_reply **reply)
{
	struct ctdb_event_msg_state *state = tevent_req_data(
		req, struct ctdb_event_msg_state);
	int ret = 0;

	if (tevent_req_is_unix_error(req, &ret)) {
		if (perr != NULL) {
			*perr = ret;
		}
		return false;
	}

	*reply = talloc_steal(mem_ctx, state->e_reply->reply);

	return true;
}

/*
 * API functions
 */

struct tevent_req *ctdb_event_run_send(TALLOC_CTX *mem_ctx,
				       struct tevent_context *ev,
				       struct ctdb_event_context *eclient,
				       struct ctdb_event_request_run *run)
{
	struct ctdb_event_request request;

	request.cmd = CTDB_EVENT_CMD_RUN;
	request.data.run = run;

	return ctdb_event_msg_send(mem_ctx, ev, eclient, &request);
}

bool ctdb_event_run_recv(struct tevent_req *req, int *perr, int *result)
{
	struct ctdb_event_reply *reply = NULL;
	bool ok;

	ok = ctdb_event_msg_recv(req, perr, req, &reply);
	if (!ok) {
		return false;
	}

	if (reply->cmd != CTDB_EVENT_CMD_RUN) {
		*result = EPROTO;
	} else {
		*result = reply->result;
	}

	talloc_free(reply);
	return true;
}

struct tevent_req *ctdb_event_status_send(
				TALLOC_CTX *mem_ctx,
				struct tevent_context *ev,
				struct ctdb_event_context *eclient,
				struct ctdb_event_request_status *status)
{
	struct ctdb_event_request request;

	request.cmd = CTDB_EVENT_CMD_STATUS;
	request.data.status = status;

	return ctdb_event_msg_send(mem_ctx, ev, eclient, &request);
}

bool ctdb_event_status_recv(struct tevent_req *req,
			    int *perr,
			    int *result,
			    TALLOC_CTX *mem_ctx,
			    struct ctdb_event_reply_status **status)
{
	struct ctdb_event_reply *reply = NULL;
	bool ok;

	ok = ctdb_event_msg_recv(req, perr, req, &reply);
	if (!ok) {
		return false;
	}

	if (reply->cmd != CTDB_EVENT_CMD_STATUS) {
		*result = EPROTO;
	} else {
		*result = reply->result;
	}

	if (reply->result == 0) {
		*status = talloc_steal(mem_ctx, reply->data.status);
	} else {
		*status = NULL;
	}

	talloc_free(reply);
	return true;
}

struct tevent_req *ctdb_event_script_send(
				TALLOC_CTX *mem_ctx,
				struct tevent_context *ev,
				struct ctdb_event_context *eclient,
				struct ctdb_event_request_script *script)
{
	struct ctdb_event_request request;

	request.cmd = CTDB_EVENT_CMD_SCRIPT;
	request.data.script = script;

	return ctdb_event_msg_send(mem_ctx, ev, eclient, &request);
}

bool ctdb_event_script_recv(struct tevent_req *req, int *perr, int *result)
{
	struct ctdb_event_reply *reply = NULL;
	bool ok;

	ok = ctdb_event_msg_recv(req, perr, req, &reply);
	if (!ok) {
		return false;
	}

	if (reply->cmd != CTDB_EVENT_CMD_SCRIPT) {
		*result = EPROTO;
	} else {
		*result = reply->result;
	}

	talloc_free(reply);
	return true;
}
