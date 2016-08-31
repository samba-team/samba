/*
   Eventd client api

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
#include "system/network.h"

#include <talloc.h>
#include <tevent.h>

#include "lib/util/debug.h"
#include "lib/util/tevent_unix.h"

#include "common/logging.h"
#include "common/reqid.h"
#include "common/comm.h"

#include "protocol/protocol_api.h"

#include "client/client.h"

struct ctdb_event_context {
	struct reqid_context *idr;
	struct comm_context *comm;
	int fd;

	ctdb_client_callback_func_t callback;
	void *private_data;
};

static int ctdb_event_connect(struct ctdb_event_context *eclient,
			      struct tevent_context *ev,
			      const char *sockpath);

static int ctdb_event_context_destructor(struct ctdb_event_context *eclient);

int ctdb_event_init(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
		    const char *sockpath, struct ctdb_event_context **out)
{
	struct ctdb_event_context *eclient;
	int ret;

	eclient = talloc_zero(mem_ctx, struct ctdb_event_context);
	if (eclient == NULL) {
		DEBUG(DEBUG_ERR, (__location__ " memory allocation error\n"));
		return ENOMEM;
	}

	ret = reqid_init(eclient, INT_MAX-200, &eclient->idr);
	if (ret != 0) {
		DEBUG(DEBUG_ERR, ("reqid_init() failed, ret=%d\n", ret));
		talloc_free(eclient);
		return ret;
	}

	eclient->fd = -1;

	ret = ctdb_event_connect(eclient, ev, sockpath);
	if (ret != 0) {
		talloc_free(eclient);
		return ret;
	}

	talloc_set_destructor(eclient, ctdb_event_context_destructor);

	*out = eclient;
	return 0;
}

static int ctdb_event_context_destructor(struct ctdb_event_context *eclient)
{
	if (eclient->fd != -1) {
		close(eclient->fd);
		eclient->fd = -1;
	}
	return 0;
}

static void event_read_handler(uint8_t *buf, size_t buflen,
			       void *private_data);
static void event_dead_handler(void *private_data);

static int ctdb_event_connect(struct ctdb_event_context *eclient,
			      struct tevent_context *ev, const char *sockpath)
{
	struct sockaddr_un addr;
	size_t len;
	int fd, ret;

	if (sockpath == NULL) {
		DEBUG(DEBUG_ERR, ("socket path cannot be NULL\n"));
		return EINVAL;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	len = strlcpy(addr.sun_path, sockpath, sizeof(addr.sun_path));
	if (len >= sizeof(addr.sun_path)) {
		DEBUG(DEBUG_ERR, ("socket path too long, len=%zu\n",
				  strlen(sockpath)));
		return ENAMETOOLONG;
	}

	fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd == -1) {
		ret = errno;
		DEBUG(DEBUG_ERR, ("socket() failed, errno=%d\n", ret));
		return ret;
	}

	ret = connect(fd, (struct sockaddr *)&addr, sizeof(addr));
	if (ret == -1) {
		ret = errno;
		DEBUG(DEBUG_ERR, ("connect() failed, errno=%d\n", ret));
		close(fd);
		return ret;
	}
	eclient->fd = fd;

	ret = comm_setup(eclient, ev, fd, event_read_handler, eclient,
			 event_dead_handler, eclient, &eclient->comm);
	if (ret != 0) {
		DEBUG(DEBUG_ERR, ("comm_setup() failed, ret=%d\n", ret));
		close(fd);
		eclient->fd = -1;
		return ret;
	}

	return 0;
}

static void ctdb_event_msg_reply(struct ctdb_event_context *eclient,
				 uint8_t *buf, size_t buflen);

static void event_read_handler(uint8_t *buf, size_t buflen,
			       void *private_data)
{
	struct ctdb_event_context *eclient = talloc_get_type_abort(
		private_data, struct ctdb_event_context);

	ctdb_event_msg_reply(eclient, buf, buflen);
}

static void event_dead_handler(void *private_data)
{
	struct ctdb_event_context *eclient = talloc_get_type_abort(
		private_data, struct ctdb_event_context);
	ctdb_client_callback_func_t callback = eclient->callback;
	void *callback_data = eclient->private_data;

	talloc_free(eclient);
	if (callback != NULL) {
		callback(callback_data);
		return;
	}

	DEBUG(DEBUG_NOTICE, ("connection to daemon closed, exiting\n"));
	exit(1);
}

void ctdb_event_set_disconnect_callback(struct ctdb_event_context *eclient,
					ctdb_client_callback_func_t callback,
					void *private_data)
{
	eclient->callback = callback;
	eclient->private_data = private_data;
}

/*
 * Handle eventd_request and eventd_reply
 */

struct ctdb_event_msg_state {
	struct ctdb_event_context *eclient;

	uint32_t reqid;
	struct tevent_req *req;
	struct ctdb_event_reply *reply;
};

static int ctdb_event_msg_state_destructor(struct ctdb_event_msg_state *state);
static void ctdb_event_msg_done(struct tevent_req *subreq);

struct tevent_req *ctdb_event_msg_send(TALLOC_CTX *mem_ctx,
				       struct tevent_context *ev,
				       struct ctdb_event_context *eclient,
				       struct ctdb_event_request *request)
{
	struct tevent_req *req, *subreq;
	struct ctdb_event_msg_state *state;
	uint8_t *buf;
	size_t buflen;
	int ret;

	req = tevent_req_create(mem_ctx, &state, struct ctdb_event_msg_state);
	if (req == NULL) {
		return NULL;
	}

	state->eclient = eclient;

	state->reqid = reqid_new(eclient->idr, state);
	if (state->reqid == REQID_INVALID) {
		talloc_free(req);
		return NULL;
	}
	state->req = req;

	talloc_set_destructor(state, ctdb_event_msg_state_destructor);

	ctdb_event_header_fill(&request->header, state->reqid);

	buflen = ctdb_event_request_len(request);
	buf = talloc_size(state, buflen);
	if (tevent_req_nomem(buf, req)) {
		return tevent_req_post(req, ev);
	}

	ret = ctdb_event_request_push(request, buf, &buflen);
	if (ret != 0) {
		tevent_req_error(req, ret);
		return tevent_req_post(req, ev);
	}

	subreq = comm_write_send(state, ev, eclient->comm, buf, buflen);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, ctdb_event_msg_done, req);

	return req;
}

static int ctdb_event_msg_state_destructor(struct ctdb_event_msg_state *state)
{
	reqid_remove(state->eclient->idr, state->reqid);
	return 0;
}

static void ctdb_event_msg_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	int ret;
	bool status;

	status = comm_write_recv(subreq, &ret);
	TALLOC_FREE(subreq);
	if (! status) {
		tevent_req_error(req, ret);
		return;
	}

	/* Wait for the reply or timeout */
}

static void ctdb_event_msg_reply(struct ctdb_event_context *eclient,
				 uint8_t *buf, size_t buflen)
{
	struct ctdb_event_reply *reply;
	struct ctdb_event_msg_state *state;
	int ret;

	reply = talloc_zero(eclient, struct ctdb_event_reply);
	if (reply == NULL) {
		D_WARNING("memory allocation error\n");
		return;
	}

	ret = ctdb_event_reply_pull(buf, buflen, reply, reply);
	if (ret != 0) {
		D_WARNING("Invalid packet received, ret=%d\n", ret);
		return;
	}

	state = reqid_find(eclient->idr, reply->header.reqid,
			   struct ctdb_event_msg_state);
	if (state == NULL) {
		return;
	}

	if (reply->header.reqid != state->reqid) {
		return;
	}

	state->reply = talloc_steal(state, reply);
	tevent_req_done(state->req);
}

bool ctdb_event_msg_recv(struct tevent_req *req, int *perr,
			 TALLOC_CTX *mem_ctx,
			 struct ctdb_event_reply **reply)
{
	struct ctdb_event_msg_state *state = tevent_req_data(
		req, struct ctdb_event_msg_state);
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
 * Run an event
 */

struct tevent_req *ctdb_event_run_send(TALLOC_CTX *mem_ctx,
				       struct tevent_context *ev,
				       struct ctdb_event_context *eclient,
				       enum ctdb_event event,
				       uint32_t timeout, const char *arg_str)
{
	struct ctdb_event_request request;
	struct ctdb_event_request_run rdata;

	rdata.event = event;
	rdata.timeout = timeout;
	rdata.arg_str = arg_str;

	request.rdata.command = CTDB_EVENT_COMMAND_RUN;
	request.rdata.data.run = &rdata;

	return ctdb_event_msg_send(mem_ctx, ev, eclient, &request);
}

bool ctdb_event_run_recv(struct tevent_req *req, int *perr, int *result)
{
	struct ctdb_event_reply *reply;
	int ret;
	bool status;

	status = ctdb_event_msg_recv(req, &ret, req, &reply);
	if (! status) {
		if (perr != NULL) {
			*perr = ret;
		}
		return false;
	}

	if (reply->rdata.command != CTDB_EVENT_COMMAND_RUN) {
		if (perr != NULL) {
			*perr = EPROTO;
		}
		talloc_free(reply);
		return false;
	}

	if (result != NULL) {
		*result = reply->rdata.result;
	}

	talloc_free(reply);
	return true;
}

/*
 * Get event status
 */

struct tevent_req *ctdb_event_status_send(TALLOC_CTX *mem_ctx,
					  struct tevent_context *ev,
					  struct ctdb_event_context *eclient,
					  enum ctdb_event event,
					  enum ctdb_event_status_state state)
{
	struct ctdb_event_request request;
	struct ctdb_event_request_status rdata;

	rdata.event = event;
	rdata.state = state;

	request.rdata.command = CTDB_EVENT_COMMAND_STATUS;
	request.rdata.data.status = &rdata;

	return ctdb_event_msg_send(mem_ctx, ev, eclient, &request);
}

bool ctdb_event_status_recv(struct tevent_req *req, int *perr,
			    int32_t *result, int *event_status,
			    TALLOC_CTX *mem_ctx,
			    struct ctdb_script_list **script_list)
{
	struct ctdb_event_reply *reply;
	int ret;
	bool status;

	status = ctdb_event_msg_recv(req, &ret, req, &reply);
	if (! status) {
		if (perr != NULL) {
			*perr = ret;
		}
		return false;
	}

	if (reply->rdata.command != CTDB_EVENT_COMMAND_STATUS) {
		if (perr != NULL) {
			*perr = EPROTO;
		}
		talloc_free(reply);
		return false;
	}

	if (result != NULL) {
		*result = reply->rdata.result;
	}
	if (event_status != NULL) {
		*event_status = reply->rdata.data.status->status;
	}
	if (script_list != NULL) {
		*script_list = talloc_steal(mem_ctx,
					reply->rdata.data.status->script_list);
	}

	talloc_free(reply);
	return true;
}

/*
 * Get script list
 */

struct tevent_req *ctdb_event_script_list_send(
					TALLOC_CTX *mem_ctx,
					struct tevent_context *ev,
					struct ctdb_event_context *eclient)
{
	struct ctdb_event_request request;

	request.rdata.command = CTDB_EVENT_COMMAND_SCRIPT_LIST;

	return ctdb_event_msg_send(mem_ctx, ev, eclient, &request);
}

bool ctdb_event_script_list_recv(struct tevent_req *req, int *perr,
				 int32_t *result, TALLOC_CTX *mem_ctx,
				 struct ctdb_script_list **script_list)
{
	struct ctdb_event_reply *reply;
	int ret;
	bool status;

	status = ctdb_event_msg_recv(req, &ret, req, &reply);
	if (! status) {
		if (perr != NULL) {
			*perr = ret;
		}
		return false;
	}

	if (reply->rdata.command != CTDB_EVENT_COMMAND_SCRIPT_LIST) {
		if (perr != NULL) {
			*perr = EPROTO;
		}
		talloc_free(reply);
		return false;
	}

	if (result != NULL) {
		*result = reply->rdata.result;
	}
	if (script_list != NULL) {
		*script_list = talloc_steal(mem_ctx,
				reply->rdata.data.script_list->script_list);
	}

	talloc_free(reply);
	return true;
}

/*
 * Enable a script
 */

struct tevent_req *ctdb_event_script_enable_send(
					TALLOC_CTX *mem_ctx,
					struct tevent_context *ev,
					struct ctdb_event_context *eclient,
					const char *script_name)
{
	struct ctdb_event_request request;
	struct ctdb_event_request_script_enable rdata;

	rdata.script_name = script_name;

	request.rdata.command = CTDB_EVENT_COMMAND_SCRIPT_ENABLE;
	request.rdata.data.script_enable = &rdata;

	return ctdb_event_msg_send(mem_ctx, ev, eclient, &request);
}

bool ctdb_event_script_enable_recv(struct tevent_req *req, int *perr,
				   int *result)
{
	struct ctdb_event_reply *reply;
	int ret;
	bool status;

	status = ctdb_event_msg_recv(req, &ret, req, &reply);
	if (! status) {
		if (perr != NULL) {
			*perr = ret;
		}
		return false;
	}

	if (reply->rdata.command != CTDB_EVENT_COMMAND_SCRIPT_ENABLE) {
		if (perr != NULL) {
			*perr = EPROTO;
		}
		talloc_free(reply);
		return false;
	}

	if (result != NULL) {
		*result = reply->rdata.result;
	}

	talloc_free(reply);
	return true;
}

/*
 * Disable a script
 */

struct tevent_req *ctdb_event_script_disable_send(
					TALLOC_CTX *mem_ctx,
					struct tevent_context *ev,
					struct ctdb_event_context *eclient,
					const char *script_name)
{
	struct ctdb_event_request request;
	struct ctdb_event_request_script_disable rdata;

	rdata.script_name = script_name;

	request.rdata.command = CTDB_EVENT_COMMAND_SCRIPT_DISABLE;
	request.rdata.data.script_disable = &rdata;

	return ctdb_event_msg_send(mem_ctx, ev, eclient, &request);
}

bool ctdb_event_script_disable_recv(struct tevent_req *req, int *perr,
				    int *result)
{
	struct ctdb_event_reply *reply;
	int ret;
	bool status;

	status = ctdb_event_msg_recv(req, &ret, req, &reply);
	if (! status) {
		if (perr != NULL) {
			*perr = ret;
		}
		return false;
	}

	if (reply->rdata.command != CTDB_EVENT_COMMAND_SCRIPT_DISABLE) {
		if (perr != NULL) {
			*perr = EPROTO;
		}
		talloc_free(reply);
		return false;
	}

	if (result != NULL) {
		*result = reply->rdata.result;
	}

	talloc_free(reply);
	return true;
}
