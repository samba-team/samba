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
#include "system/network.h"

#include <talloc.h>
#include <tevent.h>

#include "lib/util/debug.h"
#include "lib/util/tevent_unix.h"

#include "common/logging.h"
#include "common/sock_client.h"

#include "protocol/protocol_api.h"

#include "client/client_event.h"

struct ctdb_event_context {
	struct sock_client_context *sockc;
};

static int ctdb_event_msg_request_push(void *request_data, uint32_t reqid,
				       TALLOC_CTX *mem_ctx,
				       uint8_t **buf, size_t *buflen,
				       void *private_data)
{
	struct ctdb_event_request *request =
		(struct ctdb_event_request *)request_data;
	int ret;

	sock_packet_header_set_reqid(&request->header, reqid);

	*buflen = ctdb_event_request_len(request);
	*buf = talloc_size(mem_ctx, *buflen);
	if (*buf == NULL) {
		return ENOMEM;
	}

	ret = ctdb_event_request_push(request, *buf, buflen);
	if (ret != 0) {
		return ret;
	}

	return 0;
}

static int ctdb_event_msg_reply_pull(uint8_t *buf, size_t buflen,
				     TALLOC_CTX *mem_ctx, void **reply_data,
				     void *private_data)
{
	struct ctdb_event_reply *reply;
	int ret;

	reply = talloc_zero(mem_ctx, struct ctdb_event_reply);
	if (reply == NULL) {
		return ENOMEM;
	}

	ret = ctdb_event_reply_pull(buf, buflen, reply, reply);
	if (ret != 0) {
		talloc_free(reply);
		return ret;
	}

	*reply_data = reply;
	return 0;
}

static int ctdb_event_msg_reply_reqid(uint8_t *buf, size_t buflen,
				      uint32_t *reqid, void *private_data)
{
	struct sock_packet_header header;
	size_t np;
	int ret;

	ret = sock_packet_header_pull(buf, buflen, &header, &np);
	if (ret != 0) {
		return ret;
	}

	*reqid = header.reqid;
	return 0;
}

struct sock_client_proto_funcs event_proto_funcs = {
	.request_push = ctdb_event_msg_request_push,
	.reply_pull = ctdb_event_msg_reply_pull,
	.reply_reqid = ctdb_event_msg_reply_reqid,
};


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

	ret = sock_client_setup(eclient, ev, sockpath,
				&event_proto_funcs, eclient,
				&eclient->sockc);
	if (ret != 0) {
		talloc_free(eclient);
		return ret;
	}

	*out = eclient;
	return 0;
}

void ctdb_event_set_disconnect_callback(struct ctdb_event_context *eclient,
					ctdb_client_callback_func_t callback,
					void *private_data)
{
	sock_client_set_disconnect_callback(eclient->sockc,
					    callback, private_data);
}

/*
 * Handle eventd_request and eventd_reply
 */

struct tevent_req *ctdb_event_msg_send(TALLOC_CTX *mem_ctx,
				       struct tevent_context *ev,
				       struct ctdb_event_context *eclient,
				       struct ctdb_event_request *request)
{
	struct tevent_req *req;

	req = sock_client_msg_send(mem_ctx, ev, eclient->sockc,
				   tevent_timeval_zero(), request);
	return req;
}

bool ctdb_event_msg_recv(struct tevent_req *req, int *perr,
			 TALLOC_CTX *mem_ctx,
			 struct ctdb_event_reply **reply)
{
	void *reply_data;
	bool status;

	status = sock_client_msg_recv(req, perr, mem_ctx, &reply_data);

	if (status && reply != NULL) {
		*reply = talloc_get_type_abort(
				reply_data, struct ctdb_event_reply);
	}

	return status;
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
