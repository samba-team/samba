/*
   CTDB client code

   Copyright (C) Amitay Isaacs  2015

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
#include "system/filesys.h"

#include <talloc.h>
#include <tevent.h>
#include <tdb.h>

#include "lib/util/tevent_unix.h"

#include "common/reqid.h"
#include "common/srvid.h"
#include "common/comm.h"

#include "protocol/protocol.h"
#include "protocol/protocol_api.h"

#include "client/client_private.h"
#include "client/client.h"


/*
 * Handle REQ_MESSAGE
 */

struct ctdb_client_message_state {
	struct ctdb_client_context *client;
	uint32_t reqid;
};

static int ctdb_client_message_state_destructor(
	struct ctdb_client_message_state *state);
static void ctdb_client_message_done(struct tevent_req *subreq);

struct tevent_req *ctdb_client_message_send(TALLOC_CTX *mem_ctx,
					    struct tevent_context *ev,
					    struct ctdb_client_context *client,
					    uint32_t destnode,
					    struct ctdb_req_message *message)
{
	struct tevent_req *req, *subreq;
	struct ctdb_client_message_state *state;
	struct ctdb_req_header h;
	uint32_t reqid;
	uint8_t *buf;
	size_t datalen, buflen;
	int ret;

	req = tevent_req_create(mem_ctx, &state,
				struct ctdb_client_message_state);
	if (req == NULL) {
		return NULL;
	}

	reqid = reqid_new(client->idr, state);
	if (reqid == REQID_INVALID) {
		talloc_free(req);
		return NULL;
	}

	state->client = client;
	state->reqid = reqid;

	talloc_set_destructor(state, ctdb_client_message_state_destructor);

	ctdb_req_header_fill(&h, 0, CTDB_REQ_MESSAGE, destnode,
			     client->pnn, reqid);

	datalen = ctdb_req_message_len(&h, message);
	ret = ctdb_allocate_pkt(state, datalen, &buf, &buflen);
	if (ret != 0) {
		tevent_req_error(req, ret);
		return tevent_req_post(req, ev);
	}

	ret = ctdb_req_message_push(&h, message, buf, &buflen);
	if (ret != 0) {
		tevent_req_error(req, ret);
		return tevent_req_post(req, ev);
	}

	subreq = comm_write_send(state, ev, client->comm, buf, buflen);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, ctdb_client_message_done, req);

	return req;
}

static int ctdb_client_message_state_destructor(
	struct ctdb_client_message_state *state)
{
	reqid_remove(state->client->idr, state->reqid);
	return 0;
}

static void ctdb_client_message_done(struct tevent_req *subreq)
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

	tevent_req_done(req);
}

bool ctdb_client_message_recv(struct tevent_req *req, int *perr)
{
	int err;

	if (tevent_req_is_unix_error(req, &err)) {
		if (perr != NULL) {
			*perr = err;
		}
		return false;
	}

	return true;
}

void ctdb_client_req_message(struct ctdb_client_context *client,
			     uint8_t *buf, size_t buflen, uint32_t reqid)
{
	struct ctdb_req_header h;
	struct ctdb_req_message_data message;
	TALLOC_CTX *tmp_ctx = talloc_new(client);
	int ret;

	ret = ctdb_req_message_data_pull(buf, buflen, &h, tmp_ctx, &message);
	if (ret != 0) {
		return;
	}

	srvid_dispatch(client->srv, message.srvid, CTDB_SRVID_ALL,
		       message.data);
	talloc_free(tmp_ctx);
}

/*
 * Handle multiple nodes
 */

struct ctdb_client_message_multi_state {
	uint32_t *pnn_list;
	int count;
	int done;
	int err;
	int *err_list;
};

struct message_index_state {
	struct tevent_req *req;
	int index;
};

static void ctdb_client_message_multi_done(struct tevent_req *subreq);

struct tevent_req *ctdb_client_message_multi_send(
				TALLOC_CTX *mem_ctx,
				struct tevent_context *ev,
				struct ctdb_client_context *client,
				uint32_t *pnn_list, int count,
				struct ctdb_req_message *message)
{
	struct tevent_req *req, *subreq;
	struct ctdb_client_message_multi_state *state;
	int i;

	if (pnn_list == NULL || count == 0) {
		return NULL;
	}

	req = tevent_req_create(mem_ctx, &state,
				struct ctdb_client_message_multi_state);
	if (req == NULL) {
		return NULL;
	}

	state->pnn_list = pnn_list;
	state->count = count;
	state->done = 0;
	state->err = 0;
	state->err_list = talloc_zero_array(state, int, count);
	if (tevent_req_nomem(state->err_list, req)) {
		return tevent_req_post(req, ev);
	}

	for (i=0; i<count; i++) {
		struct message_index_state *substate;

		subreq = ctdb_client_message_send(state, ev, client,
						  pnn_list[i], message);
		if (tevent_req_nomem(subreq, req)) {
			return tevent_req_post(req, ev);
		}

		substate = talloc(subreq, struct message_index_state);
		if (tevent_req_nomem(substate, req)) {
			return tevent_req_post(req, ev);
		}

		substate->req = req;
		substate->index = i;

		tevent_req_set_callback(subreq, ctdb_client_message_multi_done,
					substate);
	}

	return req;
}

static void ctdb_client_message_multi_done(struct tevent_req *subreq)
{
	struct message_index_state *substate = tevent_req_callback_data(
		subreq, struct message_index_state);
	struct tevent_req *req = substate->req;
	int idx = substate->index;
	struct ctdb_client_message_multi_state *state = tevent_req_data(
		req, struct ctdb_client_message_multi_state);
	bool status;
	int ret;

	status = ctdb_client_message_recv(subreq, &ret);
	TALLOC_FREE(subreq);
	if (! status) {
		if (state->err == 0) {
			state->err = ret;
			state->err_list[idx] = state->err;
		}
	}

	state->done += 1;

	if (state->done == state->count) {
		tevent_req_done(req);
	}
}

bool ctdb_client_message_multi_recv(struct tevent_req *req, int *perr,
				    TALLOC_CTX *mem_ctx, int **perr_list)
{
	struct ctdb_client_message_multi_state *state = tevent_req_data(
		req, struct ctdb_client_message_multi_state);
	int err;

	if (tevent_req_is_unix_error(req, &err)) {
		if (perr != NULL) {
			*perr = err;
		}
		if (perr_list != NULL) {
			*perr_list = talloc_steal(mem_ctx, state->err_list);
		}
		return false;
	}

	if (perr != NULL) {
		*perr = state->err;
	}

	if (perr_list != NULL) {
		*perr_list = talloc_steal(mem_ctx, state->err_list);
	}

	if (state->err != 0) {
		return false;
	}

	return true;
}

/*
 * sync version of message send
 */

int ctdb_client_message(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
			struct ctdb_client_context *client,
			uint32_t destnode, struct ctdb_req_message *message)
{
	TALLOC_CTX *tmp_ctx;
	struct tevent_req *req;
	int ret;
	bool status;

	tmp_ctx = talloc_new(client);
	if (tmp_ctx == NULL) {
		return ENOMEM;
	}

	req = ctdb_client_message_send(tmp_ctx, ev, client, destnode, message);
	if (req == NULL) {
		talloc_free(tmp_ctx);
		return ENOMEM;
	}

	tevent_req_poll(req, ev);

	status = ctdb_client_message_recv(req, &ret);
	if (! status) {
		talloc_free(tmp_ctx);
		return ret;
	}

	talloc_free(tmp_ctx);
	return 0;
}

int ctdb_client_message_multi(TALLOC_CTX *mem_ctx,
			      struct tevent_context *ev,
			      struct ctdb_client_context *client,
			      uint32_t *pnn_list, int count,
			      struct ctdb_req_message *message,
			      int **perr_list)
{
	struct tevent_req *req;
	bool status;
	int ret;

	req = ctdb_client_message_multi_send(mem_ctx, ev, client,
					     pnn_list, count,
					     message);
	if (req == NULL) {
		return ENOMEM;
	}

	tevent_req_poll(req, ev);

	status = ctdb_client_message_multi_recv(req, &ret, mem_ctx, perr_list);
	if (! status) {
		return ret;
	}

	return 0;
}

struct ctdb_client_set_message_handler_state {
	struct ctdb_client_context *client;
	uint64_t srvid;
	srvid_handler_fn handler;
	void *private_data;
};

static void ctdb_client_set_message_handler_done(struct tevent_req *subreq);

struct tevent_req *ctdb_client_set_message_handler_send(
					TALLOC_CTX *mem_ctx,
					struct tevent_context *ev,
					struct ctdb_client_context *client,
					uint64_t srvid,
					srvid_handler_fn handler,
					void *private_data)
{
	struct tevent_req *req, *subreq;
	struct ctdb_client_set_message_handler_state *state;
	struct ctdb_req_control request;

	req = tevent_req_create(mem_ctx, &state,
				struct ctdb_client_set_message_handler_state);
	if (req == NULL) {
		return NULL;
	}

	state->client = client;
	state->srvid = srvid;
	state->handler = handler;
	state->private_data = private_data;

	ctdb_req_control_register_srvid(&request, srvid);
	subreq = ctdb_client_control_send(state, ev, client, client->pnn,
					  tevent_timeval_zero(), &request);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, ctdb_client_set_message_handler_done,
				req);

	return req;
}

static void ctdb_client_set_message_handler_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct ctdb_client_set_message_handler_state *state = tevent_req_data(
		req, struct ctdb_client_set_message_handler_state);
	struct ctdb_reply_control *reply;
	bool status;
	int ret;

	status = ctdb_client_control_recv(subreq, &ret, state, &reply);
	TALLOC_FREE(subreq);
	if (! status) {
		tevent_req_error(req, ret);
		return;
	}

	ret = ctdb_reply_control_register_srvid(reply);
	talloc_free(reply);
	if (ret != 0) {
		tevent_req_error(req, ret);
		return;
	}

	ret = srvid_register(state->client->srv, state->client, state->srvid,
			     state->handler, state->private_data);
	if (ret != 0) {
		tevent_req_error(req, ret);
		return;
	}

	tevent_req_done(req);
}

bool ctdb_client_set_message_handler_recv(struct tevent_req *req, int *perr)
{
	int err;

	if (tevent_req_is_unix_error(req, &err)) {
		if (perr != NULL) {
			*perr = err;
		}
		return false;
	}
	return true;
}

struct ctdb_client_remove_message_handler_state {
	struct ctdb_client_context *client;
	uint64_t srvid;
	void *private_data;
};

static void ctdb_client_remove_message_handler_done(struct tevent_req *subreq);

struct tevent_req *ctdb_client_remove_message_handler_send(
					TALLOC_CTX *mem_ctx,
					struct tevent_context *ev,
					struct ctdb_client_context *client,
					uint64_t srvid,
					void *private_data)
{
	struct tevent_req *req, *subreq;
	struct ctdb_client_remove_message_handler_state *state;
	struct ctdb_req_control request;

	req = tevent_req_create(mem_ctx, &state,
				struct ctdb_client_remove_message_handler_state);
	if (req == NULL) {
		return NULL;
	}

	state->client = client;
	state->srvid = srvid;
	state->private_data = private_data;

	ctdb_req_control_deregister_srvid(&request, srvid);
	subreq = ctdb_client_control_send(state, ev, client, client->pnn,
					  tevent_timeval_zero(), &request);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq,
				ctdb_client_remove_message_handler_done, req);

	return req;
}

static void ctdb_client_remove_message_handler_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct ctdb_client_remove_message_handler_state *state = tevent_req_data(
		req, struct ctdb_client_remove_message_handler_state);
	struct ctdb_reply_control *reply;
	bool status;
	int ret;

	status = ctdb_client_control_recv(subreq, &ret, state, &reply);
	TALLOC_FREE(subreq);
	if (! status) {
		tevent_req_error(req, ret);
		return;
	}

	ret = ctdb_reply_control_deregister_srvid(reply);
	talloc_free(reply);
	if (ret != 0) {
		tevent_req_error(req, ret);
		return;
	}

	ret = srvid_deregister(state->client->srv, state->srvid,
			       state->private_data);
	if (ret != 0) {
		tevent_req_error(req, ret);
		return;
	}

	tevent_req_done(req);
}

bool ctdb_client_remove_message_handler_recv(struct tevent_req *req, int *perr)
{
	int err;

	if (tevent_req_is_unix_error(req, &err)) {
		if (perr != NULL) {
			*perr = err;
		}
		return false;
	}
	return true;
}

int ctdb_client_set_message_handler(struct tevent_context *ev,
				    struct ctdb_client_context *client,
				    uint64_t srvid, srvid_handler_fn handler,
				    void *private_data)
{
	TALLOC_CTX *mem_ctx;
	struct tevent_req *req;
	int ret;
	bool status;

	mem_ctx = talloc_new(client);
	if (mem_ctx == NULL) {
		return ENOMEM;
	}

	req = ctdb_client_set_message_handler_send(mem_ctx, ev, client,
						   srvid, handler,
						   private_data);
	if (req == NULL) {
		talloc_free(mem_ctx);
		return ENOMEM;
	}

	tevent_req_poll(req, ev);

	status = ctdb_client_set_message_handler_recv(req, &ret);
	if (! status) {
		talloc_free(mem_ctx);
		return ret;
	}

	talloc_free(mem_ctx);
	return 0;
}

int ctdb_client_remove_message_handler(struct tevent_context *ev,
				       struct ctdb_client_context *client,
				       uint64_t srvid, void *private_data)
{
	TALLOC_CTX *mem_ctx;
	struct tevent_req *req;
	int ret;
	bool status;

	mem_ctx = talloc_new(client);
	if (mem_ctx == NULL) {
		return ENOMEM;
	}

	req = ctdb_client_remove_message_handler_send(mem_ctx, ev, client,
						      srvid, private_data);
	if (req == NULL) {
		talloc_free(mem_ctx);
		return ENOMEM;
	}

	tevent_req_poll(req, ev);

	status = ctdb_client_remove_message_handler_recv(req, &ret);
	if (! status) {
		talloc_free(mem_ctx);
		return ret;
	}

	talloc_free(mem_ctx);
	return 0;
}
