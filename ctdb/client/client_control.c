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
 * Handle REQ_CONTROL and REPLY_CONTROL
 */

struct ctdb_client_control_state {
	struct ctdb_client_context *client;
	uint32_t opcode;
	uint32_t flags;
	uint32_t reqid;
	struct ctdb_reply_control *reply;
	struct tevent_req *req;
};

static int ctdb_client_control_state_destructor(
	struct ctdb_client_control_state *state);
static void ctdb_client_control_done(struct tevent_req *subreq);

struct tevent_req *ctdb_client_control_send(TALLOC_CTX *mem_ctx,
					    struct tevent_context *ev,
					    struct ctdb_client_context *client,
					    uint32_t destnode,
					    struct timeval timeout,
					    struct ctdb_req_control *request)
{
	struct ctdb_req_header h;
	struct tevent_req *req, *subreq;
	struct ctdb_client_control_state *state;
	uint32_t reqid;
	uint8_t *buf;
	size_t datalen, buflen;
	int ret;

	req = tevent_req_create(mem_ctx, &state,
				struct ctdb_client_control_state);
	if (req == NULL) {
		return NULL;
	}

	reqid = reqid_new(client->idr, state);
	if (reqid == REQID_INVALID) {
		talloc_free(req);
		return NULL;
	}

	state->client = client;
	state->flags = request->flags;
	state->opcode = request->opcode;
	state->reqid = reqid;
	state->req = req;
	state->reply = talloc_zero(state, struct ctdb_reply_control);
	if (tevent_req_nomem(state->reply, req)) {
		return tevent_req_post(req, ev);
	}
	state->reply->rdata.opcode = request->rdata.opcode;

	talloc_set_destructor(state, ctdb_client_control_state_destructor);

	ctdb_req_header_fill(&h, 0, CTDB_REQ_CONTROL, destnode,
			     client->pnn, reqid);

	datalen = ctdb_req_control_len(&h, request);
	ret = ctdb_allocate_pkt(state, datalen, &buf, &buflen);
	if (ret != 0) {
		tevent_req_error(req, ret);
		return tevent_req_post(req, ev);
	}

	ret = ctdb_req_control_push(&h, request, buf, &buflen);
	if (ret != 0) {
		tevent_req_error(req, ret);
		return tevent_req_post(req, ev);
	}

	if (!tevent_timeval_is_zero(&timeout)) {
		if (!tevent_req_set_endtime(req, ev, timeout)) {
			return tevent_req_post(req, ev);
		}
	}

	subreq = comm_write_send(state, ev, client->comm, buf, buflen);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, ctdb_client_control_done, req);

	return req;
}

static int ctdb_client_control_state_destructor(
	struct ctdb_client_control_state *state)
{
	reqid_remove(state->client->idr, state->reqid);
	return 0;
}

static void ctdb_client_control_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct ctdb_client_control_state *state = tevent_req_data(
		req, struct ctdb_client_control_state);
	bool status;
	int ret;

	status = comm_write_recv(subreq, &ret);
	TALLOC_FREE(subreq);
	if (! status) {
		tevent_req_error(req, ret);
		return;
	}

	/* Daemon will not reply, so we set status to 0 */
	if (state->flags & CTDB_CTRL_FLAG_NOREPLY) {
		state->reply->status = 0;
		tevent_req_done(req);
	}

	/* wait for the reply or timeout */
}

void ctdb_client_reply_control(struct ctdb_client_context *client,
			       uint8_t *buf, size_t buflen, uint32_t reqid)
{
	struct ctdb_req_header h;
	struct ctdb_client_control_state *state;
	int ret;

	state = reqid_find(client->idr, reqid,
			   struct ctdb_client_control_state);
	if (state == NULL) {
		return;
	}

	if (reqid != state->reqid) {
		return;
	}

	ret = ctdb_reply_control_pull(buf, buflen, state->opcode, &h,
				      state->reply, state->reply);
	if (ret != 0) {
		tevent_req_error(state->req, ret);
		return;
	}

	tevent_req_done(state->req);
}

bool ctdb_client_control_recv(struct tevent_req *req, int *perr,
			      TALLOC_CTX *mem_ctx,
			      struct ctdb_reply_control **reply)
{
	struct ctdb_client_control_state *state = tevent_req_data(
		req, struct ctdb_client_control_state);
	int err;

	if (tevent_req_is_unix_error(req, &err)) {
		if (perr != NULL) {
			*perr = err;
		}
		return false;
	}

	if (reply != NULL) {
		*reply = talloc_steal(mem_ctx, state->reply);
	}

	return true;
}

/*
 * Handle multiple nodes - there cannot be any return data
 */

struct ctdb_client_control_multi_state {
	uint32_t *pnn_list;
	int count;
	int done;
	int err;
	int *err_list;
	struct ctdb_reply_control **reply;
};

struct control_index_state {
	struct tevent_req *req;
	int index;
};

static void ctdb_client_control_multi_done(struct tevent_req *subreq);

struct tevent_req *ctdb_client_control_multi_send(
				TALLOC_CTX *mem_ctx,
				struct tevent_context *ev,
				struct ctdb_client_context *client,
				uint32_t *pnn_list, int count,
				struct timeval timeout,
				struct ctdb_req_control *request)
{
	struct tevent_req *req, *subreq;
	struct ctdb_client_control_multi_state *state;
	int i;

	if (pnn_list == NULL || count == 0) {
		return NULL;
	}

	req = tevent_req_create(mem_ctx, &state,
				struct ctdb_client_control_multi_state);
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
	state->reply = talloc_zero_array(state, struct ctdb_reply_control *,
					 count);
	if (tevent_req_nomem(state->reply, req)) {
		return tevent_req_post(req, ev);
	}

	for (i=0; i<count; i++) {
		struct control_index_state *substate;

		subreq = ctdb_client_control_send(state, ev, client,
						  pnn_list[i], timeout,
						  request);
		if (tevent_req_nomem(subreq, req)) {
			return tevent_req_post(req, ev);
		}

		substate = talloc(subreq, struct control_index_state);
		if (tevent_req_nomem(substate, req)) {
			return tevent_req_post(req, ev);
		}

		substate->req = req;
		substate->index = i;

		tevent_req_set_callback(subreq, ctdb_client_control_multi_done,
					substate);
	}

	return req;
}

static void ctdb_client_control_multi_done(struct tevent_req *subreq)
{
	struct control_index_state *substate = tevent_req_callback_data(
		subreq, struct control_index_state);
	struct tevent_req *req = substate->req;
	int idx = substate->index;
	struct ctdb_client_control_multi_state *state = tevent_req_data(
		req, struct ctdb_client_control_multi_state);
	bool status;
	int ret;

	status = ctdb_client_control_recv(subreq, &ret, state->reply,
					  &state->reply[idx]);
	TALLOC_FREE(subreq);
	if (! status) {
		if (state->err == 0) {
			state->err = ret;
			state->err_list[idx] = state->err;
		}
	} else {
		if (state->reply[idx]->status != 0) {
			if (state->err == 0) {
				state->err = state->reply[idx]->status;
				state->err_list[idx] = state->err;
			}
		}
	}

	state->done += 1;

	if (state->done == state->count) {
		tevent_req_done(req);
	}
}

bool ctdb_client_control_multi_recv(struct tevent_req *req, int *perr,
				    TALLOC_CTX *mem_ctx, int **perr_list,
				    struct ctdb_reply_control ***preply)
{
	struct ctdb_client_control_multi_state *state = tevent_req_data(
		req, struct ctdb_client_control_multi_state);
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

	if (preply != NULL) {
		*preply = talloc_steal(mem_ctx, state->reply);
	}

	if (state->err != 0) {
		return false;
	}

	return true;
}

int ctdb_client_control_multi_error(uint32_t *pnn_list, int count,
				    int *err_list, uint32_t *pnn)
{
	int ret = 0, i;

	for (i=0; i<count; i++) {
		if (err_list[i] != 0) {
			ret = err_list[i];
			*pnn = pnn_list[i];
		}
	}

	return ret;
}

/*
 * Sync version of control send/recv
 */

int ctdb_client_control(TALLOC_CTX *mem_ctx,
			struct tevent_context *ev,
			struct ctdb_client_context *client,
			uint32_t destnode,
			struct timeval timeout,
			struct ctdb_req_control *request,
			struct ctdb_reply_control **reply)
{
	struct tevent_req *req;
	int ret;
	bool status;

	req = ctdb_client_control_send(mem_ctx, ev, client, destnode, timeout,
				       request);
	if (req == NULL) {
		return ENOMEM;
	}

	tevent_req_poll(req, ev);

	status = ctdb_client_control_recv(req, &ret, mem_ctx, reply);
	if (! status) {
		return ret;
	}

	return 0;
}

int ctdb_client_control_multi(TALLOC_CTX *mem_ctx,
			      struct tevent_context *ev,
			      struct ctdb_client_context *client,
			      uint32_t *pnn_list, int count,
			      struct timeval timeout,
			      struct ctdb_req_control *request,
			      int **perr_list,
			      struct ctdb_reply_control ***preply)
{
	struct tevent_req *req;
	bool status;
	int ret;

	req = ctdb_client_control_multi_send(mem_ctx, ev, client,
					     pnn_list, count,
					     timeout, request);
	if (req == NULL) {
		return ENOMEM;
	}

	tevent_req_poll(req, ev);

	status = ctdb_client_control_multi_recv(req, &ret, mem_ctx, perr_list,
						preply);
	if (! status) {
		return ret;
	}

	return 0;
}
