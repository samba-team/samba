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
 * Handle REQ_CALL and REPLY_CALL
 */

struct ctdb_client_call_state {
	struct ctdb_client_context *client;
	uint32_t reqid;
	struct ctdb_reply_call *reply;
	struct tevent_req *req;
};

static int ctdb_client_call_state_destructor(
	struct ctdb_client_call_state *state);
static void ctdb_client_call_done(struct tevent_req *subreq);

struct tevent_req *ctdb_client_call_send(TALLOC_CTX *mem_ctx,
					 struct tevent_context *ev,
					 struct ctdb_client_context *client,
					 struct ctdb_req_call *request)
{
	struct ctdb_req_header h;
	struct tevent_req *req, *subreq;
	struct ctdb_client_call_state *state;
	uint32_t reqid;
	uint8_t *buf;
	size_t datalen, buflen;
	int ret;

	req = tevent_req_create(mem_ctx, &state,
				struct ctdb_client_call_state);
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
	state->req = req;
	state->reply = talloc_zero(state, struct ctdb_reply_call);
	if (tevent_req_nomem(state->reply, req)) {
		return tevent_req_post(req, ev);
	}

	talloc_set_destructor(state, ctdb_client_call_state_destructor);

	ctdb_req_header_fill(&h, 0, CTDB_REQ_CALL, CTDB_CURRENT_NODE,
			     client->pnn, reqid);

	datalen = ctdb_req_call_len(&h, request);
	ret = ctdb_allocate_pkt(state, datalen, &buf, &buflen);
	if (ret != 0) {
		tevent_req_error(req, ret);
		return tevent_req_post(req, ev);
	}

	ret = ctdb_req_call_push(&h, request, buf, &buflen);
	if (ret != 0) {
		tevent_req_error(req, ret);
		return tevent_req_post(req, ev);
	}

	subreq = comm_write_send(state, ev, client->comm, buf, buflen);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, ctdb_client_call_done, req);

	return req;
}

static int ctdb_client_call_state_destructor(
	struct ctdb_client_call_state *state)
{
	reqid_remove(state->client->idr, state->reqid);
	return 0;
}

static void ctdb_client_call_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	bool status;
	int ret;

	status = comm_write_recv(subreq, &ret);
	TALLOC_FREE(subreq);
	if (! status) {
		tevent_req_error(req, ret);
		return;
	}

	/* wait for the reply */
}

void ctdb_client_reply_call(struct ctdb_client_context *client,
			    uint8_t *buf, size_t buflen, uint32_t reqid)
{
	struct ctdb_req_header h;
	struct ctdb_client_call_state *state;
	int ret;

	state = reqid_find(client->idr, reqid, struct ctdb_client_call_state);
	if (state == NULL) {
		return;
	}

	if (reqid != state->reqid) {
		return;
	}

	ret = ctdb_reply_call_pull(buf, buflen, &h, state, state->reply);
	if (ret != 0) {
		tevent_req_error(state->req, ret);
		return;
	}

	tevent_req_done(state->req);
}

bool ctdb_client_call_recv(struct tevent_req *req, TALLOC_CTX *mem_ctx,
			   struct ctdb_reply_call **reply, int *perr)
{
	struct ctdb_client_call_state *state = tevent_req_data(
		req, struct ctdb_client_call_state);
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
