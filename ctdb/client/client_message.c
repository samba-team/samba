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
	size_t buflen;
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

	ret = ctdb_req_message_push(&h, message, state, &buf, &buflen);
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

int ctdb_client_set_message_handler(TALLOC_CTX *mem_ctx,
				    struct tevent_context *ev,
				    struct ctdb_client_context *client,
				    uint64_t srvid, srvid_handler_fn handler,
				    void *private_data)
{
	int ret;

	ret = ctdb_ctrl_register_srvid(mem_ctx, ev, client, client->pnn,
				       tevent_timeval_zero(), srvid);
	if (ret != 0) {
		return ret;
	}

	return srvid_register(client->srv, client, srvid,
			      handler, private_data);
}

int ctdb_client_remove_message_handler(TALLOC_CTX *mem_ctx,
				       struct tevent_context *ev,
				       struct ctdb_client_context *client,
				       uint64_t srvid, void *private_data)
{
	int ret;

	ret = ctdb_ctrl_deregister_srvid(mem_ctx, ev, client, client->pnn,
					 tevent_timeval_zero(), srvid);
	if (ret != 0) {
		return ret;
	}

	return srvid_deregister(client->srv, srvid, private_data);
}
