/*
   CTDB client code

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
#include <tdb.h>

#include "lib/util/tevent_unix.h"

#include "common/reqid.h"
#include "common/srvid.h"
#include "common/comm.h"

#include "protocol/protocol.h"
#include "protocol/protocol_api.h"

#include "client/client_private.h"
#include "client/client.h"


struct ctdb_tunnel_data {
	struct ctdb_req_header hdr;
	struct ctdb_req_tunnel *tunnel;
	uint32_t reqid;
};

/*
 * Tunnel setup and destroy
 */

struct ctdb_tunnel_setup_state {
	struct ctdb_client_context *client;
	struct ctdb_tunnel_context *tctx;
	uint64_t tunnel_id;
};

static void ctdb_tunnel_setup_register_done(struct tevent_req *subreq);
static void ctdb_tunnel_handler(uint64_t tunnel_id, TDB_DATA data,
				void *private_data);

struct tevent_req *ctdb_tunnel_setup_send(TALLOC_CTX *mem_ctx,
					  struct tevent_context *ev,
					  struct ctdb_client_context *client,
					  uint64_t tunnel_id,
					  ctdb_tunnel_callback_func_t callback,
					  void *private_data)
{
	struct tevent_req *req, *subreq;
	struct ctdb_tunnel_setup_state *state;
	struct ctdb_tunnel_context *tctx;
	struct ctdb_req_control request;
	int ret;

	req = tevent_req_create(mem_ctx, &state,
				struct ctdb_tunnel_setup_state);
	if (req == NULL) {
		return NULL;
	}

	tctx = talloc_zero(client, struct ctdb_tunnel_context);
	if (tevent_req_nomem(tctx, req)) {
		return tevent_req_post(req, ev);
	}

	tctx->client = client;
	tctx->tunnel_id = tunnel_id;
	tctx->callback = callback;
	tctx->private_data = private_data;

	state->client = client;
	state->tunnel_id = tunnel_id;
	state->tctx = tctx;

	ret = srvid_exists(client->tunnels, tunnel_id, NULL);
	if (ret == 0) {
		tevent_req_error(req, EEXIST);
		return tevent_req_post(req, ev);
	}

	ctdb_req_control_tunnel_register(&request, tunnel_id);
	subreq = ctdb_client_control_send(state, ev, client,
					  ctdb_client_pnn(client),
					  tevent_timeval_zero(),
					  &request);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, ctdb_tunnel_setup_register_done, req);

	return req;
}

static void ctdb_tunnel_setup_register_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct ctdb_tunnel_setup_state *state = tevent_req_data(
		req, struct ctdb_tunnel_setup_state);
	struct ctdb_reply_control *reply;
	bool status;
	int ret;

	status = ctdb_client_control_recv(subreq, &ret, state, &reply);
	TALLOC_FREE(subreq);
	if (! status) {
		tevent_req_error(req, ret);
		return;
	}

	ret = ctdb_reply_control_tunnel_register(reply);
	talloc_free(reply);
	if (ret != 0) {
		tevent_req_error(req, ret);
		return;
	}

	ret = srvid_register(state->client->tunnels, state->client,
			     state->tunnel_id,
			     ctdb_tunnel_handler, state->tctx);
	if (ret != 0) {
		tevent_req_error(req, ret);
		return;
	}

	tevent_req_done(req);
}

static void ctdb_tunnel_handler(uint64_t tunnel_id, TDB_DATA data,
				void *private_data)
{
	struct ctdb_tunnel_context *tctx = talloc_get_type_abort(
		private_data, struct ctdb_tunnel_context);
	struct ctdb_tunnel_data *tunnel_data;

	if (tctx->tunnel_id != tunnel_id) {
		return;
	}

	if (data.dsize != sizeof(struct ctdb_tunnel_data)) {
		return;
	}

	tunnel_data = (struct ctdb_tunnel_data *)data.dptr;

	tctx->callback(tctx, tunnel_data->hdr.srcnode, tunnel_data->reqid,
		       tunnel_data->tunnel->data.dptr,
		       tunnel_data->tunnel->data.dsize, tctx->private_data);
}

bool ctdb_tunnel_setup_recv(struct tevent_req *req, int *perr,
			    struct ctdb_tunnel_context **result)
{
	struct ctdb_tunnel_setup_state *state = tevent_req_data(
		req, struct ctdb_tunnel_setup_state);
	int ret;

	if (tevent_req_is_unix_error(req, &ret)) {
		if (perr != NULL) {
			*perr = ret;
		}
		return false;
	}

	*result = state->tctx;
	return true;
}

int ctdb_tunnel_setup(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
		      struct ctdb_client_context *client, uint64_t tunnel_id,
		      ctdb_tunnel_callback_func_t callback, void *private_data,
		      struct ctdb_tunnel_context **result)
{
	struct tevent_req *req;
	int ret;
	bool status;

	req = ctdb_tunnel_setup_send(mem_ctx, ev, client, tunnel_id,
				     callback, private_data);
	if (req == NULL) {
		return ENOMEM;
	}

	tevent_req_poll(req, ev);

	status = ctdb_tunnel_setup_recv(req, &ret, result);
	talloc_free(req);
	if (! status) {
		return ret;
	}

	return 0;
}

struct ctdb_tunnel_destroy_state {
	struct ctdb_tunnel_context *tctx;
};

static void ctdb_tunnel_destroy_deregister_done(struct tevent_req *subreq);

struct tevent_req *ctdb_tunnel_destroy_send(TALLOC_CTX *mem_ctx,
					    struct tevent_context *ev,
					    struct ctdb_tunnel_context *tctx)
{
	struct tevent_req *req, *subreq;
	struct ctdb_tunnel_destroy_state *state;
	struct ctdb_req_control request;

	req = tevent_req_create(mem_ctx, &state,
				struct ctdb_tunnel_destroy_state);
	if (req == NULL) {
		return NULL;
	}

	state->tctx = tctx;

	ctdb_req_control_tunnel_deregister(&request, tctx->tunnel_id);
	subreq = ctdb_client_control_send(state, ev, tctx->client,
					  ctdb_client_pnn(tctx->client),
					  tevent_timeval_zero(),
					  &request);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, ctdb_tunnel_destroy_deregister_done,
				req);

	return req;
}

static void ctdb_tunnel_destroy_deregister_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct ctdb_tunnel_destroy_state *state = tevent_req_data(
		req, struct ctdb_tunnel_destroy_state);
	struct ctdb_client_context *client = state->tctx->client;
	struct ctdb_reply_control *reply;
	bool status;
	int ret;

	status = ctdb_client_control_recv(subreq, &ret, state, &reply);
	TALLOC_FREE(subreq);
	if (! status) {
		tevent_req_error(req, ret);
		return;
	}

	ret = ctdb_reply_control_tunnel_deregister(reply);
	talloc_free(reply);
	if (ret != 0) {
		tevent_req_error(req, ret);
		return;
	}

	ret = srvid_deregister(client->tunnels, state->tctx->tunnel_id,
			       state->tctx);
	if (ret != 0) {
		tevent_req_error(req, ret);
		return;
	}

	tevent_req_done(req);
}

bool ctdb_tunnel_destroy_recv(struct tevent_req *req, int *perr)
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


int ctdb_tunnel_destroy(struct tevent_context *ev,
			struct ctdb_tunnel_context *tctx)
{
	struct tevent_req *req;
	int ret;
	bool status;

	req = ctdb_tunnel_destroy_send(ev, ev, tctx);
	if (req == NULL) {
		return ENOMEM;
	}

	tevent_req_poll(req, ev);

	status = ctdb_tunnel_destroy_recv(req, &ret);
	talloc_free(req);
	if (! status) {
		return ret;
	}

	return 0;
}

/*
 * Callback when REQ_TUNNEL packet is received
 */

static void ctdb_tunnel_request_reply(struct tevent_req *req,
				      struct ctdb_tunnel_data *tunnel_data);

void ctdb_client_req_tunnel(struct ctdb_client_context *client,
			    uint8_t *buf, size_t buflen, uint32_t reqid)
{
	TALLOC_CTX *tmp_ctx = talloc_new(client);
	struct ctdb_req_header h;
	struct ctdb_req_tunnel *tunnel;
	struct tevent_req *req;
	struct ctdb_tunnel_data tunnel_data;
	int ret;

	tunnel = talloc_zero(tmp_ctx, struct ctdb_req_tunnel);
	if (tunnel == NULL) {
		goto fail;
	}

	ret = ctdb_req_tunnel_pull(buf, buflen, &h, tmp_ctx, tunnel);
	if (ret != 0) {
		goto fail;
	}

	tunnel_data = (struct ctdb_tunnel_data) {
		.hdr = h,
		.tunnel = tunnel,
		.reqid = reqid,
	};

	if (tunnel->flags & CTDB_TUNNEL_FLAG_REPLY) {
		req = reqid_find(client->idr, reqid, struct tevent_req);
		if (req == NULL) {
			goto fail;
		}

		ctdb_tunnel_request_reply(req, &tunnel_data);

	} else if (tunnel->flags & CTDB_TUNNEL_FLAG_REQUEST) {

		TDB_DATA data = {
			.dsize = sizeof(struct ctdb_tunnel_data),
			.dptr = (uint8_t *)&tunnel_data,
		};

		srvid_dispatch(client->tunnels, tunnel->tunnel_id, 0, data);
	}

fail:
	TALLOC_FREE(tmp_ctx);
}


/*
 * Send messages using tunnel
 */

struct ctdb_tunnel_request_state {
	struct ctdb_tunnel_context *tctx;
	bool wait_for_reply;
	uint32_t reqid;
	struct ctdb_req_tunnel *tunnel;
};

static int ctdb_tunnel_request_state_destructor(
			struct ctdb_tunnel_request_state *state);
static void ctdb_tunnel_request_done(struct tevent_req *subreq);

struct tevent_req *ctdb_tunnel_request_send(TALLOC_CTX *mem_ctx,
					    struct tevent_context *ev,
					    struct ctdb_tunnel_context *tctx,
					    uint32_t destnode,
					    struct timeval timeout,
					    uint8_t *buf, size_t buflen,
					    bool wait_for_reply)
{
	struct tevent_req *req, *subreq;
	struct ctdb_tunnel_request_state *state;
	struct ctdb_req_tunnel tunnel;
	struct ctdb_req_header h;
	uint8_t *pkt;
	size_t datalen, pkt_len;
	int ret;

	req = tevent_req_create(mem_ctx, &state,
				struct ctdb_tunnel_request_state);
	if (req == NULL) {
		return NULL;
	}

	state->tctx = tctx;
	state->wait_for_reply = wait_for_reply;
	state->reqid = reqid_new(tctx->client->idr, req);
	if (state->reqid == REQID_INVALID) {
		talloc_free(req);
		return NULL;
	}

	talloc_set_destructor(state, ctdb_tunnel_request_state_destructor);

	tunnel = (struct ctdb_req_tunnel) {
		.tunnel_id = state->tctx->tunnel_id,
		.flags = CTDB_TUNNEL_FLAG_REQUEST,
		.data = (TDB_DATA) {
			.dptr = buf,
			.dsize = buflen,
		},
	};

	if (destnode == CTDB_BROADCAST_ALL ||
	    destnode == CTDB_BROADCAST_ACTIVE ||
	    destnode == CTDB_BROADCAST_CONNECTED) {
		state->wait_for_reply = false;
	}
	if (! state->wait_for_reply) {
		tunnel.flags |= CTDB_TUNNEL_FLAG_NOREPLY;
	}

	ctdb_req_header_fill(&h, 0, CTDB_REQ_TUNNEL, destnode,
			     ctdb_client_pnn(state->tctx->client),
			     state->reqid);

	datalen = ctdb_req_tunnel_len(&h, &tunnel);
	ret = ctdb_allocate_pkt(state, datalen, &pkt, &pkt_len);
	if (ret != 0) {
		tevent_req_error(req, ret);
		return tevent_req_post(req, ev);
	}

	ret = ctdb_req_tunnel_push(&h, &tunnel, pkt, &pkt_len);
	if (ret != 0) {
		tevent_req_error(req, ret);
		return tevent_req_post(req, ev);
	}

	if (!tevent_timeval_is_zero(&timeout)) {
		if (!tevent_req_set_endtime(req, ev, timeout)) {
			return tevent_req_post(req, ev);
		}
	}

	subreq = comm_write_send(state, ev, tctx->client->comm,
				 pkt, pkt_len);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, ctdb_tunnel_request_done, req);

	return req;
}

static int ctdb_tunnel_request_state_destructor(
			struct ctdb_tunnel_request_state *state)
{
	reqid_remove(state->tctx->client->idr, state->reqid);
	return 0;
}

static void ctdb_tunnel_request_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct ctdb_tunnel_request_state *state = tevent_req_data(
		req, struct ctdb_tunnel_request_state);
	int ret;
	bool status;

	status = comm_write_recv(subreq, &ret);
	TALLOC_FREE(subreq);
	if (! status) {
		tevent_req_error(req, ret);
		return;
	}

	if (! state->wait_for_reply) {
		tevent_req_done(req);
	}

	/* Wait for the reply or timeout */
}

static void ctdb_tunnel_request_reply(struct tevent_req *req,
				      struct ctdb_tunnel_data *tunnel_data)
{
	struct ctdb_tunnel_request_state *state = tevent_req_data(
		req, struct ctdb_tunnel_request_state);

	if (tunnel_data->reqid != state->reqid) {
		return;
	}

	state->tunnel = talloc_steal(state, tunnel_data->tunnel);
	tevent_req_done(req);
}

bool ctdb_tunnel_request_recv(struct tevent_req *req, int *perr,
			      TALLOC_CTX *mem_ctx, uint8_t **buf,
			      size_t *buflen)
{
	struct ctdb_tunnel_request_state *state = tevent_req_data(
		req, struct ctdb_tunnel_request_state);
	int ret;

	if (tevent_req_is_unix_error(req, &ret)) {
		if (perr != NULL) {
			*perr = ret;
		}
		return false;
	}

	if (state->wait_for_reply) {
		if (buf != NULL) {
			*buf = talloc_steal(mem_ctx, state->tunnel->data.dptr);
		}
		if (buflen != NULL) {
			*buflen = state->tunnel->data.dsize;
		}
	}

	return true;
}

int ctdb_tunnel_request(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
			struct ctdb_tunnel_context *tctx, uint32_t destnode,
			struct timeval timeout, uint8_t *buf, size_t buflen,
			bool wait_for_reply)
{
	struct tevent_req *req;
	int ret;
	bool status;

	req = ctdb_tunnel_request_send(mem_ctx, ev, tctx, destnode,
				       timeout, buf, buflen, wait_for_reply);
	if (req == NULL) {
		return ENOMEM;
	}

	tevent_req_poll(req, ev);

	status = ctdb_tunnel_request_recv(req, &ret, NULL, NULL, NULL);
	talloc_free(req);
	if (! status) {
		return ret;
	}

	return 0;
}

struct ctdb_tunnel_reply_state {
};

static void ctdb_tunnel_reply_done(struct tevent_req *subreq);

struct tevent_req *ctdb_tunnel_reply_send(TALLOC_CTX *mem_ctx,
					  struct tevent_context *ev,
					  struct ctdb_tunnel_context *tctx,
					  uint32_t destnode, uint32_t reqid,
					  struct timeval timeout,
					  uint8_t *buf, size_t buflen)
{
	struct tevent_req *req, *subreq;
	struct ctdb_tunnel_reply_state *state;
	struct ctdb_req_tunnel tunnel;
	struct ctdb_req_header h;
	uint8_t *pkt;
	size_t datalen, pkt_len;
	int ret;

	req = tevent_req_create(mem_ctx, &state,
				struct ctdb_tunnel_reply_state);
	if (req == NULL) {
		return NULL;
	}

	tunnel = (struct ctdb_req_tunnel) {
		.tunnel_id = tctx->tunnel_id,
		.flags = CTDB_TUNNEL_FLAG_REPLY,
		.data = (TDB_DATA) {
			.dptr = buf,
			.dsize = buflen,
		},
	};

	ctdb_req_header_fill(&h, 0, CTDB_REQ_TUNNEL, destnode,
			     ctdb_client_pnn(tctx->client), reqid);

	datalen = ctdb_req_tunnel_len(&h, &tunnel);
	ret = ctdb_allocate_pkt(state, datalen, &pkt, &pkt_len);
	if (ret != 0) {
		tevent_req_error(req, ret);
		return tevent_req_post(req, ev);
	}

	ret = ctdb_req_tunnel_push(&h, &tunnel, pkt, &pkt_len);
	if (ret != 0) {
		tevent_req_error(req, ret);
		return tevent_req_post(req, ev);
	}

	if (!tevent_timeval_is_zero(&timeout)) {
		if (!tevent_req_set_endtime(req, ev, timeout)) {
			return tevent_req_post(req, ev);
		}
	}

	subreq = comm_write_send(state, ev, tctx->client->comm, pkt, pkt_len);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, ctdb_tunnel_reply_done, req);

	return req;
}

static void ctdb_tunnel_reply_done(struct tevent_req *subreq)
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

bool ctdb_tunnel_reply_recv(struct tevent_req *req, int *perr)
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

int ctdb_tunnel_reply(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
		      struct ctdb_tunnel_context *tctx, uint32_t destnode,
		      uint32_t reqid, struct timeval timeout,
		      uint8_t *buf, size_t buflen)
{
	struct tevent_req *req;
	int ret;
	bool status;

	req = ctdb_tunnel_reply_send(mem_ctx, ev, tctx, destnode, reqid,
				     timeout, buf, buflen);
	if (req == NULL) {
		return ENOMEM;
	}

	tevent_req_poll(req, ev);

	status = ctdb_tunnel_reply_recv(req, &ret);
	talloc_free(req);
	if (! status) {
		return ret;
	}

	return 0;
}
