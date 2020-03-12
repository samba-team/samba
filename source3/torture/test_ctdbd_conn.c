/*
 * Unix SMB/CIFS implementation.
 * Test async ctdb_req_send/recv
 * Copyright (C) Volker Lendecke 2020
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "includes.h"
#include "torture/proto.h"
#include "ctdbd_conn.h"
#include "lib/cluster_support.h"
#include "ctdb/include/ctdb_protocol.h"
#include "lib/util/tevent_unix.h"

extern int torture_nprocs;
extern int torture_numops;

struct ctdb_echo_state {
	struct ctdb_req_control_old req;
	struct iovec iov[2];
	TDB_DATA echodata;
};

static void ctdb_echo_done(struct tevent_req *subreq);

static struct tevent_req *ctdb_echo_send(
	TALLOC_CTX *mem_ctx,
	struct tevent_context *ev,
	struct ctdbd_connection *conn,
	uint32_t delay)
{
	struct tevent_req *req = NULL, *subreq = NULL;
	struct ctdb_echo_state *state = NULL;
	struct ctdb_req_header *hdr = NULL;
	uint32_t datalen;

	req = tevent_req_create(
		mem_ctx, &state, struct ctdb_echo_state);
	if (req == NULL) {
		return NULL;
	}

	hdr = &state->req.hdr;
	ctdbd_prep_hdr_next_reqid(conn, hdr);
	hdr->operation = CTDB_REQ_CONTROL;
	state->req.opcode = CTDB_CONTROL_ECHO_DATA;

	state->iov[0] = (struct iovec) {
		.iov_base = &state->req,
		.iov_len = offsetof(struct ctdb_req_control_old, data),
	};

	datalen = generate_random() % 1024;

	state->echodata.dptr = talloc_array(state, uint8_t, datalen+8);
	if (tevent_req_nomem(state->echodata.dptr, req)) {
		return tevent_req_post(req, ev);
	}
	state->echodata.dsize = talloc_get_size(state->echodata.dptr);
	generate_random_buffer(
		state->echodata.dptr, state->echodata.dsize);

	memcpy(state->echodata.dptr, &delay, sizeof(delay));
	memcpy(state->echodata.dptr+4, &datalen, sizeof(datalen));

	state->req.datalen = state->echodata.dsize;

	state->iov[1] = (struct iovec) {
		.iov_base = state->echodata.dptr,
		.iov_len = state->echodata.dsize,
	};

	hdr->length =
		offsetof(struct ctdb_req_control_old, data) +
		state->req.datalen;

	subreq = ctdbd_req_send(
		state, ev, conn, state->iov, ARRAY_SIZE(state->iov));
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, ctdb_echo_done, req);

	return req;
}

static void ctdb_echo_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct ctdb_echo_state *state = tevent_req_data(
		req, struct ctdb_echo_state);
	struct ctdb_req_header *hdr = NULL;
	struct ctdb_reply_control_old *reply = NULL;
	int cmp, ret;

	ret = ctdbd_req_recv(subreq, state, &hdr);
	TALLOC_FREE(subreq);
	if (tevent_req_error(req, ret)) {
		printf("ctdbd_req_recv(%"PRIu32") returned %d (%s)\n",
		       state->req.hdr.reqid,
		       ret,
		       strerror(ret));
		return;
	}
	if (hdr->operation != CTDB_REPLY_CONTROL) {
		printf("Expected CTDB_REPLY_CONTROL, got %"PRIu32"\n",
		       hdr->operation);
		tevent_req_error(req, EIO);
		return;
	}
	reply = (struct ctdb_reply_control_old *)hdr;
	if (reply->status != 0) {
		printf("reply->status = %"PRIi32"\n", reply->status);
		tevent_req_error(req, EIO);
		return;
	}
	if (reply->datalen != state->req.datalen) {
		printf("state->echodata.dsize=%zu datalen=%"PRIu32"\n",
		       state->echodata.dsize,
		       reply->datalen);
		tevent_req_error(req, EIO);
		return;
	}
	cmp = memcmp(reply->data,
		     state->echodata.dptr,
		     state->echodata.dsize);
	if (cmp != 0) {
		printf("data mismatch\n");
		tevent_req_error(req, EIO);
		return;
	}
	TALLOC_FREE(reply);
	tevent_req_done(req);
}

static int ctdb_echo_recv(struct tevent_req *req)
{
	return tevent_req_simple_recv_unix(req);
}

struct ctdb_ping_flood_state {
	struct tevent_context *ev;
	struct ctdbd_connection *conn;
	size_t num_running;
	bool done;
};

static void ctdb_ping_flood_next(struct tevent_req *subreq);
static void ctdb_ping_flood_done(struct tevent_req *subreq);

static struct tevent_req *ctdb_ping_flood_send(
	TALLOC_CTX *mem_ctx,
	struct tevent_context *ev,
	struct ctdbd_connection *conn,
	size_t num_parallel,
	unsigned usecs)
{
	struct tevent_req *req = NULL, *subreq = NULL;
	struct ctdb_ping_flood_state *state = NULL;
	size_t i;

	req = tevent_req_create(
		mem_ctx, &state, struct ctdb_ping_flood_state);
	if (req == NULL) {
		return NULL;
	}
	state->ev = ev;
	state->conn = conn;

	for (i=0; i<num_parallel; i++) {
		subreq = ctdb_echo_send(
			state,
			state->ev,
			state->conn,
			generate_random() % 10);
		if (tevent_req_nomem(subreq, req)) {
			return tevent_req_post(req, ev);
		}
		tevent_req_set_callback(subreq, ctdb_ping_flood_next, req);
	}
	state->num_running = num_parallel;

	subreq = tevent_wakeup_send(
		state,
		ev,
		tevent_timeval_current_ofs(0, usecs));
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, ctdb_ping_flood_done, req);

	return req;
}

static void ctdb_ping_flood_next(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct ctdb_ping_flood_state *state = tevent_req_data(
		req, struct ctdb_ping_flood_state);
	int ret;

	ret = ctdb_echo_recv(subreq);
	TALLOC_FREE(subreq);
	if (tevent_req_error(req, ret)) {
		return;
	}
	state->num_running -= 1;

	if (state->done) {
		if (state->num_running == 0) {
			tevent_req_done(req);
		}
		return;
	}

	subreq = ctdb_echo_send(
		state,
		state->ev,
		state->conn,
		generate_random() % 10);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, ctdb_ping_flood_next, req);
	state->num_running += 1;
}

static void ctdb_ping_flood_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct ctdb_ping_flood_state *state = tevent_req_data(
		req, struct ctdb_ping_flood_state);
	bool ok;

	ok = tevent_wakeup_recv(subreq);
	TALLOC_FREE(subreq);
	if (!ok) {
		tevent_req_oom(req);
		return;
	}
	state->done = true;
}

static int ctdb_ping_flood_recv(struct tevent_req *req)
{
	return tevent_req_simple_recv_unix(req);
}

bool run_ctdbd_conn1(int dummy)
{
	struct ctdbd_connection *conn = NULL;
	struct tevent_context *ev = NULL;
	struct tevent_req *req = NULL;
	int ret;
	bool ok;
	bool result = false;

	ev = samba_tevent_context_init(talloc_tos());
	if (ev == NULL) {
		printf("samba_tevent_context_init failed\n");
		goto done;
	}

	ret = ctdbd_init_async_connection(
		ev, lp_ctdbd_socket(), 0, &conn);
	if (ret != 0) {
		printf("ctdbd_init_async_connection failed: %s\n",
		       strerror(ret));
		goto done;
	}

	req = ctdb_ping_flood_send(
		ev, ev, conn, torture_nprocs, torture_numops * 1000);
	if (req == NULL) {
		printf("ctdb_ping_flood_send failed\n");
		goto done;
	}

	ok = tevent_req_poll_unix(req, ev, &ret);
	if (!ok) {
		printf("tevent_req_poll_unix failed: %s\n",
		       strerror(ret));
		goto done;
	}

	ret = ctdb_ping_flood_recv(req);
	TALLOC_FREE(req);
	if (ret != 0) {
		printf("ctdb_ping_flood failed: %s\n", strerror(ret));
		goto done;
	}

	result = true;
done:
	TALLOC_FREE(conn);
	return result;
}
