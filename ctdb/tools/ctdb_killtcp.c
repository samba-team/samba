/*
   CTDB TCP connection killing utility

   Copyright (C) Martin Schwenke <martin@meltin.net> 2016

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

#include "protocol/protocol.h"
#include "protocol/protocol_util.h"

#include "common/db_hash.h"
#include "common/system_socket.h"
#include "common/logging.h"


struct reset_connections_state {
	struct tevent_context *ev;
	int capture_fd;
	struct tevent_fd *fde;
	struct db_hash_context *connections;
	void *private_data;
	unsigned int attempts;
	unsigned int max_attempts;
	struct timeval retry_interval;
	unsigned int batch_count;
	unsigned int batch_size;
};


static void reset_connections_capture_tcp_handler(struct tevent_context *ev,
						  struct tevent_fd *fde,
						  uint16_t flags,
						  void *private_data);
static void reset_connections_batch(struct tevent_req *subreq);
static int reset_connections_tickle_connection(
					uint8_t *keybuf, size_t keylen,
					uint8_t *databuf, size_t datalen,
					void *private_data);

static struct tevent_req *reset_connections_send(
			      TALLOC_CTX *mem_ctx,
			      struct tevent_context *ev,
			      const char *iface,
			      struct ctdb_connection_list *conn_list)
{
	struct tevent_req *req, *subreq;
	struct reset_connections_state *state;
	unsigned int i;
	int ret;

	req = tevent_req_create(mem_ctx, &state,
				struct reset_connections_state);
	if (req == NULL) {
		return NULL;
	}

	state->ev = ev;

	if (conn_list->num == 0) {
		/* No connections, done! */
		tevent_req_done(req);
		return tevent_req_post(req, ev);
	}

	ret = db_hash_init(state, "connections", 2048, DB_HASH_SIMPLE,
			   &state->connections);
	if (ret != 0) {
		D_ERR("Failed to initialise connection hash (%s)\n",
		      strerror(ret));
		tevent_req_error(req, ret);
		return tevent_req_post(req, ev);
	}

	DBG_DEBUG("Adding %u connections to hash\n", conn_list->num);
	for (i = 0; i < conn_list->num; i++) {
		struct ctdb_connection *c = &conn_list->conn[i];

		DBG_DEBUG("Adding connection to hash: %s\n",
			  ctdb_connection_to_string(conn_list, c, true));

		/* Connection is stored as a key in the connections hash */
		ret = db_hash_add(state->connections,
				  (uint8_t *)discard_const(c), sizeof(*c),
				  NULL, 0);
		if (ret != 0) {
			D_ERR("Error adding connection to hash (%s)\n",
			      strerror(ret));
			tevent_req_error(req, ret);
			return tevent_req_post(req, ev);
		}
	}

	state->attempts = 0;
	state->max_attempts = 50;

	state->retry_interval.tv_sec = 0;
	state->retry_interval.tv_usec = 100 * 1000;

	state->batch_count = 0;
	state->batch_size = 300;

	state->capture_fd =
		ctdb_sys_open_capture_socket(iface, &state->private_data);
	if (state->capture_fd == -1) {
		D_ERR("Failed to open capture socket on iface '%s' (%s)\n",
		      iface, strerror(errno));
			tevent_req_error(req, EIO);
			return tevent_req_post(req, ev);
	}

	state->fde = tevent_add_fd(ev, state, state->capture_fd,
				   TEVENT_FD_READ,
				   reset_connections_capture_tcp_handler,
				   state);
	if (tevent_req_nomem(state->fde, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_fd_set_auto_close(state->fde);

	subreq = tevent_wakeup_send(state, ev, tevent_timeval_current_ofs(0,0));
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, reset_connections_batch, req);

	return req;
}

/*
  called when we get a read event on the raw socket
 */
static void reset_connections_capture_tcp_handler(struct tevent_context *ev,
						  struct tevent_fd *fde,
						  uint16_t flags,
						  void *private_data)
{
	struct reset_connections_state *state = talloc_get_type_abort(
		private_data, struct reset_connections_state);
	/* 0 the parts that don't get set by ctdb_sys_read_tcp_packet */
	struct ctdb_connection conn;
	uint32_t ack_seq, seq;
	int rst;
	uint16_t window;
	int ret;

	ret = ctdb_sys_read_tcp_packet(state->capture_fd,
				       state->private_data,
				       &conn.server, &conn.client,
				       &ack_seq, &seq, &rst, &window);
	if (ret != 0) {
		/* probably a non-tcp ACK packet */
		return;
	}

	if (window == htons(1234) && (rst || seq == 0)) {
		/* Ignore packets that we sent! */
		D_DEBUG("Ignoring packet: %s, "
			"seq=%"PRIu32", ack_seq=%"PRIu32", "
			"rst=%d, window=%"PRIu16"\n",
			ctdb_connection_to_string(state, &conn, false),
			seq, ack_seq, rst, ntohs(window));
		return;
	}

	/* Check if this connection is one being reset, if found then delete */
	ret = db_hash_delete(state->connections,
			     (uint8_t*)&conn, sizeof(conn));
	if (ret == ENOENT) {
		/* Packet for some other connection, ignore */
		DBG_DEBUG("Ignoring packet for unknown connection: %s\n",
			  ctdb_connection_to_string(state, &conn, true));
		return;
	}
	if (ret != 0) {
		DBG_WARNING("Internal error (%s)\n", strerror(ret));
		return;
	}

	D_INFO("Sending a TCP RST to for connection %s\n",
	       ctdb_connection_to_string(state, &conn, true));

	ret = ctdb_sys_send_tcp(&conn.server, &conn.client, ack_seq, seq, 1);
	if (ret != 0) {
		DBG_ERR("Error sending TCP RST for connection\n");
	}
}

/*
 * Called periodically until all sentenced connections have been reset
 * or enough attempts have been made
 */
static void reset_connections_batch(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct reset_connections_state *state = tevent_req_data(
		req, struct reset_connections_state);
	bool status;
	int count, ret;

	status = tevent_wakeup_recv(subreq);
	TALLOC_FREE(subreq);

	if (! status) {
		DBG_WARNING("Unexpected error on timer expiry\n");
		/* Keep going... */
	}

	/* loop over up to batch_size connections sending tickle ACKs */
	state->batch_count = 0;
	ret = db_hash_traverse(state->connections,
			       reset_connections_tickle_connection,
			       state, NULL);
	if (ret != 0) {
		DBG_WARNING("Unexpected error traversing connections (%s)\n",
			    strerror(ret));
	}

	state->attempts++;

	/*
	 * If there are no more connections to kill or we have tried
	 * too many times we're finished
	 */
	ret = db_hash_traverse(state->connections, NULL, NULL, &count);
	if (ret != 0) {
		/* What now?  Try again until max_attempts reached */
		DBG_WARNING("Unexpected error traversing connections (%s)\n",
			    strerror(ret));
		count = 1;
	}
	if (count == 0 ||
	    state->attempts >= state->max_attempts) {
		tevent_req_done(req);
		return;
	}

	/* Schedule next attempt */
	subreq = tevent_wakeup_send(state, state->ev,
				    tevent_timeval_current_ofs(
					    state->retry_interval.tv_sec,
					    state->retry_interval.tv_usec));
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, reset_connections_batch, req);
}

static int reset_connections_tickle_connection(
					uint8_t *keybuf, size_t keylen,
					uint8_t *databuf, size_t datalen,
					void *private_data)
{
	struct reset_connections_state *state = talloc_get_type_abort(
		private_data, struct reset_connections_state);
	struct ctdb_connection *conn;
	int ret;

	if (keylen != sizeof(*conn)) {
		DBG_WARNING("Unexpected data in connection hash\n");
		return 0;
	}

	conn = (struct ctdb_connection *)keybuf;

	state->batch_count++;
	if (state->batch_count > state->batch_size) {
		/* Terminate the traverse */
		return 1;
	}

	DBG_DEBUG("Sending tickle ACK for connection '%s'\n",
		  ctdb_connection_to_string(state, conn, true));
	ret = ctdb_sys_send_tcp(&conn->server, &conn->client, 0, 0, 0);
	if (ret != 0) {
		DBG_ERR("Error sending tickle ACK\n");
		/* continue */
	}

	return 0;
}

static bool reset_connections_recv(struct tevent_req *req, int *perr)
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

static void usage(const char *prog)
{
	printf("usage: %s <interface> [ <srcip:port> <dstip:port> ]\n", prog);
	exit(1);
}

int main(int argc, char **argv)
{
	struct ctdb_connection conn;
	struct tevent_context *ev = NULL;
	TALLOC_CTX *mem_ctx = NULL;
	struct ctdb_connection_list *conn_list = NULL;
	const char *t;
	struct tevent_req *req;
	int debug_level;
	bool status;
	bool ok;
	int ret;

	/* Set the debug level */
	t = getenv("CTDB_DEBUGLEVEL");
	if (t != NULL) {
		ok = debug_level_parse(t, &debug_level);
		if (!ok) {
			debug_level = DEBUG_ERR;
		}
		debuglevel_set(debug_level);
	}

	if (argc != 2 && argc != 4) {
		usage(argv[0]);
	}

	if (argc == 4) {
		ret = ctdb_sock_addr_from_string(argv[2], &conn.client, true);
		if (ret != 0) {
			D_ERR("Bad IP:port '%s'\n", argv[2]);
			goto fail;
		}

		ret = ctdb_sock_addr_from_string(argv[3], &conn.server, true);
		if (ret != 0) {
			D_ERR("Bad IP:port '%s'\n", argv[3]);
			goto fail;
		}


		conn_list = talloc_zero(mem_ctx, struct ctdb_connection_list);
		if (conn_list == NULL) {
			ret = ENOMEM;
			DBG_ERR("Internal error (%s)\n", strerror(ret));
			goto fail;
		}
		ret = ctdb_connection_list_add(conn_list, &conn);
		if (ret != 0) {
			DBG_ERR("Internal error (%s)\n", strerror(ret));
			goto fail;
		}
	} else {
		ret = ctdb_connection_list_read(mem_ctx, 0, true, &conn_list);
		if (ret != 0) {
			D_ERR("Unable to parse connections (%s)\n",
			      strerror(ret));
			goto fail;
		}
	}

	mem_ctx = talloc_new(NULL);
	if (mem_ctx == NULL) {
		DEBUG(DEBUG_ERR, (__location__ " out of memory\n"));
		goto fail;
	}

	ev = tevent_context_init(mem_ctx);
	if (ev == NULL) {
		DEBUG(DEBUG_ERR, ("Failed to initialise tevent\n"));
		goto fail;
	}

	req = reset_connections_send(mem_ctx, ev, argv[1], conn_list);
	if (req == NULL) {
		goto fail;
	}

	tevent_req_poll(req, ev);

	status = reset_connections_recv(req, &ret);
	if (! status) {
		D_ERR("Failed to kill connections (%s)\n", strerror(ret));
		goto fail;
	}

	talloc_free(mem_ctx);

	return 0;

fail:
	TALLOC_FREE(mem_ctx);
	return -1;
}
