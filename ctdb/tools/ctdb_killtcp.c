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

#include <talloc.h>
#include <tevent.h>

#include "replace.h"
#include "system/network.h"

#include "lib/util/debug.h"

#include "protocol/protocol.h"
#include "protocol/protocol_util.h"

#include "common/db_hash.h"
#include "common/system.h"
#include "common/logging.h"


/* Contains the listening socket and the list of TCP connections to
 * kill */
struct ctdb_kill_tcp {
	int capture_fd;
	struct tevent_fd *fde;
	struct db_hash_context *connections;
	void *private_data;
	void *destructor_data;
	unsigned int attempts;
	unsigned int max_attempts;
	struct timeval retry_interval;
	unsigned int batch_count;
	unsigned int batch_size;
};

static const char *prog;

/*
  called when we get a read event on the raw socket
 */
static void capture_tcp_handler(struct tevent_context *ev,
				struct tevent_fd *fde,
				uint16_t flags, void *private_data)
{
	struct ctdb_kill_tcp *killtcp = talloc_get_type(private_data, struct ctdb_kill_tcp);
	/* 0 the parts that don't get set by ctdb_sys_read_tcp_packet */
	struct ctdb_connection conn;
	uint32_t ack_seq, seq;
	int rst;
	uint16_t window;
	int ret;

	if (ctdb_sys_read_tcp_packet(killtcp->capture_fd,
				     killtcp->private_data,
				     &conn.server, &conn.client,
				     &ack_seq, &seq, &rst, &window) != 0) {
		/* probably a non-tcp ACK packet */
		return;
	}

	if (window == htons(1234) && (rst || seq == 0)) {
		/* Ignore packets that we sent! */
		D_DEBUG("Ignoring packet: %s, "
			"seq=%"PRIu32", ack_seq=%"PRIu32", "
			"rst=%d, window=%"PRIu16"\n",
			ctdb_connection_to_string(killtcp, &conn, false),
			seq, ack_seq, rst, ntohs(window));
		return;
	}

	/* Check if this connection is one being reset, if found then delete */
	ret = db_hash_delete(killtcp->connections,
			     (uint8_t*)&conn, sizeof(conn));
	if (ret == ENOENT) {
		/* Packet for some other connection, ignore */
		return;
	}
	if (ret != 0) {
		DBG_WARNING("Internal error (%s)\n", strerror(ret));
		return;
	}

	D_INFO("Sending a TCP RST to kill connection %s\n",
	       ctdb_connection_to_string(killtcp, &conn, true));

	ctdb_sys_send_tcp(&conn.server, &conn.client, ack_seq, seq, 1);
}


static int tickle_connection_parser(uint8_t *keybuf, size_t keylen,
				    uint8_t *databuf, size_t datalen,
				    void *private_data)
{
	struct ctdb_kill_tcp *killtcp = talloc_get_type_abort(
		private_data, struct ctdb_kill_tcp);
	struct ctdb_connection *conn;

	if (keylen != sizeof(*conn)) {
		DBG_WARNING("Unexpected data in connection hash\n");
		return 0;
	}

	conn = (struct ctdb_connection *)keybuf;

	killtcp->batch_count++;
	if (killtcp->batch_count > killtcp->batch_size) {
		/* Terminate the traverse */
		return 1;
	}

	ctdb_sys_send_tcp(&conn->server, &conn->client, 0, 0, 0);

	return 0;
}

/*
 * Called periodically until all sentenced connections have been reset
 * or enough attempts have been made
 */
static void ctdb_tickle_sentenced_connections(struct tevent_context *ev,
					      struct tevent_timer *te,
					      struct timeval t, void *private_data)
{
	struct ctdb_kill_tcp *killtcp = talloc_get_type(private_data, struct ctdb_kill_tcp);
	int count, ret;

	/* loop over up to batch_size connections sending tickle ACKs */
	killtcp->batch_count = 0;
	ret = db_hash_traverse(killtcp->connections,
			       tickle_connection_parser, killtcp, NULL);
	if (ret != 0) {
		DBG_WARNING("Unexpected error traversing connections (%s)\n",
			    strerror(ret));
	}

	killtcp->attempts++;

	/*
	 * If there are no more connections to kill or we have tried
	 * too many times we can remove the entire killtcp structure
	 */
	ret = db_hash_traverse(killtcp->connections, NULL, NULL, &count);
	if (ret != 0) {
		/* What now?  Try again until max_attempts reached */
		DBG_WARNING("Unexpected error traversing connections (%s)\n",
			    strerror(ret));
		count = 1;
	}
	if (count == 0 ||
	    killtcp->attempts >= killtcp->max_attempts) {
		talloc_free(killtcp);
		return;
	}

	/* try tickling them again in a seconds time
	 */
	tevent_add_timer(ev, killtcp,
			 tevent_timeval_current_ofs(
				 killtcp->retry_interval.tv_sec,
				 killtcp->retry_interval.tv_usec),
			 ctdb_tickle_sentenced_connections, killtcp);
}

/* Add a TCP socket to the list of connections we want to RST.  The
 * list is attached to *killtcp_arg.  If this is NULL then allocate
 * the structure.  */
static int ctdb_killtcp(struct tevent_context *ev,
			TALLOC_CTX *mem_ctx,
			const char *iface,
			struct ctdb_connection *conn,
			struct ctdb_kill_tcp **killtcp_arg)
{
	struct ctdb_kill_tcp *killtcp;
	int ret;

	if (killtcp_arg == NULL) {
		DEBUG(DEBUG_ERR, (__location__ " killtcp_arg is NULL!\n"));
		return -1;
	}

	killtcp = *killtcp_arg;

	/* Allocate a new structure if necessary.  The structure is
	 * only freed when mem_ctx is freed. */
	if (killtcp == NULL) {
		killtcp = talloc_zero(mem_ctx, struct ctdb_kill_tcp);
		if (killtcp == NULL) {
			DEBUG(DEBUG_ERR, (__location__ " out of memory\n"));
			return -1;
		}

		killtcp->capture_fd  = -1;
		ret = db_hash_init(killtcp, "connections", 2048, DB_HASH_SIMPLE,
				   &killtcp->connections);
		if (ret != 0) {
			D_ERR("Failed to initialise connection hash (%s)\n",
			      strerror(ret));
			talloc_free(killtcp);
			return -1;
		}

		killtcp->attempts = 0;
		killtcp->max_attempts = 50;

		killtcp->retry_interval.tv_sec = 0;
		killtcp->retry_interval.tv_usec = 100 * 1000;

		killtcp->batch_count = 0;
		killtcp->batch_size = 300;

		*killtcp_arg = killtcp;
	}

	/* Connection is stored as a key in the connections hash */
	ret = db_hash_add(killtcp->connections,
			  (uint8_t *)conn, sizeof(*conn),
			  NULL, 0);
	if (ret != 0) {
		D_ERR("Error adding connection to hash (%s)\n", strerror(ret));
		return -1;
	}

	/*
	   If we don't have a socket to listen on yet we must create it
	 */
	if (killtcp->capture_fd == -1) {
		killtcp->capture_fd =
			ctdb_sys_open_capture_socket(iface,
						     &killtcp->private_data);
		if (killtcp->capture_fd == -1) {
			DEBUG(DEBUG_CRIT,(__location__ " Failed to open capturing "
					  "socket on iface '%s' for killtcp (%s)\n",
					  iface, strerror(errno)));
			return -1;
		}
	}


	if (killtcp->fde == NULL) {
		killtcp->fde = tevent_add_fd(ev, killtcp,
					     killtcp->capture_fd,
					     TEVENT_FD_READ,
					     capture_tcp_handler, killtcp);
		tevent_fd_set_auto_close(killtcp->fde);
	}

	return 0;
}

static int ctdb_killtcp_destructor(struct ctdb_kill_tcp *killtcp)
{
	bool *done = killtcp->destructor_data;
	*done = true;

	return 0;
}

static void usage(void)
{
	printf("usage: %s <interface> [ <srcip:port> <dstip:port> ]\n", prog);
	exit(1);
}

int main(int argc, char **argv)
{
	struct ctdb_connection conn;
	struct ctdb_kill_tcp *killtcp = NULL;
	struct tevent_context *ev = NULL;
	struct TALLOC_CONTEXT *mem_ctx = NULL;
	struct ctdb_connection_list *conn_list = NULL;
	const char *t;
	int debug_level;
	bool done;
	int i, ret;

	/* Set the debug level */
	t = getenv("CTDB_DEBUGLEVEL");
	if (t != NULL) {
		if (debug_level_parse(t, &debug_level)) {
			DEBUGLEVEL = debug_level;
		} else {
			DEBUGLEVEL = DEBUG_ERR;
		}
	}

	prog = argv[0];

	if (argc != 2 && argc != 4) {
		usage();
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
		ret = ctdb_connection_list_read(mem_ctx, true, &conn_list);
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

	if (conn_list->num == 0) {
		/* No connections, done! */
		talloc_free(mem_ctx);
		return 0;
	}

	for (i = 0; i < conn_list->num; i++) {
		ret = ctdb_killtcp(ev, mem_ctx, argv[1],
				   &conn_list->conn[i], &killtcp);
		if (ret != 0) {
			DEBUG(DEBUG_ERR, ("Unable to killtcp\n"));
			goto fail;
		}
	}

	done = false;
	killtcp->destructor_data = &done;
	talloc_set_destructor(killtcp, ctdb_killtcp_destructor);

	/* Do the initial processing of connections */
	tevent_add_timer(ev, killtcp,
			 tevent_timeval_current_ofs(0, 0),
			 ctdb_tickle_sentenced_connections, killtcp);

	while (!done) {
		tevent_loop_once(ev);
	}

	talloc_free(mem_ctx);

	return 0;

fail:
	TALLOC_FREE(mem_ctx);
	return -1;
}
