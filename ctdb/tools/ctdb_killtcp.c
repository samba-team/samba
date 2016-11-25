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
#include "protocol/protocol_api.h"

#include "common/rb_tree.h"
#include "common/system.h"
#include "common/logging.h"


/* Contains the listening socket and the list of TCP connections to
 * kill */
struct ctdb_kill_tcp {
	int capture_fd;
	struct tevent_fd *fde;
	trbt_tree_t *connections;
	void *private_data;
	void *destructor_data;
	unsigned int attempts;
	unsigned int max_attempts;
	struct timeval retry_interval;
	unsigned int batch_count;
	unsigned int batch_size;
};

static const char *prog;

/* TCP connection to be killed */
struct ctdb_killtcp_con {
	ctdb_sock_addr src_addr;
	ctdb_sock_addr dst_addr;
	struct ctdb_kill_tcp *killtcp;
};

/* this function is used to create a key to represent this socketpair
   in the killtcp tree.
   this key is used to insert and lookup matching socketpairs that are
   to be tickled and RST
*/
#define KILLTCP_KEYLEN	10
static uint32_t *killtcp_key(ctdb_sock_addr *src, ctdb_sock_addr *dst)
{
	static uint32_t key[KILLTCP_KEYLEN];

	bzero(key, sizeof(key));

	if (src->sa.sa_family != dst->sa.sa_family) {
		DEBUG(DEBUG_ERR, (__location__ " ERROR, different families passed :%u vs %u\n", src->sa.sa_family, dst->sa.sa_family));
		return key;
	}

	switch (src->sa.sa_family) {
	case AF_INET:
		key[0]	= dst->ip.sin_addr.s_addr;
		key[1]	= src->ip.sin_addr.s_addr;
		key[2]	= dst->ip.sin_port;
		key[3]	= src->ip.sin_port;
		break;
	case AF_INET6: {
		uint32_t *dst6_addr32 =
			(uint32_t *)&(dst->ip6.sin6_addr.s6_addr);
		uint32_t *src6_addr32 =
			(uint32_t *)&(src->ip6.sin6_addr.s6_addr);
		key[0]	= dst6_addr32[3];
		key[1]	= src6_addr32[3];
		key[2]	= dst6_addr32[2];
		key[3]	= src6_addr32[2];
		key[4]	= dst6_addr32[1];
		key[5]	= src6_addr32[1];
		key[6]	= dst6_addr32[0];
		key[7]	= src6_addr32[0];
		key[8]	= dst->ip6.sin6_port;
		key[9]	= src->ip6.sin6_port;
		break;
	}
	default:
		DEBUG(DEBUG_ERR, (__location__ " ERROR, unknown family passed :%u\n", src->sa.sa_family));
		return key;
	}

	return key;
}

/*
  called when we get a read event on the raw socket
 */
static void capture_tcp_handler(struct tevent_context *ev,
				struct tevent_fd *fde,
				uint16_t flags, void *private_data)
{
	struct ctdb_kill_tcp *killtcp = talloc_get_type(private_data, struct ctdb_kill_tcp);
	struct ctdb_killtcp_con *con;
	ctdb_sock_addr src, dst;
	uint32_t ack_seq, seq;
	int rst;
	uint16_t window;

	if (ctdb_sys_read_tcp_packet(killtcp->capture_fd,
				     killtcp->private_data,
				     &src, &dst,
				     &ack_seq, &seq, &rst, &window) != 0) {
		/* probably a non-tcp ACK packet */
		return;
	}

	if (window == htons(1234) && (rst || seq == 0)) {
		/* Ignore packets that we sent! */
		DEBUG(DEBUG_DEBUG,
		      ("Ignoring packet with dst=%s:%d, src=%s:%d, seq=%"PRIu32", ack_seq=%"PRIu32", rst=%d, window=%"PRIu16"\n",
		       ctdb_sock_addr_to_string(killtcp, &dst),
		       ntohs(dst.ip.sin_port),
		       ctdb_sock_addr_to_string(killtcp, &src),
		       ntohs(src.ip.sin_port),
		       seq, ack_seq, rst, ntohs(window)));
		return;
	}

	/* check if we have this guy in our list of connections
	   to kill
	*/
	con = trbt_lookuparray32(killtcp->connections,
			KILLTCP_KEYLEN, killtcp_key(&src, &dst));
	if (con == NULL) {
		/* no this was some other packet we can just ignore */
		return;
	}

	/* This connection has been tickled!  RST it and remove it
	 * from the list. */
	DEBUG(DEBUG_INFO,
	      ("Sending a TCP RST to kill connection (%s:%d) -> %s:%d\n",
	       ctdb_sock_addr_to_string(con, &con->src_addr),
	       ntohs(con->src_addr.ip.sin_port),
	       ctdb_sock_addr_to_string(con, &con->dst_addr),
	       ntohs(con->dst_addr.ip.sin_port)));

	ctdb_sys_send_tcp(&con->dst_addr, &con->src_addr, ack_seq, seq, 1);
	talloc_free(con);
}


/* when traversing the list of all tcp connections to send tickle acks to
   (so that we can capture the ack coming back and kill the connection
    by a RST)
   this callback is called for each connection we are currently trying to kill
*/
static int tickle_connection_traverse(void *param, void *data)
{
	struct ctdb_killtcp_con *con = talloc_get_type(data, struct ctdb_killtcp_con);

	con->killtcp->batch_count++;
	if (con->killtcp->batch_count > con->killtcp->batch_size) {
		/* Terminate the traverse */
		return -1;
	}

	ctdb_sys_send_tcp(&con->dst_addr, &con->src_addr, 0, 0, 0);

	return 0;
}


/*
   called every second until all sentenced connections have been reset
 */
static void ctdb_tickle_sentenced_connections(struct tevent_context *ev,
					      struct tevent_timer *te,
					      struct timeval t, void *private_data)
{
	struct ctdb_kill_tcp *killtcp = talloc_get_type(private_data, struct ctdb_kill_tcp);
	void *delete_cons = talloc_new(NULL);

	/* loop over up to batch_size connections sending tickle ACKs */
	killtcp->batch_count = 0;
	trbt_traversearray32(killtcp->connections, KILLTCP_KEYLEN, tickle_connection_traverse, delete_cons);

	/* now we've finished traverse, it's safe to do deletion. */
	talloc_free(delete_cons);

	killtcp->attempts++;

	/* If there are no more connections to kill or we have tried
	   too many times we can remove the entire killtcp structure
	 */
	if (killtcp->connections == NULL ||
	    killtcp->connections->root == NULL ||
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

/* nothing fancy here, just unconditionally replace any existing
   connection structure with the new one.

   don't even free the old one if it did exist, that one is talloc_stolen
   by the same node in the tree anyway and will be deleted when the new data
   is deleted
*/
static void *add_killtcp_callback(void *parm, void *data)
{
	return parm;
}

/* Add a TCP socket to the list of connections we want to RST.  The
 * list is attached to *killtcp_arg.  If this is NULL then allocate
 * the structure.  */
static int ctdb_killtcp(struct tevent_context *ev,
			TALLOC_CTX *mem_ctx,
			const char *iface,
			const ctdb_sock_addr *src,
			const ctdb_sock_addr *dst,
			struct ctdb_kill_tcp **killtcp_arg)
{
	struct ctdb_kill_tcp *killtcp;
	struct ctdb_killtcp_con *con;

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
		killtcp->connections = trbt_create(killtcp, 0);

		killtcp->attempts = 0;
		killtcp->max_attempts = 50;

		killtcp->retry_interval.tv_sec = 0;
		killtcp->retry_interval.tv_usec = 100 * 1000;

		killtcp->batch_count = 0;
		killtcp->batch_size = 300;

		*killtcp_arg = killtcp;
	}

	/* create a structure that describes this connection we want to
	   RST and store it in killtcp->connections
	*/
	con = talloc(killtcp, struct ctdb_killtcp_con);
	if (con == NULL) {
		DEBUG(DEBUG_ERR, (__location__ " out of memory\n"));
		return -1;
	}
	con->src_addr = *src;
	con->dst_addr = *dst;
	con->killtcp  = killtcp;


	trbt_insertarray32_callback(killtcp->connections,
				    KILLTCP_KEYLEN,
				    killtcp_key(&con->dst_addr,
						&con->src_addr),
				    add_killtcp_callback, con);

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
	struct ctdb_connection *conns = NULL;
	const char *t;
	int debug_level;
	bool done;
	int num = 0;
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
		if (!parse_ip_port(argv[2], &conn.src)) {
			DEBUG(DEBUG_ERR, ("Bad IP:port '%s'\n", argv[2]));
			goto fail;
		}

		if (!parse_ip_port(argv[3], &conn.dst)) {
			DEBUG(DEBUG_ERR, ("Bad IP:port '%s'\n", argv[3]));
			goto fail;
		}

		conns = &conn;
		num = 1;
	} else {
		ret = ctdb_parse_connections(stdin, mem_ctx, &num, &conns);
		if (ret != 0) {
			DEBUG(DEBUG_ERR,
			      ("Unable to parse connections [%s]\n",
			       strerror(ret)));
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

	if (num == 0) {
		/* No connections, done! */
		talloc_free(mem_ctx);
		return 0;
	}

	for (i = 0; i < num; i++) {
		ret = ctdb_killtcp(ev, mem_ctx, argv[1],
				   &conns[i].src, &conns[i].dst,
				   &killtcp);
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
