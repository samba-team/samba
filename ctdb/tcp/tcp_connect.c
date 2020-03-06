/* 
   ctdb over TCP

   Copyright (C) Andrew Tridgell  2006
   Copyright (C) Ronnie Sahlberg  2008

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

#include "lib/util/debug.h"
#include "lib/util/time.h"
#include "lib/util/blocking.h"

#include "ctdb_private.h"

#include "common/system.h"
#include "common/common.h"
#include "common/logging.h"

#include "ctdb_tcp.h"

/*
  stop any outgoing connection (established or pending) to a node
 */
void ctdb_tcp_stop_outgoing(struct ctdb_node *node)
{
	struct ctdb_tcp_node *tnode = talloc_get_type(
		node->transport_data, struct ctdb_tcp_node);

	TALLOC_FREE(tnode->out_queue);
	TALLOC_FREE(tnode->connect_te);
	TALLOC_FREE(tnode->connect_fde);
	if (tnode->out_fd != -1) {
		close(tnode->out_fd);
		tnode->out_fd = -1;
	}
}

/*
  stop incoming connection to a node
 */
void ctdb_tcp_stop_incoming(struct ctdb_node *node)
{
	struct ctdb_tcp_node *tnode = talloc_get_type(
		node->transport_data, struct ctdb_tcp_node);

	TALLOC_FREE(tnode->in_queue);
}

/*
  called when a complete packet has come in - should not happen on this socket
  unless the other side closes the connection with RST or FIN
 */
void ctdb_tcp_tnode_cb(uint8_t *data, size_t cnt, void *private_data)
{
	struct ctdb_node *node = talloc_get_type(private_data, struct ctdb_node);

	node->ctdb->upcalls->node_dead(node);

	TALLOC_FREE(data);
}

/*
  called when socket becomes writeable on connect
*/
static void ctdb_node_connect_write(struct tevent_context *ev,
				    struct tevent_fd *fde,
				    uint16_t flags, void *private_data)
{
	struct ctdb_node *node = talloc_get_type(private_data,
						 struct ctdb_node);
	struct ctdb_tcp_node *tnode = talloc_get_type(node->transport_data,
						      struct ctdb_tcp_node);
	struct ctdb_context *ctdb = node->ctdb;
	int error = 0;
	socklen_t len = sizeof(error);
	int one = 1;
	int ret;

	TALLOC_FREE(tnode->connect_te);

	ret = getsockopt(tnode->out_fd, SOL_SOCKET, SO_ERROR, &error, &len);
	if (ret != 0 || error != 0) {
		ctdb_tcp_stop_outgoing(node);
		tnode->connect_te = tevent_add_timer(ctdb->ev, tnode,
						    timeval_current_ofs(1, 0),
						    ctdb_tcp_node_connect, node);
		return;
	}

	TALLOC_FREE(tnode->connect_fde);

	ret = setsockopt(tnode->out_fd,
			 IPPROTO_TCP,
			 TCP_NODELAY,
			 (char *)&one,
			 sizeof(one));
	if (ret == -1) {
		DBG_WARNING("Failed to set TCP_NODELAY on fd - %s\n",
			  strerror(errno));
	}
	ret = setsockopt(tnode->out_fd,
			 SOL_SOCKET,
			 SO_KEEPALIVE,(char *)&one,
			 sizeof(one));
	if (ret == -1) {
		DBG_WARNING("Failed to set KEEPALIVE on fd - %s\n",
			    strerror(errno));
	}

	tnode->out_queue = ctdb_queue_setup(node->ctdb,
					    tnode,
					    tnode->out_fd,
					    CTDB_TCP_ALIGNMENT,
					    ctdb_tcp_tnode_cb,
					    node,
					    "to-node-%s",
					    node->name);
	if (tnode->out_queue == NULL) {
		DBG_ERR("Failed to set up outgoing queue\n");
		ctdb_tcp_stop_outgoing(node);
		tnode->connect_te = tevent_add_timer(ctdb->ev,
						     tnode,
						     timeval_current_ofs(1, 0),
						     ctdb_tcp_node_connect,
						     node);
		return;
	}

	/* the queue subsystem now owns this fd */
	tnode->out_fd = -1;

	/*
	 * Mark the node to which this connection has been established
	 * as connected, but only if the corresponding listening
	 * socket is also connected
	 */
	if (tnode->in_queue != NULL) {
		node->ctdb->upcalls->node_connected(node);
	}
}


static void ctdb_tcp_node_connect_timeout(struct tevent_context *ev,
					  struct tevent_timer *te,
					  struct timeval t,
					  void *private_data);

/*
  called when we should try and establish a tcp connection to a node
*/
static void ctdb_tcp_start_outgoing(struct ctdb_node *node)
{
	struct ctdb_tcp_node *tnode = talloc_get_type(node->transport_data,
						      struct ctdb_tcp_node);
	struct ctdb_context *ctdb = node->ctdb;
        ctdb_sock_addr sock_in;
	int sockin_size;
	int sockout_size;
        ctdb_sock_addr sock_out;
	int ret;

	sock_out = node->address;

	tnode->out_fd = socket(sock_out.sa.sa_family, SOCK_STREAM, IPPROTO_TCP);
	if (tnode->out_fd == -1) {
		DBG_ERR("Failed to create socket\n");
		goto failed;
	}

	ret = set_blocking(tnode->out_fd, false);
	if (ret != 0) {
		DBG_ERR("Failed to set socket non-blocking (%s)\n",
			strerror(errno));
		goto failed;
	}

	set_close_on_exec(tnode->out_fd);

	DBG_DEBUG("Created TCP SOCKET FD:%d\n", tnode->out_fd);

	/* Bind our side of the socketpair to the same address we use to listen
	 * on incoming CTDB traffic.
	 * We must specify this address to make sure that the address we expose to
	 * the remote side is actually routable in case CTDB traffic will run on
	 * a dedicated non-routeable network.
	 */
	sock_in = *ctdb->address;

	/* AIX libs check to see if the socket address and length
	   arguments are consistent with each other on calls like
	   connect().   Can not get by with just sizeof(sock_in),
	   need sizeof(sock_in.ip).
	*/
	switch (sock_in.sa.sa_family) {
	case AF_INET:
		sock_in.ip.sin_port = 0 /* Any port */;
		sockin_size = sizeof(sock_in.ip);
		sockout_size = sizeof(sock_out.ip);
		break;
	case AF_INET6:
		sock_in.ip6.sin6_port = 0 /* Any port */;
		sockin_size = sizeof(sock_in.ip6);
		sockout_size = sizeof(sock_out.ip6);
		break;
	default:
		DBG_ERR("Unknown address family %u\n", sock_in.sa.sa_family);
		/* Can't happen to due to address parsing restrictions */
		goto failed;
	}

	ret = bind(tnode->out_fd, (struct sockaddr *)&sock_in, sockin_size);
	if (ret == -1) {
		DBG_ERR("Failed to bind socket (%s)\n", strerror(errno));
		goto failed;
	}

	ret = connect(tnode->out_fd,
		      (struct sockaddr *)&sock_out,
		      sockout_size);
	if (ret != 0 && errno != EINPROGRESS) {
		goto failed;
	}

	/* non-blocking connect - wait for write event */
	tnode->connect_fde = tevent_add_fd(node->ctdb->ev,
					   tnode,
					   tnode->out_fd,
					   TEVENT_FD_WRITE|TEVENT_FD_READ,
					   ctdb_node_connect_write,
					   node);

	/* don't give it long to connect - retry in one second. This ensures
	   that we find a node is up quickly (tcp normally backs off a syn reply
	   delay by quite a lot) */
	tnode->connect_te = tevent_add_timer(ctdb->ev,
					     tnode,
					     timeval_current_ofs(1, 0),
					     ctdb_tcp_node_connect_timeout,
					     node);

	return;

failed:
	ctdb_tcp_stop_outgoing(node);
	tnode->connect_te = tevent_add_timer(ctdb->ev,
					     tnode,
					     timeval_current_ofs(1, 0),
					     ctdb_tcp_node_connect,
					     node);
}

void ctdb_tcp_node_connect(struct tevent_context *ev,
			   struct tevent_timer *te,
			   struct timeval t,
			   void *private_data)
{
	struct ctdb_node *node = talloc_get_type_abort(private_data,
						       struct ctdb_node);

	ctdb_tcp_start_outgoing(node);
}

static void ctdb_tcp_node_connect_timeout(struct tevent_context *ev,
					  struct tevent_timer *te,
					  struct timeval t,
					  void *private_data)
{
	struct ctdb_node *node = talloc_get_type_abort(private_data,
						       struct ctdb_node);

	ctdb_tcp_stop_outgoing(node);
	ctdb_tcp_start_outgoing(node);
}

/*
  called when we get contacted by another node
  currently makes no attempt to check if the connection is really from a ctdb
  node in our cluster
*/
static void ctdb_listen_event(struct tevent_context *ev, struct tevent_fd *fde,
			      uint16_t flags, void *private_data)
{
	struct ctdb_context *ctdb = talloc_get_type(private_data, struct ctdb_context);
	struct ctdb_tcp *ctcp = talloc_get_type(ctdb->transport_data,
						struct ctdb_tcp);
	ctdb_sock_addr addr;
	socklen_t len;
	int fd;
	struct ctdb_node *node;
	struct ctdb_tcp_node *tnode;
	int one = 1;
	int ret;

	memset(&addr, 0, sizeof(addr));
	len = sizeof(addr);
	fd = accept(ctcp->listen_fd, (struct sockaddr *)&addr, &len);
	if (fd == -1) return;
	smb_set_close_on_exec(fd);

	node = ctdb_ip_to_node(ctdb, &addr);
	if (node == NULL) {
		D_ERR("Refused connection from unknown node %s\n",
		      ctdb_addr_to_str(&addr));
		close(fd);
		return;
	}

	tnode = talloc_get_type_abort(node->transport_data,
				      struct ctdb_tcp_node);
	if (tnode == NULL) {
		/* This can't happen - see ctdb_tcp_initialise() */
		DBG_ERR("INTERNAL ERROR setting up connection from node %s\n",
			ctdb_addr_to_str(&addr));
		close(fd);
		return;
	}

	if (tnode->in_queue != NULL) {
		DBG_ERR("Incoming queue active, rejecting connection from %s\n",
			ctdb_addr_to_str(&addr));
		close(fd);
		return;
	}

	ret = set_blocking(fd, false);
	if (ret != 0) {
		DBG_ERR("Failed to set socket non-blocking (%s)\n",
			strerror(errno));
		close(fd);
		return;
	}

	set_close_on_exec(fd);

	DBG_DEBUG("Created SOCKET FD:%d to incoming ctdb connection\n", fd);

	ret = setsockopt(fd,
			 SOL_SOCKET,
			 SO_KEEPALIVE,
			 (char *)&one,
			 sizeof(one));
	if (ret == -1) {
		DBG_WARNING("Failed to set KEEPALIVE on fd - %s\n",
			    strerror(errno));
	}

	tnode->in_queue = ctdb_queue_setup(ctdb,
					   tnode,
					   fd,
					   CTDB_TCP_ALIGNMENT,
					   ctdb_tcp_read_cb,
					   node,
					   "ctdbd-%s",
					   ctdb_addr_to_str(&addr));
	if (tnode->in_queue == NULL) {
		DBG_ERR("Failed to set up incoming queue\n");
		close(fd);
		return;
	}

       /*
	* Mark the connecting node as connected, but only if the
	* corresponding outbound connected is also up
	*/
	if (tnode->out_queue != NULL) {
		node->ctdb->upcalls->node_connected(node);
	}
 }


/*
  automatically find which address to listen on
*/
static int ctdb_tcp_listen_automatic(struct ctdb_context *ctdb)
{
	struct ctdb_tcp *ctcp = talloc_get_type(ctdb->transport_data,
						struct ctdb_tcp);
        ctdb_sock_addr sock;
	int lock_fd;
	unsigned int i;
	const char *lock_path = CTDB_RUNDIR "/.socket_lock";
	struct flock lock;
	int one = 1;
	int sock_size;
	struct tevent_fd *fde;

	/* If there are no nodes, then it won't be possible to find
	 * the first one.  Log a failure and short circuit the whole
	 * process.
	 */
	if (ctdb->num_nodes == 0) {
		DEBUG(DEBUG_CRIT,("No nodes available to attempt bind to - is the nodes file empty?\n"));
		return -1;
	}

	/* in order to ensure that we don't get two nodes with the
	   same adddress, we must make the bind() and listen() calls
	   atomic. The SO_REUSEADDR setsockopt only prevents double
	   binds if the first socket is in LISTEN state  */
	lock_fd = open(lock_path, O_RDWR|O_CREAT, 0666);
	if (lock_fd == -1) {
		DEBUG(DEBUG_CRIT,("Unable to open %s\n", lock_path));
		return -1;
	}

	lock.l_type = F_WRLCK;
	lock.l_whence = SEEK_SET;
	lock.l_start = 0;
	lock.l_len = 1;
	lock.l_pid = 0;

	if (fcntl(lock_fd, F_SETLKW, &lock) != 0) {
		DEBUG(DEBUG_CRIT,("Unable to lock %s\n", lock_path));
		close(lock_fd);
		return -1;
	}

	for (i=0; i < ctdb->num_nodes; i++) {
		if (ctdb->nodes[i]->flags & NODE_FLAGS_DELETED) {
			continue;
		}
		sock = ctdb->nodes[i]->address;

		switch (sock.sa.sa_family) {
		case AF_INET:
			sock_size = sizeof(sock.ip);
			break;
		case AF_INET6:
			sock_size = sizeof(sock.ip6);
			break;
		default:
			DEBUG(DEBUG_ERR, (__location__ " unknown family %u\n",
				sock.sa.sa_family));
			continue;
		}

		ctcp->listen_fd = socket(sock.sa.sa_family, SOCK_STREAM, IPPROTO_TCP);
		if (ctcp->listen_fd == -1) {
			ctdb_set_error(ctdb, "socket failed\n");
			continue;
		}

		set_close_on_exec(ctcp->listen_fd);

	        if (setsockopt(ctcp->listen_fd,SOL_SOCKET,SO_REUSEADDR,
			       (char *)&one,sizeof(one)) == -1) {
			DEBUG(DEBUG_WARNING, ("Failed to set REUSEADDR on fd - %s\n",
					      strerror(errno)));
		}

		if (bind(ctcp->listen_fd, (struct sockaddr * )&sock, sock_size) == 0) {
			break;
		}

		if (errno == EADDRNOTAVAIL) {
			DEBUG(DEBUG_DEBUG,(__location__ " Failed to bind() to socket. %s(%d)\n",
					strerror(errno), errno));
		} else {
			DEBUG(DEBUG_ERR,(__location__ " Failed to bind() to socket. %s(%d)\n",
					strerror(errno), errno));
		}

		close(ctcp->listen_fd);
		ctcp->listen_fd = -1;
	}

	if (i == ctdb->num_nodes) {
		DEBUG(DEBUG_CRIT,("Unable to bind to any of the node addresses - giving up\n"));
		goto failed;
	}
	ctdb->address = talloc_memdup(ctdb,
				      &ctdb->nodes[i]->address,
				      sizeof(ctdb_sock_addr));
	if (ctdb->address == NULL) {
		ctdb_set_error(ctdb, "Out of memory at %s:%d",
			       __FILE__, __LINE__);
		goto failed;
	}

	ctdb->name = talloc_asprintf(ctdb, "%s:%u",
				     ctdb_addr_to_str(ctdb->address),
				     ctdb_addr_to_port(ctdb->address));
	if (ctdb->name == NULL) {
		ctdb_set_error(ctdb, "Out of memory at %s:%d",
			       __FILE__, __LINE__);
		goto failed;
	}
	DEBUG(DEBUG_INFO,("ctdb chose network address %s\n", ctdb->name));

	if (listen(ctcp->listen_fd, 10) == -1) {
		goto failed;
	}

	fde = tevent_add_fd(ctdb->ev, ctcp, ctcp->listen_fd, TEVENT_FD_READ,
			    ctdb_listen_event, ctdb);
	tevent_fd_set_auto_close(fde);

	close(lock_fd);

	return 0;

failed:
	close(lock_fd);
	if (ctcp->listen_fd != -1) {
		close(ctcp->listen_fd);
		ctcp->listen_fd = -1;
	}
	return -1;
}


/*
  listen on our own address
*/
int ctdb_tcp_listen(struct ctdb_context *ctdb)
{
	struct ctdb_tcp *ctcp = talloc_get_type(ctdb->transport_data,
						struct ctdb_tcp);
        ctdb_sock_addr sock;
	int sock_size;
	int one = 1;
	struct tevent_fd *fde;

	/* we can either auto-bind to the first available address, or we can
	   use a specified address */
	if (!ctdb->address) {
		return ctdb_tcp_listen_automatic(ctdb);
	}

	sock = *ctdb->address;

	switch (sock.sa.sa_family) {
	case AF_INET:
		sock_size = sizeof(sock.ip);
		break;
	case AF_INET6:
		sock_size = sizeof(sock.ip6);
		break;
	default:
		DEBUG(DEBUG_ERR, (__location__ " unknown family %u\n",
			sock.sa.sa_family));
		goto failed;
	}

	ctcp->listen_fd = socket(sock.sa.sa_family, SOCK_STREAM, IPPROTO_TCP);
	if (ctcp->listen_fd == -1) {
		ctdb_set_error(ctdb, "socket failed\n");
		return -1;
	}

	set_close_on_exec(ctcp->listen_fd);

        if (setsockopt(ctcp->listen_fd,SOL_SOCKET,SO_REUSEADDR,(char *)&one,sizeof(one)) == -1) {
		DEBUG(DEBUG_WARNING, ("Failed to set REUSEADDR on fd - %s\n",
				      strerror(errno)));
	}

	if (bind(ctcp->listen_fd, (struct sockaddr * )&sock, sock_size) != 0) {
		DEBUG(DEBUG_ERR,(__location__ " Failed to bind() to socket. %s(%d)\n", strerror(errno), errno));
		goto failed;
	}

	if (listen(ctcp->listen_fd, 10) == -1) {
		goto failed;
	}

	fde = tevent_add_fd(ctdb->ev, ctcp, ctcp->listen_fd, TEVENT_FD_READ,
			    ctdb_listen_event, ctdb);
	tevent_fd_set_auto_close(fde);

	return 0;

failed:
	if (ctcp->listen_fd != -1) {
		close(ctcp->listen_fd);
	}
	ctcp->listen_fd = -1;
	return -1;
}

