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

#include "ctdb_private.h"

#include "common/system.h"
#include "common/common.h"
#include "common/logging.h"

#include "ctdb_tcp.h"

/*
  stop any connecting (established or pending) to a node
 */
void ctdb_tcp_stop_connection(struct ctdb_node *node)
{
	struct ctdb_tcp_node *tnode = talloc_get_type(
		node->private_data, struct ctdb_tcp_node);
	
	ctdb_queue_set_fd(tnode->out_queue, -1);
	talloc_free(tnode->connect_te);
	talloc_free(tnode->connect_fde);
	tnode->connect_fde = NULL;
	tnode->connect_te = NULL;
	if (tnode->fd != -1) {
		close(tnode->fd);
		tnode->fd = -1;
	}
}


/*
  called when a complete packet has come in - should not happen on this socket
  unless the other side closes the connection with RST or FIN
 */
void ctdb_tcp_tnode_cb(uint8_t *data, size_t cnt, void *private_data)
{
	struct ctdb_node *node = talloc_get_type(private_data, struct ctdb_node);
	struct ctdb_tcp_node *tnode = talloc_get_type(
		node->private_data, struct ctdb_tcp_node);

	if (data == NULL) {
		node->ctdb->upcalls->node_dead(node);
	}

	ctdb_tcp_stop_connection(node);
	tnode->connect_te = tevent_add_timer(node->ctdb->ev, tnode,
					     timeval_current_ofs(3, 0),
					     ctdb_tcp_node_connect, node);
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
	struct ctdb_tcp_node *tnode = talloc_get_type(node->private_data,
						      struct ctdb_tcp_node);
	struct ctdb_context *ctdb = node->ctdb;
	int error = 0;
	socklen_t len = sizeof(error);
	int one = 1;

	talloc_free(tnode->connect_te);
	tnode->connect_te = NULL;

	if (getsockopt(tnode->fd, SOL_SOCKET, SO_ERROR, &error, &len) != 0 ||
	    error != 0) {
		ctdb_tcp_stop_connection(node);
		tnode->connect_te = tevent_add_timer(ctdb->ev, tnode,
						    timeval_current_ofs(1, 0),
						    ctdb_tcp_node_connect, node);
		return;
	}

	talloc_free(tnode->connect_fde);
	tnode->connect_fde = NULL;

        if (setsockopt(tnode->fd,IPPROTO_TCP,TCP_NODELAY,(char *)&one,sizeof(one)) == -1) {
		DEBUG(DEBUG_WARNING, ("Failed to set TCP_NODELAY on fd - %s\n",
				      strerror(errno)));
	}
        if (setsockopt(tnode->fd,SOL_SOCKET,SO_KEEPALIVE,(char *)&one,sizeof(one)) == -1) {
		DEBUG(DEBUG_WARNING, ("Failed to set KEEPALIVE on fd - %s\n",
				      strerror(errno)));
	}

	ctdb_queue_set_fd(tnode->out_queue, tnode->fd);

	/* the queue subsystem now owns this fd */
	tnode->fd = -1;
}


/*
  called when we should try and establish a tcp connection to a node
*/
void ctdb_tcp_node_connect(struct tevent_context *ev, struct tevent_timer *te,
			   struct timeval t, void *private_data)
{
	struct ctdb_node *node = talloc_get_type(private_data,
						 struct ctdb_node);
	struct ctdb_tcp_node *tnode = talloc_get_type(node->private_data, 
						      struct ctdb_tcp_node);
	struct ctdb_context *ctdb = node->ctdb;
        ctdb_sock_addr sock_in;
	int sockin_size;
	int sockout_size;
        ctdb_sock_addr sock_out;

	ctdb_tcp_stop_connection(node);

	sock_out = node->address;

	tnode->fd = socket(sock_out.sa.sa_family, SOCK_STREAM, IPPROTO_TCP);
	if (tnode->fd == -1) {
		DEBUG(DEBUG_ERR, (__location__ "Failed to create socket\n"));
		return;
	}
	set_nonblocking(tnode->fd);
	set_close_on_exec(tnode->fd);

	DEBUG(DEBUG_DEBUG, (__location__ " Created TCP SOCKET FD:%d\n", tnode->fd));

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
		DEBUG(DEBUG_ERR, (__location__ " unknown family %u\n",
			sock_in.sa.sa_family));
		close(tnode->fd);
		return;
	}

	if (bind(tnode->fd, (struct sockaddr *)&sock_in, sockin_size) == -1) {
		DEBUG(DEBUG_ERR, (__location__ "Failed to bind socket %s(%d)\n",
				  strerror(errno), errno));
		close(tnode->fd);
		return;
	}

	if (connect(tnode->fd, (struct sockaddr *)&sock_out, sockout_size) != 0 &&
	    errno != EINPROGRESS) {
		ctdb_tcp_stop_connection(node);
		tnode->connect_te = tevent_add_timer(ctdb->ev, tnode,
						     timeval_current_ofs(1, 0),
						     ctdb_tcp_node_connect, node);
		return;
	}

	/* non-blocking connect - wait for write event */
	tnode->connect_fde = tevent_add_fd(node->ctdb->ev, tnode, tnode->fd,
					   TEVENT_FD_WRITE|TEVENT_FD_READ,
					   ctdb_node_connect_write, node);

	/* don't give it long to connect - retry in one second. This ensures
	   that we find a node is up quickly (tcp normally backs off a syn reply
	   delay by quite a lot) */
	tnode->connect_te = tevent_add_timer(ctdb->ev, tnode,
					     timeval_current_ofs(1, 0),
					     ctdb_tcp_node_connect, node);
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
	struct ctdb_tcp *ctcp = talloc_get_type(ctdb->private_data, struct ctdb_tcp);
	ctdb_sock_addr addr;
	socklen_t len;
	int fd, nodeid;
	struct ctdb_incoming *in;
	int one = 1;

	memset(&addr, 0, sizeof(addr));
	len = sizeof(addr);
	fd = accept(ctcp->listen_fd, (struct sockaddr *)&addr, &len);
	if (fd == -1) return;

	nodeid = ctdb_ip_to_nodeid(ctdb, &addr);

	if (nodeid == -1) {
		DEBUG(DEBUG_ERR, ("Refused connection from unknown node %s\n", ctdb_addr_to_str(&addr)));
		close(fd);
		return;
	}

	in = talloc_zero(ctcp, struct ctdb_incoming);
	in->fd = fd;
	in->ctdb = ctdb;

	set_nonblocking(in->fd);
	set_close_on_exec(in->fd);

	DEBUG(DEBUG_DEBUG, (__location__ " Created SOCKET FD:%d to incoming ctdb connection\n", fd));

        if (setsockopt(in->fd,SOL_SOCKET,SO_KEEPALIVE,(char *)&one,sizeof(one)) == -1) {
		DEBUG(DEBUG_WARNING, ("Failed to set KEEPALIVE on fd - %s\n",
				      strerror(errno)));
	}

	in->queue = ctdb_queue_setup(ctdb, in, in->fd, CTDB_TCP_ALIGNMENT,
				     ctdb_tcp_read_cb, in, "ctdbd-%s", ctdb_addr_to_str(&addr));
}


/*
  automatically find which address to listen on
*/
static int ctdb_tcp_listen_automatic(struct ctdb_context *ctdb)
{
	struct ctdb_tcp *ctcp = talloc_get_type(ctdb->private_data,
						struct ctdb_tcp);
        ctdb_sock_addr sock;
	int lock_fd, i;
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
	struct ctdb_tcp *ctcp = talloc_get_type(ctdb->private_data,
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

