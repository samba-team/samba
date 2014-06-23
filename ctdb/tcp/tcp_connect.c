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

#include "includes.h"
#include "tdb.h"
#include "system/network.h"
#include "system/filesys.h"
#include "../include/ctdb_private.h"
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
	tnode->connect_te = event_add_timed(node->ctdb->ev, tnode,
					    timeval_current_ofs(3, 0),
					    ctdb_tcp_node_connect, node);
}

/*
  called when socket becomes writeable on connect
*/
static void ctdb_node_connect_write(struct event_context *ev, struct fd_event *fde, 
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
		tnode->connect_te = event_add_timed(ctdb->ev, tnode, 
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


static int ctdb_tcp_get_address(struct ctdb_context *ctdb,
				const char *address, ctdb_sock_addr *addr)
{
	if (parse_ip(address, NULL, 0, addr) == 0) {
		DEBUG(DEBUG_CRIT, (__location__ " Unparsable address : %s.\n", address));
		return -1;
	}
	return 0;
}

/*
  called when we should try and establish a tcp connection to a node
*/
void ctdb_tcp_node_connect(struct event_context *ev, struct timed_event *te, 
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

	ZERO_STRUCT(sock_out);
#ifdef HAVE_SOCK_SIN_LEN
	sock_out.ip.sin_len = sizeof(sock_out);
#endif
	if (ctdb_tcp_get_address(ctdb, node->address.address, &sock_out) != 0) {
		return;
	}
	switch (sock_out.sa.sa_family) {
	case AF_INET:
		sock_out.ip.sin_port = htons(node->address.port);
		break;
	case AF_INET6:
		sock_out.ip6.sin6_port = htons(node->address.port);
		break;
	default:
		DEBUG(DEBUG_ERR, (__location__ " unknown family %u\n",
			sock_out.sa.sa_family));
		return;
	}

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
	ZERO_STRUCT(sock_in);
	if (ctdb_tcp_get_address(ctdb, ctdb->address.address, &sock_in) != 0) {
		DEBUG(DEBUG_ERR, (__location__ " Failed to find our address. Failing bind.\n"));
		close(tnode->fd);
		return;
	}

	/* AIX libs check to see if the socket address and length
	   arguments are consistent with each other on calls like
	   connect().   Can not get by with just sizeof(sock_in),
	   need sizeof(sock_in.ip).
	*/
	switch (sock_in.sa.sa_family) {
	case AF_INET:
		sockin_size = sizeof(sock_in.ip);
		sockout_size = sizeof(sock_out.ip);
		break;
	case AF_INET6:
		sockin_size = sizeof(sock_in.ip6);
		sockout_size = sizeof(sock_out.ip6);
		break;
	default:
		DEBUG(DEBUG_ERR, (__location__ " unknown family %u\n",
			sock_in.sa.sa_family));
		close(tnode->fd);
		return;
	}
#ifdef HAVE_SOCK_SIN_LEN
	sock_in.ip.sin_len = sockin_size;
	sock_out.ip.sin_len = sockout_size;
#endif
	if (bind(tnode->fd, (struct sockaddr *)&sock_in, sockin_size) == -1) {
		DEBUG(DEBUG_ERR, (__location__ "Failed to bind socket %s(%d)\n",
				  strerror(errno), errno));
		close(tnode->fd);
		return;
	}

	if (connect(tnode->fd, (struct sockaddr *)&sock_out, sockout_size) != 0 &&
	    errno != EINPROGRESS) {
		ctdb_tcp_stop_connection(node);
		tnode->connect_te = event_add_timed(ctdb->ev, tnode, 
						    timeval_current_ofs(1, 0),
						    ctdb_tcp_node_connect, node);
		return;
	}

	/* non-blocking connect - wait for write event */
	tnode->connect_fde = event_add_fd(node->ctdb->ev, tnode, tnode->fd, 
					  EVENT_FD_WRITE|EVENT_FD_READ, 
					  ctdb_node_connect_write, node);

	/* don't give it long to connect - retry in one second. This ensures
	   that we find a node is up quickly (tcp normally backs off a syn reply
	   delay by quite a lot) */
	tnode->connect_te = event_add_timed(ctdb->ev, tnode, timeval_current_ofs(1, 0), 
					    ctdb_tcp_node_connect, node);
}

/*
  called when we get contacted by another node
  currently makes no attempt to check if the connection is really from a ctdb
  node in our cluster
*/
static void ctdb_listen_event(struct event_context *ev, struct fd_event *fde, 
			      uint16_t flags, void *private_data)
{
	struct ctdb_context *ctdb = talloc_get_type(private_data, struct ctdb_context);
	struct ctdb_tcp *ctcp = talloc_get_type(ctdb->private_data, struct ctdb_tcp);
	ctdb_sock_addr addr;
	socklen_t len;
	int fd, nodeid;
	struct ctdb_incoming *in;
	int one = 1;
	const char *incoming_node;

	memset(&addr, 0, sizeof(addr));
	len = sizeof(addr);
	fd = accept(ctcp->listen_fd, (struct sockaddr *)&addr, &len);
	if (fd == -1) return;

	incoming_node = ctdb_addr_to_str(&addr);
	nodeid = ctdb_ip_to_nodeid(ctdb, incoming_node);

	if (nodeid == -1) {
		DEBUG(DEBUG_ERR, ("Refused connection from unknown node %s\n", incoming_node));
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
				     ctdb_tcp_read_cb, in, "ctdbd-%s", incoming_node);
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
		ZERO_STRUCT(sock);
		if (ctdb_tcp_get_address(ctdb,
				ctdb->nodes[i]->address.address, 
				&sock) != 0) {
			continue;
		}
	
		switch (sock.sa.sa_family) {
		case AF_INET:
			sock.ip.sin_port = htons(ctdb->nodes[i]->address.port);
			sock_size = sizeof(sock.ip);
			break;
		case AF_INET6:
			sock.ip6.sin6_port = htons(ctdb->nodes[i]->address.port);
			sock_size = sizeof(sock.ip6);
			break;
		default:
			DEBUG(DEBUG_ERR, (__location__ " unknown family %u\n",
				sock.sa.sa_family));
			continue;
		}
#ifdef HAVE_SOCK_SIN_LEN
		sock.ip.sin_len = sock_size;
#endif

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
	}
	
	if (i == ctdb->num_nodes) {
		DEBUG(DEBUG_CRIT,("Unable to bind to any of the node addresses - giving up\n"));
		goto failed;
	}
	ctdb->address.address = talloc_strdup(ctdb, ctdb->nodes[i]->address.address);
	ctdb->address.port    = ctdb->nodes[i]->address.port;
	ctdb->name = talloc_asprintf(ctdb, "%s:%u", 
				     ctdb->address.address, 
				     ctdb->address.port);
	ctdb->pnn = ctdb->nodes[i]->pnn;
	DEBUG(DEBUG_INFO,("ctdb chose network address %s:%u pnn %u\n", 
		 ctdb->address.address, 
		 ctdb->address.port, 
		 ctdb->pnn));
	
	if (listen(ctcp->listen_fd, 10) == -1) {
		goto failed;
	}

	fde = event_add_fd(ctdb->ev, ctcp, ctcp->listen_fd, EVENT_FD_READ,
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
	if (!ctdb->address.address) {
		return ctdb_tcp_listen_automatic(ctdb);
	}

	ZERO_STRUCT(sock);
	if (ctdb_tcp_get_address(ctdb, ctdb->address.address, 
				 &sock) != 0) {
		goto failed;
	}
	
	switch (sock.sa.sa_family) {
	case AF_INET:
		sock.ip.sin_port = htons(ctdb->address.port);
		sock_size = sizeof(sock.ip);
		break;
	case AF_INET6:
		sock.ip6.sin6_port = htons(ctdb->address.port);
		sock_size = sizeof(sock.ip6);
		break;
	default:
		DEBUG(DEBUG_ERR, (__location__ " unknown family %u\n",
			sock.sa.sa_family));
		goto failed;
	}
#ifdef HAVE_SOCK_SIN_LEN
	sock.ip.sin_len = sock_size;
#endif

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

	fde = event_add_fd(ctdb->ev, ctcp, ctcp->listen_fd, EVENT_FD_READ,
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

