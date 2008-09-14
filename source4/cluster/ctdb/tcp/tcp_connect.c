/* 
   ctdb over TCP

   Copyright (C) Andrew Tridgell  2006

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
#include "lib/events/events.h"
#include "lib/tdb/include/tdb.h"
#include "system/network.h"
#include "system/filesys.h"
#include "../include/ctdb_private.h"
#include "ctdb_tcp.h"

/*
  called when a complete packet has come in - should not happen on this socket
 */
void ctdb_tcp_tnode_cb(uint8_t *data, size_t cnt, void *private_data)
{
	struct ctdb_node *node = talloc_get_type(private_data, struct ctdb_node);
	struct ctdb_tcp_node *tnode = talloc_get_type(
		node->private_data, struct ctdb_tcp_node);

	if (data == NULL) {
		node->ctdb->upcalls->node_dead(node);
	}

	/* start a new connect cycle to try to re-establish the
	   link */
	ctdb_queue_set_fd(tnode->out_queue, -1);
	tnode->fd = -1;
	event_add_timed(node->ctdb->ev, tnode, timeval_zero(), 
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
		talloc_free(fde);
		close(tnode->fd);
		tnode->fd = -1;
		event_add_timed(ctdb->ev, tnode, timeval_current_ofs(1, 0), 
				ctdb_tcp_node_connect, node);
		return;
	}

	talloc_free(fde);
	
        setsockopt(tnode->fd,IPPROTO_TCP,TCP_NODELAY,(char *)&one,sizeof(one));
        setsockopt(tnode->fd,SOL_SOCKET,SO_KEEPALIVE,(char *)&one,sizeof(one));

	ctdb_queue_set_fd(tnode->out_queue, tnode->fd);

	/* tell the ctdb layer we are connected */
	node->ctdb->upcalls->node_connected(node);
}


static int ctdb_tcp_get_address(struct ctdb_context *ctdb,
				const char *address, struct in_addr *addr)
{
	if (inet_pton(AF_INET, address, addr) <= 0) {
		struct hostent *he = gethostbyname(address);
		if (he == NULL || he->h_length > sizeof(*addr)) {
			ctdb_set_error(ctdb, "invalid nework address '%s'\n", 
				       address);
			return -1;
		}
		memcpy(addr, he->h_addr, he->h_length);
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
        struct sockaddr_in sock_in;
        struct sockaddr_in sock_out;

	if (tnode->fd != -1) {
		talloc_free(tnode->connect_fde);
		tnode->connect_fde = NULL;
		close(tnode->fd);
		tnode->fd = -1;
	}

	tnode->fd = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);

	set_nonblocking(tnode->fd);
	set_close_on_exec(tnode->fd);

	ZERO_STRUCT(sock_out);
#ifdef HAVE_SOCK_SIN_LEN
	sock_out.sin_len = sizeof(sock_out);
#endif
	if (ctdb_tcp_get_address(ctdb, node->address.address, &sock_out.sin_addr) != 0) {
		return;
	}
	sock_out.sin_port = htons(node->address.port);
	sock_out.sin_family = PF_INET;


	/* Bind our side of the socketpair to the same address we use to listen
	 * on incoming CTDB traffic.
	 * We must specify this address to make sure that the address we expose to
	 * the remote side is actually routable in case CTDB traffic will run on
	 * a dedicated non-routeable network.
	 */
	ZERO_STRUCT(sock_in);
#ifdef HAVE_SOCK_SIN_LEN
	sock_in.sin_len = sizeof(sock_in);
#endif
	if (ctdb_tcp_get_address(ctdb, ctdb->address.address, &sock_in.sin_addr) != 0) {
		return;
	}
	sock_in.sin_port = htons(0); /* INPORT_ANY is not always available */
	sock_in.sin_family = PF_INET;
	bind(tnode->fd, (struct sockaddr *)&sock_in, sizeof(sock_in));

	if (connect(tnode->fd, (struct sockaddr *)&sock_out, sizeof(sock_out)) != 0 &&
	    errno != EINPROGRESS) {
		/* try again once a second */
		close(tnode->fd);
		tnode->fd = -1;
		event_add_timed(ctdb->ev, tnode, timeval_current_ofs(1, 0), 
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
	struct sockaddr_in addr;
	socklen_t len;
	int fd, nodeid;
	struct ctdb_incoming *in;
	int one = 1;
	const char *incoming_node;

	memset(&addr, 0, sizeof(addr));
	len = sizeof(addr);
	fd = accept(ctcp->listen_fd, (struct sockaddr *)&addr, &len);
	if (fd == -1) return;

	incoming_node = inet_ntoa(addr.sin_addr);
	for (nodeid=0;nodeid<ctdb->num_nodes;nodeid++) {
		if (!strcmp(incoming_node, ctdb->nodes[nodeid]->address.address)) {
			DEBUG(0, ("Incoming connection from node:%d %s\n",nodeid,incoming_node));
			break;
		}
	}
	if (nodeid>=ctdb->num_nodes) {
		DEBUG(0, ("Refused connection from unknown node %s\n", incoming_node));
		close(fd);
		return;
	}

	in = talloc_zero(ctcp, struct ctdb_incoming);
	in->fd = fd;
	in->ctdb = ctdb;

	set_nonblocking(in->fd);
	set_close_on_exec(in->fd);

        setsockopt(in->fd,SOL_SOCKET,SO_KEEPALIVE,(char *)&one,sizeof(one));

	in->queue = ctdb_queue_setup(ctdb, in, in->fd, CTDB_TCP_ALIGNMENT, 
				     ctdb_tcp_read_cb, in);
}


/*
  automatically find which address to listen on
*/
static int ctdb_tcp_listen_automatic(struct ctdb_context *ctdb)
{
	struct ctdb_tcp *ctcp = talloc_get_type(ctdb->private_data,
						struct ctdb_tcp);
        struct sockaddr_in sock;
	int lock_fd, i;
	const char *lock_path = "/tmp/.ctdb_socket_lock";
	struct flock lock;

	/* in order to ensure that we don't get two nodes with the
	   same adddress, we must make the bind() and listen() calls
	   atomic. The SO_REUSEADDR setsockopt only prevents double
	   binds if the first socket is in LISTEN state  */
	lock_fd = open(lock_path, O_RDWR|O_CREAT, 0666);
	if (lock_fd == -1) {
		DEBUG(0,("Unable to open %s\n", lock_path));
		return -1;
	}

	lock.l_type = F_WRLCK;
	lock.l_whence = SEEK_SET;
	lock.l_start = 0;
	lock.l_len = 1;
	lock.l_pid = 0;

	if (fcntl(lock_fd, F_SETLKW, &lock) != 0) {
		DEBUG(0,("Unable to lock %s\n", lock_path));
		close(lock_fd);
		return -1;
	}

	for (i=0;i<ctdb->num_nodes;i++) {
		ZERO_STRUCT(sock);
#ifdef HAVE_SOCK_SIN_LEN
		sock.sin_len = sizeof(sock);
#endif
		sock.sin_port = htons(ctdb->nodes[i]->address.port);
		sock.sin_family = PF_INET;
		if (ctdb_tcp_get_address(ctdb, ctdb->nodes[i]->address.address, 
					 &sock.sin_addr) != 0) {
			continue;
		}
		
		if (bind(ctcp->listen_fd, (struct sockaddr * )&sock, 
			 sizeof(sock)) == 0) {
			break;
		}
	}
	
	if (i == ctdb->num_nodes) {
		DEBUG(0,("Unable to bind to any of the node addresses - giving up\n"));
		goto failed;
	}
	ctdb->address = ctdb->nodes[i]->address;
	ctdb->name = talloc_asprintf(ctdb, "%s:%u", 
				     ctdb->address.address, 
				     ctdb->address.port);
	ctdb->vnn = ctdb->nodes[i]->vnn;
	ctdb->nodes[i]->flags &= ~NODE_FLAGS_DISCONNECTED;
	DEBUG(1,("ctdb chose network address %s:%u vnn %u\n", 
		 ctdb->address.address, 
		 ctdb->address.port, 
		 ctdb->vnn));

	if (listen(ctcp->listen_fd, 10) == -1) {
		goto failed;
	}

	event_add_fd(ctdb->ev, ctcp, ctcp->listen_fd, EVENT_FD_READ|EVENT_FD_AUTOCLOSE, 
		     ctdb_listen_event, ctdb);	

	close(lock_fd);
	return 0;
	
failed:
	close(lock_fd);
	close(ctcp->listen_fd);
	ctcp->listen_fd = -1;
	return -1;
}


/*
  listen on our own address
*/
int ctdb_tcp_listen(struct ctdb_context *ctdb)
{
	struct ctdb_tcp *ctcp = talloc_get_type(ctdb->private_data,
						struct ctdb_tcp);
        struct sockaddr_in sock;
	int one = 1;

	ctcp->listen_fd = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (ctcp->listen_fd == -1) {
		ctdb_set_error(ctdb, "socket failed\n");
		return -1;
	}

	set_close_on_exec(ctcp->listen_fd);

        setsockopt(ctcp->listen_fd,SOL_SOCKET,SO_REUSEADDR,(char *)&one,sizeof(one));

	/* we can either auto-bind to the first available address, or we can
	   use a specified address */
	if (!ctdb->address.address) {
		return ctdb_tcp_listen_automatic(ctdb);
	}

	ZERO_STRUCT(sock);
#ifdef HAVE_SOCK_SIN_LEN
	sock.sin_len = sizeof(sock);
#endif
	sock.sin_port = htons(ctdb->address.port);
	sock.sin_family = PF_INET;
	
	if (ctdb_tcp_get_address(ctdb, ctdb->address.address, 
				 &sock.sin_addr) != 0) {
		goto failed;
	}
	
	if (bind(ctcp->listen_fd, (struct sockaddr * )&sock, sizeof(sock)) != 0) {
		goto failed;
	}

	if (listen(ctcp->listen_fd, 10) == -1) {
		goto failed;
	}

	event_add_fd(ctdb->ev, ctcp, ctcp->listen_fd, EVENT_FD_READ|EVENT_FD_AUTOCLOSE, 
		     ctdb_listen_event, ctdb);	

	return 0;

failed:
	close(ctcp->listen_fd);
	ctcp->listen_fd = -1;
	return -1;
}

