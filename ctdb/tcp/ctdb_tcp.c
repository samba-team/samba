/* 
   ctdb over TCP

   Copyright (C) Andrew Tridgell  2006

   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2 of the License, or (at your option) any later version.

   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with this library; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

#include "includes.h"
#include "lib/events/events.h"
#include "system/network.h"
#include "system/filesys.h"
#include "ctdb_private.h"
#include "ctdb_tcp.h"

/*
  called when socket becomes readable
*/
static void ctdb_node_read(struct event_context *ev, struct fd_event *fde, 
			   uint16_t flags, void *private)
{
	struct ctdb_node *node = talloc_get_type(private, struct ctdb_node);
	printf("connection to node %s:%u is readable\n", 
	       node->address.address, node->address.port);
	event_set_fd_flags(fde, 0);
}

static void ctdb_node_connect(struct event_context *ev, struct timed_event *te, 
			      struct timeval t, void *private);

/*
  called when socket becomes writeable on connect
*/
static void ctdb_node_connect_write(struct event_context *ev, struct fd_event *fde, 
				    uint16_t flags, void *private)
{
	struct ctdb_node *node = talloc_get_type(private, struct ctdb_node);
	struct ctdb_tcp_node *tnode = talloc_get_type(node->private, 
						      struct ctdb_tcp_node);
	struct ctdb_context *ctdb = node->ctdb;
	int error;
	socklen_t len;

	if (getsockopt(tnode->fd, SOL_SOCKET, SO_ERROR, &error, &len) != 0 ||
	    error != 0) {
		if (error == EINPROGRESS) {
			printf("connect in progress\n");
			return;
		}
		printf("getsockopt errno=%s\n", strerror(errno));
		talloc_free(fde);
		close(tnode->fd);
		tnode->fd = -1;
		event_add_timed(ctdb->ev, node, timeval_current_ofs(1, 0), 
				ctdb_node_connect, node);
		return;
	}

	printf("Established connection to %s:%u\n", 
	       node->address.address, node->address.port);
	talloc_free(fde);
	event_add_fd(node->ctdb->ev, node, tnode->fd, EVENT_FD_READ, 
		     ctdb_node_read, node);
}

/*
  called when we should try and establish a tcp connection to a node
*/
static void ctdb_node_connect(struct event_context *ev, struct timed_event *te, 
			      struct timeval t, void *private)
{
	struct ctdb_node *node = talloc_get_type(private, struct ctdb_node);
	struct ctdb_tcp_node *tnode = talloc_get_type(node->private, 
						      struct ctdb_tcp_node);
	struct ctdb_context *ctdb = node->ctdb;
        unsigned v;
        struct sockaddr_in sock_out;

	tnode->fd = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);

	v = fcntl(tnode->fd, F_GETFL, 0);
        fcntl(tnode->fd, F_SETFL, v | O_NONBLOCK);

	inet_pton(AF_INET, node->address.address, &sock_out.sin_addr);
	sock_out.sin_port = htons(node->address.port);
	sock_out.sin_family = PF_INET;
	
	if (connect(tnode->fd, &sock_out, sizeof(sock_out)) != 0 &&
	    errno != EINPROGRESS) {
		/* try again once a second */
		close(tnode->fd);
		event_add_timed(ctdb->ev, node, timeval_current_ofs(1, 0), 
				ctdb_node_connect, node);
		return;
	}

	/* non-blocking connect - wait for write event */
	event_add_fd(node->ctdb->ev, node, tnode->fd, EVENT_FD_WRITE, 
		     ctdb_node_connect_write, node);
}

/*
  called when an incoming connection is readable
*/
static void ctdb_incoming_read(struct event_context *ev, struct fd_event *fde, 
			       uint16_t flags, void *private)
{
	struct ctdb_incoming *in = talloc_get_type(private, struct ctdb_incoming);
	char c;
	printf("Incoming data\n");
	if (read(in->fd, &c, 1) <= 0) {
		/* socket is dead */
		close(in->fd);
		talloc_free(in);
	}
}


/*
  called when we get contacted by another node
  currently makes no attempt to check if the connection is really from a ctdb
  node in our cluster
*/
static void ctdb_listen_event(struct event_context *ev, struct fd_event *fde, 
			      uint16_t flags, void *private)
{
	struct ctdb_context *ctdb;
	struct ctdb_tcp *ctcp;
	struct sockaddr_in addr;
	socklen_t len;
	int fd;
	struct ctdb_incoming *in;

	ctdb = talloc_get_type(private, struct ctdb_context);
	ctcp = talloc_get_type(ctdb->private, struct ctdb_tcp);
	memset(&addr, 0, sizeof(addr));
	len = sizeof(addr);
	fd = accept(ctcp->listen_fd, (struct sockaddr *)&addr, &len);
	if (fd == -1) return;

	in = talloc(ctdb, struct ctdb_incoming);
	in->fd = fd;
	in->ctdb = ctdb;

	event_add_fd(ctdb->ev, in, in->fd, EVENT_FD_READ, 
		     ctdb_incoming_read, in);	

	printf("New incoming socket %d\n", in->fd);
}


/*
  listen on our own address
*/
static int ctdb_listen(struct ctdb_context *ctdb)
{
	struct ctdb_tcp *ctcp = talloc_get_type(ctdb->private, struct ctdb_tcp);
        struct sockaddr_in sock;
	int one = 1;

        sock.sin_port = htons(ctdb->address.port);
        sock.sin_family = PF_INET;
	inet_pton(AF_INET, ctdb->address.address, &sock.sin_addr);

        ctcp->listen_fd = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (ctcp->listen_fd == -1) {
		ctdb_set_error(ctdb, "socket failed\n");
		return -1;
        }

        setsockopt(ctcp->listen_fd,SOL_SOCKET,SO_REUSEADDR,(char *)&one,sizeof(one));

        if (bind(ctcp->listen_fd, (struct sockaddr * )&sock, sizeof(sock)) != 0) {
		ctdb_set_error(ctdb, "bind failed\n");
		close(ctcp->listen_fd);
		ctcp->listen_fd = -1;
                return -1;
        }

	if (listen(ctcp->listen_fd, 10) == -1) {
		ctdb_set_error(ctdb, "listen failed\n");
		close(ctcp->listen_fd);
		ctcp->listen_fd = -1;
		return -1;
	}

	event_add_fd(ctdb->ev, ctdb, ctcp->listen_fd, EVENT_FD_READ, 
		     ctdb_listen_event, ctdb);	

	return 0;
}

/*
  start the protocol going
*/
int ctdb_tcp_start(struct ctdb_context *ctdb)
{
	struct ctdb_node *node;

	/* listen on our own address */
	if (ctdb_listen(ctdb) != 0) return -1;

	/* startup connections to the other servers - will happen on
	   next event loop */
	for (node=ctdb->nodes;node;node=node->next) {
		if (ctdb_same_address(&ctdb->address, &node->address)) continue;
		event_add_timed(ctdb->ev, node, timeval_zero(), 
				ctdb_node_connect, node);
	}

	return 0;
}


/*
  initialise tcp portion of a ctdb node 
*/
int ctdb_tcp_add_node(struct ctdb_node *node)
{
	struct ctdb_tcp_node *tnode;
	tnode = talloc_zero(node, struct ctdb_tcp_node);
	CTDB_NO_MEMORY(node->ctdb, tnode);

	tnode->fd = -1;
	node->private = tnode;
	return 0;
}


static const struct ctdb_methods ctdb_tcp_methods = {
	.start    = ctdb_tcp_start,
	.add_node = ctdb_tcp_add_node
};

/*
  initialise tcp portion of ctdb 
*/
int ctdb_tcp_init(struct ctdb_context *ctdb)
{
	struct ctdb_tcp *ctcp;
	ctcp = talloc_zero(ctdb, struct ctdb_tcp);
	CTDB_NO_MEMORY(ctdb, ctcp);

	ctcp->listen_fd = -1;
	ctdb->private = ctcp;
	ctdb->methods = &ctdb_tcp_methods;
	return 0;
}

