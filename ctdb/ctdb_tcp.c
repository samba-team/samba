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

/*
  initialise the ctdb daemon. 

  if the ctdb dispatcher daemon has already been started then this
  does nothing. Otherwise it forks the ctdb dispatcher daemon and
  starts the daemons connecting to each other
  
  NOTE: In current code the daemon does not fork. This is for testing purposes only
  and to simplify the code.
*/

struct ctdb_context *ctdb_init(struct event_context *ev)
{
	struct ctdb_context *ctdb;

	ctdb = talloc_zero(ev, struct ctdb_context);
	ctdb->ev = ev;

	return ctdb;
}

const char *ctdb_errstr(struct ctdb_context *ctdb)
{
	return ctdb->err_msg;
}

/*
  remember an error message
*/
static void ctdb_set_error(struct ctdb_context *ctdb, const char *fmt, ...)
{
	va_list ap;
	talloc_free(ctdb->err_msg);
	va_start(ap, fmt);
	ctdb->err_msg = talloc_vasprintf(ctdb, fmt, ap);
	va_end(ap);
}

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
	struct ctdb_context *ctdb = node->ctdb;
	int error;
	socklen_t len;

	if (getsockopt(node->fd, SOL_SOCKET, SO_ERROR, &error, &len) != 0 ||
	    error != 0) {
		if (error == EINPROGRESS) {
			printf("connect in progress\n");
			return;
		}
		printf("getsockopt errno=%s\n", strerror(errno));
		talloc_free(fde);
		close(node->fd);
		node->fd = -1;
		event_add_timed(ctdb->ev, node, timeval_current_ofs(1, 0), 
				ctdb_node_connect, node);
		return;
	}

	printf("Established connection to %s:%u\n", 
	       node->address.address, node->address.port);
	talloc_free(fde);
	event_add_fd(node->ctdb->ev, node, node->fd, EVENT_FD_READ, 
		     ctdb_node_read, node);
}

/*
  called when we should try and establish a tcp connection to a node
*/
static void ctdb_node_connect(struct event_context *ev, struct timed_event *te, 
			      struct timeval t, void *private)
{
	struct ctdb_node *node = talloc_get_type(private, struct ctdb_node);
	struct ctdb_context *ctdb = node->ctdb;
        unsigned v;
        struct sockaddr_in sock_out;

	node->fd = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);

	v = fcntl(node->fd, F_GETFL, 0);
        fcntl(node->fd, F_SETFL, v | O_NONBLOCK);

	inet_pton(AF_INET, node->address.address, &sock_out.sin_addr);
	sock_out.sin_port = htons(node->address.port);
	sock_out.sin_family = PF_INET;
	
	if (connect(node->fd, &sock_out, sizeof(sock_out)) != 0 &&
	    errno != EINPROGRESS) {
		/* try again once a second */
		close(node->fd);
		event_add_timed(ctdb->ev, node, timeval_current_ofs(1, 0), 
				ctdb_node_connect, node);
		return;
	}

	/* non-blocking connect - wait for write event */
	event_add_fd(node->ctdb->ev, node, node->fd, EVENT_FD_WRITE, 
		     ctdb_node_connect_write, node);
}

/*
  parse a IP:port pair
*/
static int ctdb_parse_address(struct ctdb_context *ctdb,
			      TALLOC_CTX *mem_ctx, const char *str,
			      struct ctdb_address *address)
{
	char *p;
	p = strchr(str, ':');
	if (p == NULL) {
		ctdb_set_error(ctdb, "Badly formed node '%s'\n", str);
		return -1;
	}

	address->address = talloc_strndup(mem_ctx, str, p-str);
	address->port = strtoul(p+1, NULL, 0);
	return 0;
}


/*
  add a node to the list of active nodes
*/
static int ctdb_add_node(struct ctdb_context *ctdb, char *nstr)
{
	struct ctdb_node *node;

	node = talloc(ctdb, struct ctdb_node);
	if (ctdb_parse_address(ctdb, node, nstr, &node->address) != 0) {
		return -1;
	}
	node->fd = -1;
	node->ctdb = ctdb;

	DLIST_ADD(ctdb->nodes, node);	
	return 0;
}

/*
  setup the node list from a file
*/
int ctdb_set_nlist(struct ctdb_context *ctdb, const char *nlist)
{
	char **lines;
	int nlines;
	int i;

	lines = file_lines_load(nlist, &nlines, ctdb);
	if (lines == NULL) {
		ctdb_set_error(ctdb, "Failed to load nlist '%s'\n", nlist);
		return -1;
	}

	for (i=0;i<nlines;i++) {
		if (ctdb_add_node(ctdb, lines[i]) != 0) {
			talloc_free(lines);
			return -1;
		}
	}
	
	talloc_free(lines);
	return 0;
}

/*
  setup the node list from a file
*/
int ctdb_set_address(struct ctdb_context *ctdb, const char *address)
{
	return ctdb_parse_address(ctdb, ctdb, address, &ctdb->address);
}

/*
  add a node to the list of active nodes
*/
int ctdb_set_call(struct ctdb_context *ctdb, ctdb_fn_t fn, int id)
{
	struct ctdb_registered_call *call;

	call = talloc(ctdb, struct ctdb_registered_call);
	call->fn = fn;
	call->id = id;

	DLIST_ADD(ctdb->calls, call);	
	return 0;
}

/*
  attach to a specific database
*/
int ctdb_attach(struct ctdb_context *ctdb, const char *name, int tdb_flags, 
		int open_flags, mode_t mode)
{
	ctdb->ltdb = tdb_open(name, 0, TDB_INTERNAL, 0, 0);
	if (ctdb->ltdb == NULL) {
		ctdb_set_error(ctdb, "Failed to open tdb %s\n", name);
		return -1;
	}
	return 0;
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
	struct sockaddr_in addr;
	socklen_t len;
	int fd;
	struct ctdb_incoming *in;

	ctdb = talloc_get_type(private, struct ctdb_context);
	memset(&addr, 0, sizeof(addr));
	len = sizeof(addr);
	fd = accept(ctdb->listen_fd, (struct sockaddr *)&addr, &len);
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
        struct sockaddr_in sock;
	int one = 1;

        sock.sin_port = htons(ctdb->address.port);
        sock.sin_family = PF_INET;
	inet_pton(AF_INET, ctdb->address.address, &sock.sin_addr);

        ctdb->listen_fd = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (ctdb->listen_fd == -1) {
		ctdb_set_error(ctdb, "socket failed\n");
		return -1;
        }

        setsockopt(ctdb->listen_fd,SOL_SOCKET,SO_REUSEADDR,(char *)&one,sizeof(one));

        if (bind(ctdb->listen_fd, (struct sockaddr * )&sock, sizeof(sock)) != 0) {
		ctdb_set_error(ctdb, "bind failed\n");
		close(ctdb->listen_fd);
		ctdb->listen_fd = -1;
                return -1;
        }

	if (listen(ctdb->listen_fd, 10) == -1) {
		ctdb_set_error(ctdb, "listen failed\n");
		close(ctdb->listen_fd);
		ctdb->listen_fd = -1;
		return -1;
	}

	event_add_fd(ctdb->ev, ctdb, ctdb->listen_fd, EVENT_FD_READ, 
		     ctdb_listen_event, ctdb);	

	return 0;
}

/*
  start the protocol going
*/
int ctdb_start(struct ctdb_context *ctdb)
{
	struct ctdb_node *node;

	/* listen on our own address */
	if (ctdb_listen(ctdb) != 0) return -1;

	/* startup connections to the other servers - will happen on
	   next event loop */
	for (node=ctdb->nodes;node;node=node->next) {
		event_add_timed(ctdb->ev, node, timeval_zero(), 
				ctdb_node_connect, node);
	}

	return 0;
}

/*
  make a remote ctdb call
*/
int ctdb_call(struct ctdb_context *ctdb, TDB_DATA key, int call_id, 
	      TDB_DATA *call_data, TDB_DATA *reply_data)
{
	printf("ctdb_call not implemented\n");
	return -1;
}
