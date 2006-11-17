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

struct ctdb_context *ctdb_init(TALLOC_CTX *mem_ctx)
{
	struct ctdb_context *ctdb;

	ctdb = talloc_zero(mem_ctx, struct ctdb_context);
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
	printf("connection to node %s:%u is readable\n", node->address, node->port);
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
	    errno != 0) {
		close(node->fd);
		event_add_timed(ctdb->ev, node, timeval_current_ofs(1, 0), 
				ctdb_node_connect, node);
		return;
	}

	printf("Established connection to %s:%u\n", node->address, node->port);
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
	struct ctdb_node *node = talloc_get_type(node, struct ctdb_node);
	struct ctdb_context *ctdb = node->ctdb;
        unsigned v;
        struct sockaddr_in sock_out;

	node->fd = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);

	v = fcntl(node->fd, F_GETFL, 0);
        fcntl(node->fd, F_SETFL, v | O_NONBLOCK);

	inet_pton(AF_INET, node->address, &sock_out.sin_addr);
	sock_out.sin_port = htons(node->port);
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
  add a node to the list of active nodes
*/
static int ctdb_add_node(struct ctdb_context *ctdb, char *nstr)
{
	struct ctdb_node *node;

	/* expected to be in IP:port format */
	char *p;
	p = strchr(nstr, ':');
	if (p == NULL) {
		ctdb_set_error(ctdb, "Badly formed node '%s'\n", nstr);
		return -1;
	}
	*p++ = 0;

	node = talloc(ctdb, struct ctdb_node);
	node->address = talloc_strdup(node, nstr);
	node->port = strtoul(p, NULL, 0);
	node->fd = -1;
	node->ctdb = ctdb;

	DLIST_ADD(ctdb->nodes, node);	
	event_add_timed(ctdb->ev, node, timeval_zero(), ctdb_node_connect, node);
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

