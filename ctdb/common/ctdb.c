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

const char *ctdb_errstr(struct ctdb_context *ctdb)
{
	return ctdb->err_msg;
}


/*
  remember an error message
*/
void ctdb_set_error(struct ctdb_context *ctdb, const char *fmt, ...)
{
	va_list ap;
	talloc_free(ctdb->err_msg);
	va_start(ap, fmt);
	ctdb->err_msg = talloc_vasprintf(ctdb, fmt, ap);
	va_end(ap);
}

/*
  choose the transport we will use
*/
int ctdb_set_transport(struct ctdb_context *ctdb, const char *transport)
{
	int ctdb_tcp_init(struct ctdb_context *ctdb);

	if (strcmp(transport, "tcp") == 0) {
		return ctdb_tcp_init(ctdb);
	}
	ctdb_set_error(ctdb, "Unknown transport '%s'\n", transport);
	return -1;
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
	node->ctdb = ctdb;
	node->name = talloc_asprintf(node, "%s:%u", 
				     node->address.address, 
				     node->address.port);

	if (ctdb->methods->add_node(node) != 0) {
		talloc_free(node);
		return -1;
	}

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
  setup the local node address
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
	/* when we have a separate daemon this will need to be a real
	   file, not a TDB_INTERNAL, so the parent can access it to
	   for ltdb bypass */
	ctdb->ltdb = tdb_open(name, 0, TDB_INTERNAL, 0, 0);
	if (ctdb->ltdb == NULL) {
		ctdb_set_error(ctdb, "Failed to open tdb %s\n", name);
		return -1;
	}
	return 0;
}

/*
  start the protocol going
*/
int ctdb_start(struct ctdb_context *ctdb)
{
	return ctdb->methods->start(ctdb);
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

/*
  check if two addresses are the same
*/
bool ctdb_same_address(struct ctdb_address *a1, struct ctdb_address *a2)
{
	return strcmp(a1->address, a2->address) == 0 && a1->port == a2->port;
}

/*
  called by the transport layer when a packet comes in
*/
static void ctdb_recv_pkt(struct ctdb_context *ctdb, uint8_t *data, uint32_t length)
{
	printf("received pkt of length %d\n", length);
}

/*
  called by the transport layer when a node is dead
*/
static void ctdb_node_dead(struct ctdb_node *node)
{
	printf("node %s is dead\n", node->name);
}

static const struct ctdb_upcalls ctdb_upcalls = {
	.recv_pkt  = ctdb_recv_pkt,
	.node_dead = ctdb_node_dead
};

/*
  initialise the ctdb daemon. 

  NOTE: In current code the daemon does not fork. This is for testing purposes only
  and to simplify the code.
*/
struct ctdb_context *ctdb_init(struct event_context *ev)
{
	struct ctdb_context *ctdb;

	ctdb = talloc_zero(ev, struct ctdb_context);
	ctdb->ev = ev;
	ctdb->upcalls = &ctdb_upcalls;

	return ctdb;
}

