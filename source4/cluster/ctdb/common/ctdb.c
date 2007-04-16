/* 
   ctdb main protocol code

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
#include "lib/tdb/include/tdb.h"
#include "lib/events/events.h"
#include "lib/util/dlinklist.h"
#include "system/network.h"
#include "system/filesys.h"
#include "../include/ctdb_private.h"

/*
  choose the transport we will use
*/
int ctdb_set_transport(struct ctdb_context *ctdb, const char *transport)
{
	int ctdb_tcp_init(struct ctdb_context *ctdb);
#ifdef USE_INFINIBAND
	int ctdb_ibw_init(struct ctdb_context *ctdb);
#endif /* USE_INFINIBAND */

	if (strcmp(transport, "tcp") == 0) {
		return ctdb_tcp_init(ctdb);
	}
#ifdef USE_INFINIBAND
	if (strcmp(transport, "ib") == 0) {
		return ctdb_ibw_init(ctdb);
	}
#endif /* USE_INFINIBAND */

	ctdb_set_error(ctdb, "Unknown transport '%s'\n", transport);
	return -1;
}

/*
  set some ctdb flags
*/
void ctdb_set_flags(struct ctdb_context *ctdb, unsigned flags)
{
	ctdb->flags |= flags;
}

/*
  clear some ctdb flags
*/
void ctdb_clear_flags(struct ctdb_context *ctdb, unsigned flags)
{
	ctdb->flags &= ~flags;
}

/*
  set max acess count before a dmaster migration
*/
void ctdb_set_max_lacount(struct ctdb_context *ctdb, unsigned count)
{
	ctdb->max_lacount = count;
}

/*
  add a node to the list of active nodes
*/
static int ctdb_add_node(struct ctdb_context *ctdb, char *nstr)
{
	struct ctdb_node *node, **nodep;

	nodep = talloc_realloc(ctdb, ctdb->nodes, struct ctdb_node *, ctdb->num_nodes+1);
	CTDB_NO_MEMORY(ctdb, nodep);

	ctdb->nodes = nodep;
	nodep = &ctdb->nodes[ctdb->num_nodes];
	(*nodep) = talloc_zero(ctdb->nodes, struct ctdb_node);
	CTDB_NO_MEMORY(ctdb, *nodep);
	node = *nodep;

	if (ctdb_parse_address(ctdb, node, nstr, &node->address) != 0) {
		return -1;
	}
	node->ctdb = ctdb;
	node->name = talloc_asprintf(node, "%s:%u", 
				     node->address.address, 
				     node->address.port);
	/* for now we just set the vnn to the line in the file - this
	   will change! */
	node->vnn = ctdb->num_nodes;

	if (ctdb->methods->add_node(node) != 0) {
		talloc_free(node);
		return -1;
	}

	if (ctdb_same_address(&ctdb->address, &node->address)) {
		ctdb->vnn = node->vnn;
	}

	ctdb->num_nodes++;

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
	if (ctdb_parse_address(ctdb, ctdb, address, &ctdb->address) != 0) {
		return -1;
	}
	
	ctdb->name = talloc_asprintf(ctdb, "%s:%u", 
				     ctdb->address.address, 
				     ctdb->address.port);
	return 0;
}

/*
  add a node to the list of active nodes
*/
int ctdb_set_call(struct ctdb_db_context *ctdb_db, ctdb_fn_t fn, int id)
{
	struct ctdb_registered_call *call;

	call = talloc(ctdb_db, struct ctdb_registered_call);
	call->fn = fn;
	call->id = id;

	DLIST_ADD(ctdb_db->calls, call);	
	return 0;
}

/*
  return the vnn of this node
*/
uint32_t ctdb_get_vnn(struct ctdb_context *ctdb)
{
	return ctdb->vnn;
}

/*
  return the number of nodes
*/
uint32_t ctdb_get_num_nodes(struct ctdb_context *ctdb)
{
	return ctdb->num_nodes;
}


/*
  called by the transport layer when a packet comes in
*/
static void ctdb_recv_pkt(struct ctdb_context *ctdb, uint8_t *data, uint32_t length)
{
	struct ctdb_req_header *hdr;

	if (length < sizeof(*hdr)) {
		ctdb_set_error(ctdb, "Bad packet length %d\n", length);
		return;
	}
	hdr = (struct ctdb_req_header *)data;
	if (length != hdr->length) {
		ctdb_set_error(ctdb, "Bad header length %d expected %d\n", 
			       hdr->length, length);
		return;
	}

	if (hdr->ctdb_magic != CTDB_MAGIC) {
		ctdb_set_error(ctdb, "Non CTDB packet rejected\n");
		return;
	}

	if (hdr->ctdb_version != CTDB_VERSION) {
		ctdb_set_error(ctdb, "Bad CTDB version 0x%x rejected\n", hdr->ctdb_version);
		return;
	}

	switch (hdr->operation) {
	case CTDB_REQ_CALL:
		ctdb_request_call(ctdb, hdr);
		break;

	case CTDB_REPLY_CALL:
		ctdb_reply_call(ctdb, hdr);
		break;

	case CTDB_REPLY_ERROR:
		ctdb_reply_error(ctdb, hdr);
		break;

	case CTDB_REPLY_REDIRECT:
		ctdb_reply_redirect(ctdb, hdr);
		break;

	case CTDB_REQ_DMASTER:
		ctdb_request_dmaster(ctdb, hdr);
		break;

	case CTDB_REPLY_DMASTER:
		ctdb_reply_dmaster(ctdb, hdr);
		break;

	case CTDB_REQ_MESSAGE:
		ctdb_request_message(ctdb, hdr);
		break;

	default:
		printf("Packet with unknown operation %d\n", hdr->operation);
		break;
	}
	talloc_free(hdr);
}

/*
  called by the transport layer when a node is dead
*/
static void ctdb_node_dead(struct ctdb_node *node)
{
	node->ctdb->num_connected--;
	printf("%s: node %s is dead: %d connected\n", 
	       node->ctdb->name, node->name, node->ctdb->num_connected);
}

/*
  called by the transport layer when a node is connected
*/
static void ctdb_node_connected(struct ctdb_node *node)
{
	node->ctdb->num_connected++;
	printf("%s: connected to %s - %d connected\n", 
	       node->ctdb->name, node->name, node->ctdb->num_connected);
}

/*
  wait for all nodes to be connected
*/
void ctdb_daemon_connect_wait(struct ctdb_context *ctdb)
{
	int expected = ctdb->num_nodes - 1;
	if (ctdb->flags & CTDB_FLAG_SELF_CONNECT) {
		expected++;
	}
	while (ctdb->num_connected != expected) {
		event_loop_once(ctdb->ev);
	}
}

/*
  wait until we're the only node left
*/
void ctdb_wait_loop(struct ctdb_context *ctdb)
{
	int expected = 0;
	if (ctdb->flags & CTDB_FLAG_SELF_CONNECT) {
		expected++;
	}
	while (ctdb->num_connected > expected) {
		event_loop_once(ctdb->ev);
	}
}


/*
  queue a packet or die
*/
void ctdb_queue_packet(struct ctdb_context *ctdb, struct ctdb_req_header *hdr)
{
	struct ctdb_node *node;
	node = ctdb->nodes[hdr->destnode];
	if (ctdb->methods->queue_pkt(node, (uint8_t *)hdr, hdr->length) != 0) {
		ctdb_fatal(ctdb, "Unable to queue packet\n");
	}
}


static const struct ctdb_upcalls ctdb_upcalls = {
	.recv_pkt       = ctdb_recv_pkt,
	.node_dead      = ctdb_node_dead,
	.node_connected = ctdb_node_connected
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
	ctdb->idr = idr_init(ctdb);
	ctdb->max_lacount = CTDB_DEFAULT_MAX_LACOUNT;

	return ctdb;
}

int ctdb_start(struct ctdb_context *ctdb)
{
	if (ctdb->flags&CTDB_FLAG_DAEMON_MODE) {
		return ctdbd_start(ctdb);
	}

	return ctdb->methods->start(ctdb);
}
