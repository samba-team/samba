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

#include "replace.h"
#include "system/network.h"
#include "system/filesys.h"

#include <talloc.h>
#include <tevent.h>

#include "lib/util/time.h"
#include "lib/util/debug.h"

#include "ctdb_private.h"

#include "common/common.h"
#include "common/logging.h"

#include "ctdb_tcp.h"

static int tnode_destructor(struct ctdb_tcp_node *tnode)
{
  //	struct ctdb_node *node = talloc_find_parent_bytype(tnode, struct ctdb_node);

	if (tnode->out_fd != -1) {
		close(tnode->out_fd);
		tnode->out_fd = -1;
	}

	return 0;
}

/*
  initialise tcp portion of a ctdb node
*/
static int ctdb_tcp_add_node(struct ctdb_node *node)
{
	struct ctdb_tcp_node *tnode;
	tnode = talloc_zero(node, struct ctdb_tcp_node);
	CTDB_NO_MEMORY(node->ctdb, tnode);

	tnode->out_fd = -1;
	tnode->ctdb = node->ctdb;

	node->transport_data = tnode;
	talloc_set_destructor(tnode, tnode_destructor);

	return 0;
}

/*
  initialise transport structures
*/
static int ctdb_tcp_initialise(struct ctdb_context *ctdb)
{
	unsigned int i;

	/* listen on our own address */
	if (ctdb_tcp_listen(ctdb) != 0) {
		DEBUG(DEBUG_CRIT, (__location__ " Failed to start listening on the CTDB socket\n"));
		exit(1);
	}

	for (i=0; i < ctdb->num_nodes; i++) {
		if (ctdb->nodes[i]->flags & NODE_FLAGS_DELETED) {
			continue;
		}
		if (ctdb_tcp_add_node(ctdb->nodes[i]) != 0) {
			DEBUG(DEBUG_CRIT, ("methods->add_node failed at %d\n", i));
			return -1;
		}
	}
	
	return 0;
}

/*
  start the protocol going
*/
static int ctdb_tcp_connect_node(struct ctdb_node *node)
{
	struct ctdb_context *ctdb = node->ctdb;
	struct ctdb_tcp_node *tnode = talloc_get_type(
		node->transport_data, struct ctdb_tcp_node);

	/* startup connection to the other server - will happen on
	   next event loop */
	if (!ctdb_same_address(ctdb->address, &node->address)) {
		tnode->connect_te = tevent_add_timer(ctdb->ev, tnode,
						    timeval_zero(),
						    ctdb_tcp_node_connect,
						    node);
	}

	return 0;
}

/*
  shutdown and try to restart a connection to a node after it has been
  disconnected
*/
static void ctdb_tcp_restart(struct ctdb_node *node)
{
	struct ctdb_tcp_node *tnode = talloc_get_type(
		node->transport_data, struct ctdb_tcp_node);

	DEBUG(DEBUG_NOTICE,("Tearing down connection to dead node :%d\n", node->pnn));
	ctdb_tcp_stop_incoming(node);
	ctdb_tcp_stop_outgoing(node);

	tnode->connect_te = tevent_add_timer(node->ctdb->ev, tnode,
					     timeval_zero(),
					     ctdb_tcp_node_connect, node);
}


/*
  shutdown the transport
*/
static void ctdb_tcp_shutdown(struct ctdb_context *ctdb)
{
	uint32_t i;

	TALLOC_FREE(ctdb->transport_data);

	for (i=0; i<ctdb->num_nodes; i++) {
		TALLOC_FREE(ctdb->nodes[i]->transport_data);
	}
}

/*
  start the transport
*/
static int ctdb_tcp_start(struct ctdb_context *ctdb)
{
	unsigned int i;

	for (i=0; i < ctdb->num_nodes; i++) {
		if (ctdb->nodes[i]->flags & NODE_FLAGS_DELETED) {
			continue;
		}
		ctdb_tcp_connect_node(ctdb->nodes[i]);
	}

	return 0;
}


/*
  transport packet allocator - allows transport to control memory for packets
*/
static void *ctdb_tcp_allocate_pkt(TALLOC_CTX *mem_ctx, size_t size)
{
	/* tcp transport needs to round to 8 byte alignment to ensure
	   that we can use a length header and 64 bit elements in
	   structures */
	size = (size+(CTDB_TCP_ALIGNMENT-1)) & ~(CTDB_TCP_ALIGNMENT-1);
	return talloc_size(mem_ctx, size);
}


static const struct ctdb_methods ctdb_tcp_methods = {
	.initialise   = ctdb_tcp_initialise,
	.start        = ctdb_tcp_start,
	.queue_pkt    = ctdb_tcp_queue_pkt,
	.add_node     = ctdb_tcp_add_node,
	.connect_node = ctdb_tcp_connect_node,
	.allocate_pkt = ctdb_tcp_allocate_pkt,
	.shutdown     = ctdb_tcp_shutdown,
	.restart      = ctdb_tcp_restart,
};

static int tcp_ctcp_destructor(struct ctdb_tcp *ctcp)
{
	ctcp->ctdb->transport_data = NULL;
	ctcp->ctdb->methods = NULL;
	
	return 0;
}

		
/*
  initialise tcp portion of ctdb 
*/
int ctdb_tcp_init(struct ctdb_context *ctdb)
{
	struct ctdb_tcp *ctcp;
	ctcp = talloc_zero(ctdb, struct ctdb_tcp);
	CTDB_NO_MEMORY(ctdb, ctcp);

	ctcp->listen_fd = -1;
	ctcp->ctdb      = ctdb;
	ctdb->transport_data = ctcp;
	ctdb->methods = &ctdb_tcp_methods;

	talloc_set_destructor(ctcp, tcp_ctcp_destructor);
	return 0;
}

