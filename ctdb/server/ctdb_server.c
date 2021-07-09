/* 
   ctdb main protocol code

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

#include "lib/util/dlinklist.h"
#include "lib/util/debug.h"
#include "lib/util/samba_util.h"

#include "ctdb_private.h"
#include "ctdb_client.h"

#include "common/common.h"
#include "common/logging.h"

/*
  choose the transport we will use
*/
int ctdb_set_transport(struct ctdb_context *ctdb, const char *transport)
{
	ctdb->transport = talloc_strdup(ctdb, transport);
	CTDB_NO_MEMORY(ctdb, ctdb->transport);

	return 0;
}

/* Return the node structure for nodeip, NULL if nodeip is invalid */
struct ctdb_node *ctdb_ip_to_node(struct ctdb_context *ctdb,
				  const ctdb_sock_addr *nodeip)
{
	unsigned int nodeid;

	for (nodeid=0;nodeid<ctdb->num_nodes;nodeid++) {
		if (ctdb->nodes[nodeid]->flags & NODE_FLAGS_DELETED) {
			continue;
		}
		if (ctdb_same_ip(&ctdb->nodes[nodeid]->address, nodeip)) {
			return ctdb->nodes[nodeid];
		}
	}

	return NULL;
}

/* Return the PNN for nodeip, CTDB_UNKNOWN_PNN if nodeip is invalid */
uint32_t ctdb_ip_to_pnn(struct ctdb_context *ctdb,
			const ctdb_sock_addr *nodeip)
{
	struct ctdb_node *node;

	node = ctdb_ip_to_node(ctdb, nodeip);
	if (node == NULL) {
		return CTDB_UNKNOWN_PNN;
	}

	return node->pnn;
}

/* Load a nodes list file into a nodes array */
static int convert_node_map_to_list(struct ctdb_context *ctdb,
				    TALLOC_CTX *mem_ctx,
				    struct ctdb_node_map_old *node_map,
				    struct ctdb_node ***nodes,
				    uint32_t *num_nodes)
{
	unsigned int i;

	*nodes = talloc_zero_array(mem_ctx,
					struct ctdb_node *, node_map->num);
	CTDB_NO_MEMORY(ctdb, *nodes);
	*num_nodes = node_map->num;

	for (i = 0; i < node_map->num; i++) {
		struct ctdb_node *node;

		node = talloc_zero(*nodes, struct ctdb_node);
		CTDB_NO_MEMORY(ctdb, node);
		(*nodes)[i] = node;

		node->address = node_map->nodes[i].addr;
		node->name = talloc_asprintf(node, "%s:%u",
					     ctdb_addr_to_str(&node->address),
					     ctdb_addr_to_port(&node->address));

		node->flags = node_map->nodes[i].flags;
		if (!(node->flags & NODE_FLAGS_DELETED)) {
			node->flags = NODE_FLAGS_UNHEALTHY;
		}
		node->flags |= NODE_FLAGS_DISCONNECTED;

		node->pnn = i;
		node->ctdb = ctdb;
		node->dead_count = 0;
	}

	return 0;
}

/* Load the nodes list from a file */
void ctdb_load_nodes_file(struct ctdb_context *ctdb)
{
	struct ctdb_node_map_old *node_map;
	int ret;

	node_map = ctdb_read_nodes_file(ctdb, ctdb->nodes_file);
	if (node_map == NULL) {
		goto fail;
	}

	TALLOC_FREE(ctdb->nodes);
	ret = convert_node_map_to_list(ctdb, ctdb, node_map,
				       &ctdb->nodes, &ctdb->num_nodes);
	if (ret == -1) {
		goto fail;
	}

	talloc_free(node_map);
	return;

fail:
	DEBUG(DEBUG_ERR, ("Failed to load nodes file \"%s\"\n",
			  ctdb->nodes_file));
	talloc_free(node_map);
	exit(1);
}

/*
  setup the local node address
*/
int ctdb_set_address(struct ctdb_context *ctdb, const char *address)
{
	ctdb->address = talloc(ctdb, ctdb_sock_addr);
	CTDB_NO_MEMORY(ctdb, ctdb->address);

	if (ctdb_parse_address(ctdb, address, ctdb->address) != 0) {
		return -1;
	}

	ctdb->name = talloc_asprintf(ctdb, "%s:%u",
				     ctdb_addr_to_str(ctdb->address),
				     ctdb_addr_to_port(ctdb->address));
	return 0;
}


/*
  return the number of active nodes
*/
uint32_t ctdb_get_num_active_nodes(struct ctdb_context *ctdb)
{
	unsigned int i;
	uint32_t count=0;
	for (i=0; i < ctdb->num_nodes; i++) {
		if (!(ctdb->nodes[i]->flags & NODE_FLAGS_INACTIVE)) {
			count++;
		}
	}
	return count;
}


/*
  called when we need to process a packet. This can be a requeued packet
  after a lockwait, or a real packet from another node
*/
void ctdb_input_pkt(struct ctdb_context *ctdb, struct ctdb_req_header *hdr)
{
	TALLOC_CTX *tmp_ctx;

	/* place the packet as a child of the tmp_ctx. We then use
	   talloc_free() below to free it. If any of the calls want
	   to keep it, then they will steal it somewhere else, and the
	   talloc_free() will only free the tmp_ctx */
	tmp_ctx = talloc_new(ctdb);
	talloc_steal(tmp_ctx, hdr);

	DEBUG(DEBUG_DEBUG,(__location__ " ctdb request %u of type %u length %u from "
		 "node %u to %u\n", hdr->reqid, hdr->operation, hdr->length,
		 hdr->srcnode, hdr->destnode));

	switch (hdr->operation) {
	case CTDB_REQ_CALL:
	case CTDB_REPLY_CALL:
	case CTDB_REQ_DMASTER:
	case CTDB_REPLY_DMASTER:
		/* we don't allow these calls when banned */
		if (ctdb->nodes[ctdb->pnn]->flags & NODE_FLAGS_BANNED) {
			DEBUG(DEBUG_DEBUG,(__location__ " ctdb operation %u"
				" request %u"
				" length %u from node %u to %u while node"
				" is banned\n",
				 hdr->operation, hdr->reqid,
				 hdr->length, 
				 hdr->srcnode, hdr->destnode));
			goto done;
		}

		/* for ctdb_call inter-node operations verify that the
		   remote node that sent us the call is running in the
		   same generation instance as this node
		*/
		if (ctdb->vnn_map->generation != hdr->generation) {
			DEBUG(DEBUG_DEBUG,(__location__ " ctdb operation %u"
				" request %u"
				" length %u from node %u to %u had an"
				" invalid generation id:%u while our"
				" generation id is:%u\n", 
				 hdr->operation, hdr->reqid,
				 hdr->length, 
				 hdr->srcnode, hdr->destnode, 
				 hdr->generation, ctdb->vnn_map->generation));
			goto done;
		}
	}

	switch (hdr->operation) {
	case CTDB_REQ_CALL:
		CTDB_INCREMENT_STAT(ctdb, node.req_call);
		ctdb_request_call(ctdb, hdr);
		break;

	case CTDB_REPLY_CALL:
		CTDB_INCREMENT_STAT(ctdb, node.reply_call);
		ctdb_reply_call(ctdb, hdr);
		break;

	case CTDB_REPLY_ERROR:
		CTDB_INCREMENT_STAT(ctdb, node.reply_error);
		ctdb_reply_error(ctdb, hdr);
		break;

	case CTDB_REQ_DMASTER:
		CTDB_INCREMENT_STAT(ctdb, node.req_dmaster);
		ctdb_request_dmaster(ctdb, hdr);
		break;

	case CTDB_REPLY_DMASTER:
		CTDB_INCREMENT_STAT(ctdb, node.reply_dmaster);
		ctdb_reply_dmaster(ctdb, hdr);
		break;

	case CTDB_REQ_MESSAGE:
		CTDB_INCREMENT_STAT(ctdb, node.req_message);
		ctdb_request_message(ctdb, hdr);
		break;

	case CTDB_REQ_CONTROL:
		CTDB_INCREMENT_STAT(ctdb, node.req_control);
		ctdb_request_control(ctdb, hdr);
		break;

	case CTDB_REPLY_CONTROL:
		CTDB_INCREMENT_STAT(ctdb, node.reply_control);
		ctdb_reply_control(ctdb, hdr);
		break;

	case CTDB_REQ_KEEPALIVE:
		CTDB_INCREMENT_STAT(ctdb, keepalive_packets_recv);
		ctdb_request_keepalive(ctdb, hdr);
		break;

	case CTDB_REQ_TUNNEL:
		CTDB_INCREMENT_STAT(ctdb, node.req_tunnel);
		ctdb_request_tunnel(ctdb, hdr);
		break;

	default:
		DEBUG(DEBUG_CRIT,("%s: Packet with unknown operation %u\n", 
			 __location__, hdr->operation));
		break;
	}

done:
	talloc_free(tmp_ctx);
}


/*
  called by the transport layer when a node is dead
*/
void ctdb_node_dead(struct ctdb_node *node)
{
	if (node->ctdb->methods == NULL) {
		DBG_ERR("Can not restart transport while shutting down\n");
		return;
	}
	node->ctdb->methods->restart(node);

	if (node->flags & NODE_FLAGS_DISCONNECTED) {
		DEBUG(DEBUG_INFO,("%s: node %s is already marked disconnected: %u connected\n", 
			 node->ctdb->name, node->name, 
			 node->ctdb->num_connected));
		return;
	}
	node->ctdb->num_connected--;
	node->flags |= NODE_FLAGS_DISCONNECTED | NODE_FLAGS_UNHEALTHY;
	node->rx_cnt = 0;
	node->dead_count = 0;

	DEBUG(DEBUG_ERR,("%s: node %s is dead: %u connected\n",
		 node->ctdb->name, node->name, node->ctdb->num_connected));
	ctdb_daemon_cancel_controls(node->ctdb, node);
}

/*
  called by the transport layer when a node is connected
*/
void ctdb_node_connected(struct ctdb_node *node)
{
	if (!(node->flags & NODE_FLAGS_DISCONNECTED)) {
		DEBUG(DEBUG_INFO,("%s: node %s is already marked connected: %u connected\n", 
			 node->ctdb->name, node->name, 
			 node->ctdb->num_connected));
		return;
	}
	node->ctdb->num_connected++;
	node->dead_count = 0;
	node->flags &= ~NODE_FLAGS_DISCONNECTED;
	DEBUG(DEBUG_ERR,
	      ("%s: connected to %s - %u connected\n", 
	       node->ctdb->name, node->name, node->ctdb->num_connected));
}

struct queue_next {
	struct ctdb_context *ctdb;
	struct ctdb_req_header *hdr;
};


/*
  triggered when a deferred packet is due
 */
static void queue_next_trigger(struct tevent_context *ev,
			       struct tevent_timer *te,
			       struct timeval t, void *private_data)
{
	struct queue_next *q = talloc_get_type(private_data, struct queue_next);
	ctdb_input_pkt(q->ctdb, q->hdr);
	talloc_free(q);
}	

/*
  defer a packet, so it is processed on the next event loop
  this is used for sending packets to ourselves
 */
static void ctdb_defer_packet(struct ctdb_context *ctdb, struct ctdb_req_header *hdr)
{
	struct queue_next *q;
	q = talloc(ctdb, struct queue_next);
	if (q == NULL) {
		DEBUG(DEBUG_ERR,(__location__ " Failed to allocate deferred packet\n"));
		return;
	}
	q->ctdb = ctdb;
	q->hdr = talloc_memdup(q, hdr, hdr->length);
	if (q->hdr == NULL) {
		talloc_free(q);
		DEBUG(DEBUG_ERR,("Error copying deferred packet to self\n"));
		return;
	}
#if 0
	/* use this to put packets directly into our recv function */
	ctdb_input_pkt(q->ctdb, q->hdr);
#else
	tevent_add_timer(ctdb->ev, q, timeval_zero(), queue_next_trigger, q);
#endif
}


/*
  broadcast a packet to all nodes
*/
static void ctdb_broadcast_packet_all(struct ctdb_context *ctdb, 
				      struct ctdb_req_header *hdr)
{
	unsigned int i;
	for (i=0; i < ctdb->num_nodes; i++) {
		if (ctdb->nodes[i]->flags & NODE_FLAGS_DELETED) {
			continue;
		}
		hdr->destnode = ctdb->nodes[i]->pnn;
		ctdb_queue_packet(ctdb, hdr);
	}
}

/*
  broadcast a packet to all active nodes
*/
static void ctdb_broadcast_packet_active(struct ctdb_context *ctdb,
					 struct ctdb_req_header *hdr)
{
	unsigned int i;
	for (i = 0; i < ctdb->num_nodes; i++) {
		if (ctdb->nodes[i]->flags & NODE_FLAGS_INACTIVE) {
			continue;
		}

		hdr->destnode = ctdb->nodes[i]->pnn;
		ctdb_queue_packet(ctdb, hdr);
	}
}

/*
  broadcast a packet to all connected nodes
*/
static void ctdb_broadcast_packet_connected(struct ctdb_context *ctdb, 
					    struct ctdb_req_header *hdr)
{
	unsigned int i;
	for (i=0; i < ctdb->num_nodes; i++) {
		if (ctdb->nodes[i]->flags & NODE_FLAGS_DELETED) {
			continue;
		}
		if (!(ctdb->nodes[i]->flags & NODE_FLAGS_DISCONNECTED)) {
			hdr->destnode = ctdb->nodes[i]->pnn;
			ctdb_queue_packet(ctdb, hdr);
		}
	}
}

/*
  queue a packet or die
*/
void ctdb_queue_packet(struct ctdb_context *ctdb, struct ctdb_req_header *hdr)
{
	struct ctdb_node *node;

	switch (hdr->destnode) {
	case CTDB_BROADCAST_ALL:
		ctdb_broadcast_packet_all(ctdb, hdr);
		return;
	case CTDB_BROADCAST_ACTIVE:
		ctdb_broadcast_packet_active(ctdb, hdr);
		return;
	case CTDB_BROADCAST_CONNECTED:
		ctdb_broadcast_packet_connected(ctdb, hdr);
		return;
	}

	CTDB_INCREMENT_STAT(ctdb, node_packets_sent);

	if (!ctdb_validate_pnn(ctdb, hdr->destnode)) {
	  	DEBUG(DEBUG_CRIT,(__location__ " cant send to node %u that does not exist\n", 
			 hdr->destnode));
		return;
	}

	node = ctdb->nodes[hdr->destnode];

	if (node->flags & NODE_FLAGS_DELETED) {
		DEBUG(DEBUG_ERR, (__location__ " Can not queue packet to DELETED node %d\n", hdr->destnode));
		return;
	}

	if (node->pnn == ctdb->pnn) {
		ctdb_defer_packet(ctdb, hdr);
		return;
	}

	if (ctdb->methods == NULL) {
		DEBUG(DEBUG_ALERT, (__location__ " Can not queue packet. "
				    "Transport is DOWN\n"));
		return;
	}

	node->tx_cnt++;
	if (ctdb->methods->queue_pkt(node, (uint8_t *)hdr, hdr->length) != 0) {
		ctdb_fatal(ctdb, "Unable to queue packet\n");
	}
}




/*
  a valgrind hack to allow us to get opcode specific backtraces
  very ugly, and relies on no compiler optimisation!
*/
void ctdb_queue_packet_opcode(struct ctdb_context *ctdb, struct ctdb_req_header *hdr, unsigned opcode)
{
	switch (opcode) {
#define DO_OP(x) case x: ctdb_queue_packet(ctdb, hdr); break
		DO_OP(1);
		DO_OP(2);
		DO_OP(3);
		DO_OP(4);
		DO_OP(5);
		DO_OP(6);
		DO_OP(7);
		DO_OP(8);
		DO_OP(9);
		DO_OP(10);
		DO_OP(11);
		DO_OP(12);
		DO_OP(13);
		DO_OP(14);
		DO_OP(15);
		DO_OP(16);
		DO_OP(17);
		DO_OP(18);
		DO_OP(19);
		DO_OP(20);
		DO_OP(21);
		DO_OP(22);
		DO_OP(23);
		DO_OP(24);
		DO_OP(25);
		DO_OP(26);
		DO_OP(27);
		DO_OP(28);
		DO_OP(29);
		DO_OP(30);
		DO_OP(31);
		DO_OP(32);
		DO_OP(33);
		DO_OP(34);
		DO_OP(35);
		DO_OP(36);
		DO_OP(37);
		DO_OP(38);
		DO_OP(39);
		DO_OP(40);
		DO_OP(41);
		DO_OP(42);
		DO_OP(43);
		DO_OP(44);
		DO_OP(45);
		DO_OP(46);
		DO_OP(47);
		DO_OP(48);
		DO_OP(49);
		DO_OP(50);
		DO_OP(51);
		DO_OP(52);
		DO_OP(53);
		DO_OP(54);
		DO_OP(55);
		DO_OP(56);
		DO_OP(57);
		DO_OP(58);
		DO_OP(59);
		DO_OP(60);
		DO_OP(61);
		DO_OP(62);
		DO_OP(63);
		DO_OP(64);
		DO_OP(65);
		DO_OP(66);
		DO_OP(67);
		DO_OP(68);
		DO_OP(69);
		DO_OP(70);
		DO_OP(71);
		DO_OP(72);
		DO_OP(73);
		DO_OP(74);
		DO_OP(75);
		DO_OP(76);
		DO_OP(77);
		DO_OP(78);
		DO_OP(79);
		DO_OP(80);
		DO_OP(81);
		DO_OP(82);
		DO_OP(83);
		DO_OP(84);
		DO_OP(85);
		DO_OP(86);
		DO_OP(87);
		DO_OP(88);
		DO_OP(89);
		DO_OP(90);
		DO_OP(91);
		DO_OP(92);
		DO_OP(93);
		DO_OP(94);
		DO_OP(95);
		DO_OP(96);
		DO_OP(97);
		DO_OP(98);
		DO_OP(99);
		DO_OP(100);
	default: 
		ctdb_queue_packet(ctdb, hdr);
		break;
	}
}
