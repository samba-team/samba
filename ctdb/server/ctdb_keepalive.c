/* 
   monitoring links to all other nodes to detect dead nodes


   Copyright (C) Ronnie Sahlberg 2007

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
#include "system/filesys.h"
#include "system/wait.h"
#include "../include/ctdb_private.h"


/*
  see if any nodes are dead
 */
static void ctdb_check_for_dead_nodes(struct event_context *ev, struct timed_event *te, 
				      struct timeval t, void *private_data)
{
	struct ctdb_context *ctdb = talloc_get_type(private_data, struct ctdb_context);
	int i;

	/* send a keepalive to all other nodes, unless */
	for (i=0;i<ctdb->num_nodes;i++) {
		struct ctdb_node *node = ctdb->nodes[i];

		if (node->flags & NODE_FLAGS_DELETED) {
			continue;
		}

		if (node->pnn == ctdb->pnn) {
			continue;
		}
		
		if (node->flags & NODE_FLAGS_DISCONNECTED) {
			/* it might have come alive again */
			if (node->rx_cnt != 0) {
				ctdb_node_connected(node);
			}
			continue;
		}


		if (node->rx_cnt == 0) {
			node->dead_count++;
		} else {
			node->dead_count = 0;
		}

		node->rx_cnt = 0;

		if (node->dead_count >= ctdb->tunable.keepalive_limit) {
			DEBUG(DEBUG_NOTICE,("dead count reached for node %u\n", node->pnn));
			ctdb_node_dead(node);
			ctdb_send_keepalive(ctdb, node->pnn);
			/* maybe tell the transport layer to kill the
			   sockets as well?
			*/
			continue;
		}
		
		DEBUG(DEBUG_DEBUG,("sending keepalive to %u\n", node->pnn));
		ctdb_send_keepalive(ctdb, node->pnn);

		node->tx_cnt = 0;
	}
	
	event_add_timed(ctdb->ev, ctdb->keepalive_ctx,
			timeval_current_ofs(ctdb->tunable.keepalive_interval, 0), 
			ctdb_check_for_dead_nodes, ctdb);
}


void ctdb_start_keepalive(struct ctdb_context *ctdb)
{
	struct timed_event *te;

	ctdb->keepalive_ctx = talloc_new(ctdb);
	CTDB_NO_MEMORY_FATAL(ctdb, ctdb->keepalive_ctx);

	te = event_add_timed(ctdb->ev, ctdb->keepalive_ctx,
			     timeval_current_ofs(ctdb->tunable.keepalive_interval, 0), 
			     ctdb_check_for_dead_nodes, ctdb);
	CTDB_NO_MEMORY_FATAL(ctdb, te);

	DEBUG(DEBUG_NOTICE,("Keepalive monitoring has been started\n"));
}

void ctdb_stop_keepalive(struct ctdb_context *ctdb)
{
	talloc_free(ctdb->keepalive_ctx);
	ctdb->keepalive_ctx = NULL;
}

