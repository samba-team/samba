/* 
   monitoring links to all other nodes to detect dead nodes


   Copyright (C) Ronnie Sahlberg 2007

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/

#include "includes.h"
#include "lib/events/events.h"
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

	if (ctdb->monitoring_mode==CTDB_MONITORING_DISABLED) {
		event_add_timed(ctdb->ev, ctdb, 
			timeval_current_ofs(CTDB_MONITORING_TIMEOUT, 0), 
			ctdb_check_for_dead_nodes, ctdb);
		return;
	}

	/* send a keepalive to all other nodes, unless */
	for (i=0;i<ctdb->num_nodes;i++) {
		struct ctdb_node *node = ctdb->nodes[i];
		if (node->vnn == ctdb->vnn) {
			continue;
		}
		
		/* it might have come alive again */
		if (!(node->flags & NODE_FLAGS_CONNECTED) && node->rx_cnt != 0) {
			ctdb_node_connected(node);
			continue;
		}

		if (node->rx_cnt == 0) {
			node->dead_count++;
		} else {
			node->dead_count = 0;
		}

		node->rx_cnt = 0;

		if (node->dead_count >= CTDB_MONITORING_DEAD_COUNT) {
			ctdb_node_dead(node);
			ctdb_send_keepalive(ctdb, node->vnn);
			/* maybe tell the transport layer to kill the
			   sockets as well?
			*/
			continue;
		}
		
		if (node->tx_cnt == 0 && (node->flags & NODE_FLAGS_CONNECTED)) {
			ctdb_send_keepalive(ctdb, node->vnn);
		}

		node->tx_cnt = 0;
	}
	
	event_add_timed(ctdb->ev, ctdb, 
			timeval_current_ofs(CTDB_MONITORING_TIMEOUT, 0), 
			ctdb_check_for_dead_nodes, ctdb);
}

/*
  start watching for nodes that might be dead
 */
int ctdb_start_monitoring(struct ctdb_context *ctdb)
{
	event_add_timed(ctdb->ev, ctdb, 
			timeval_current_ofs(CTDB_MONITORING_TIMEOUT, 0), 
			ctdb_check_for_dead_nodes, ctdb);
	return 0;
}


