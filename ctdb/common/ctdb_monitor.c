/* 
   monitoring links to all other nodes to detect dead nodes


   Copyright (C) Ronnie Sahlberg 2007

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
		if (node->vnn == ctdb->vnn) {
			continue;
		}
		
		/* it might have come alive again */
		if (!(node->flags & NODE_FLAGS_CONNECTED) && node->rx_cnt != 0) {
			DEBUG(0,("Node %u is alive again - marking as connected\n", node->vnn));
			node->flags |= NODE_FLAGS_CONNECTED;
		}

		if (node->rx_cnt == 0) {
			node->dead_count++;
		} else {
			node->dead_count = 0;
		}

		node->rx_cnt = 0;

		if (node->dead_count >= CTDB_MONITORING_DEAD_COUNT) {
			DEBUG(0,("Node %u is dead - marking as not connected\n", node->vnn));
			node->flags &= ~NODE_FLAGS_CONNECTED;
			ctdb_daemon_cancel_controls(ctdb, node);
			/* maybe tell the transport layer to kill the
			   sockets as well?
			*/
			continue;
		}
		
		if (node->tx_cnt == 0) {
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


