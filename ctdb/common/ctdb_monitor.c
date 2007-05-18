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
  called when a CTDB_REQ_KEEPALIVE packet comes in
*/
void ctdb_request_keepalive(struct ctdb_context *ctdb, struct ctdb_req_header *hdr)
{
	struct ctdb_req_keepalive *r = (struct ctdb_req_keepalive *)hdr;
	struct ctdb_node *node = NULL;
	int i;

	for (i=0;i<ctdb->num_nodes;i++) {
		if (ctdb->nodes[i]->vnn == r->hdr.srcnode) {
			node = ctdb->nodes[i];
			break;
		}
	}
	if (!node) {
		DEBUG(0,(__location__ " Keepalive received from node not in ctdb->nodes : %u\n", r->hdr.srcnode));
		return;
	}

	node->rx_cnt++;
}


static void ctdb_check_for_dead_nodes(struct event_context *ev, struct timed_event *te, 
			   struct timeval t, void *private_data)
{
	struct ctdb_context *ctdb = talloc_get_type(private_data, struct ctdb_context);
	int i;
	TALLOC_CTX *mem_ctx = talloc_new(ctdb);

	/* send a keepalive to all other nodes, unless */
	for (i=0;i<ctdb->num_nodes;i++) {
		if (!(ctdb->nodes[i]->flags & NODE_FLAGS_CONNECTED)) {
			continue;
		}
		if (ctdb->nodes[i]->vnn == ctdb_get_vnn(ctdb)) {
			continue;
		}

		if (ctdb->nodes[i]->rx_cnt == 0) {
			ctdb->nodes[i]->dead_count++;
		} else {
			ctdb->nodes[i]->dead_count = 0;
		}

		if (ctdb->nodes[i]->dead_count>=3) {
			ctdb->nodes[i]->flags &= ~NODE_FLAGS_CONNECTED;
			/* should probably tell the transport layer
			   to kill the sockets as well 
			*/
			continue;
		}

		ctdb_send_keepalive(ctdb, mem_ctx, i);
		ctdb->nodes[i]->rx_cnt = 0;
	}



	
	talloc_free(mem_ctx);

	event_add_timed(ctdb->ev, ctdb, 
			timeval_current_ofs(CTDB_MONITORING_TIMEOUT, 0), 
			ctdb_check_for_dead_nodes, ctdb);
}

int ctdb_start_monitoring(struct ctdb_context *ctdb)
{
	event_add_timed(ctdb->ev, ctdb, 
			timeval_current_ofs(CTDB_MONITORING_TIMEOUT, 0), 
			ctdb_check_for_dead_nodes, ctdb);
	return 0;
}


