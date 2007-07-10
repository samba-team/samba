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

	if (ctdb->monitoring_mode == CTDB_MONITORING_DISABLED) {
		event_add_timed(ctdb->ev, ctdb->monitor_context, 
			timeval_current_ofs(ctdb->tunable.keepalive_interval, 0), 
			ctdb_check_for_dead_nodes, ctdb);
		return;
	}

	/* send a keepalive to all other nodes, unless */
	for (i=0;i<ctdb->num_nodes;i++) {
		struct ctdb_node *node = ctdb->nodes[i];
		if (node->vnn == ctdb->vnn) {
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
			DEBUG(0,("dead count reached for node %u\n", node->vnn));
			ctdb_node_dead(node);
			ctdb_send_keepalive(ctdb, node->vnn);
			/* maybe tell the transport layer to kill the
			   sockets as well?
			*/
			continue;
		}
		
		if (node->tx_cnt == 0) {
			DEBUG(5,("sending keepalive to %u\n", node->vnn));
			ctdb_send_keepalive(ctdb, node->vnn);
		}

		node->tx_cnt = 0;
	}
	
	event_add_timed(ctdb->ev, ctdb->monitor_context, 
			timeval_current_ofs(ctdb->tunable.keepalive_interval, 0), 
			ctdb_check_for_dead_nodes, ctdb);
}

static void ctdb_check_health(struct event_context *ev, struct timed_event *te, 
			      struct timeval t, void *private_data);

/*
  called when a health monitoring event script finishes
 */
static void ctdb_health_callback(struct ctdb_context *ctdb, int status, void *p)
{
	struct ctdb_node *node = ctdb->nodes[ctdb->vnn];
	TDB_DATA data;
	struct ctdb_node_flag_change c;

	event_add_timed(ctdb->ev, ctdb->monitor_context, 
			timeval_current_ofs(ctdb->tunable.monitor_interval, 0), 
			ctdb_check_health, ctdb);

	if (status != 0 && !(node->flags & NODE_FLAGS_UNHEALTHY)) {
		DEBUG(0,("monitor event failed - disabling node\n"));
		node->flags |= NODE_FLAGS_UNHEALTHY;
	} else if (status == 0 && (node->flags & NODE_FLAGS_UNHEALTHY)) {
		DEBUG(0,("monitor event OK - node re-enabled\n"));
		ctdb->nodes[ctdb->vnn]->flags &= ~NODE_FLAGS_UNHEALTHY;
	} else {
		/* no change */
		return;
	}

	c.vnn = ctdb->vnn;
	c.flags = node->flags;

	data.dptr = (uint8_t *)&c;
	data.dsize = sizeof(c);

	/* tell the other nodes that something has changed */
	ctdb_daemon_send_message(ctdb, CTDB_BROADCAST_CONNECTED,
				 CTDB_SRVID_NODE_FLAGS_CHANGED, data);

}


/*
  see if the event scripts think we are healthy
 */
static void ctdb_check_health(struct event_context *ev, struct timed_event *te, 
			      struct timeval t, void *private_data)
{
	struct ctdb_context *ctdb = talloc_get_type(private_data, struct ctdb_context);
	int ret;

	if (ctdb->monitoring_mode == CTDB_MONITORING_DISABLED) {
		event_add_timed(ctdb->ev, ctdb->monitor_context,
				timeval_current_ofs(ctdb->tunable.monitor_interval, 0), 
				ctdb_check_health, ctdb);
		return;
	}
	
	ret = ctdb_event_script_callback(ctdb, 
					 timeval_current_ofs(ctdb->tunable.script_timeout, 0),
					 ctdb->monitor_context, ctdb_health_callback, ctdb, "monitor");
	if (ret != 0) {
		DEBUG(0,("Unable to launch monitor event script\n"));
		event_add_timed(ctdb->ev, ctdb->monitor_context, 
				timeval_current_ofs(ctdb->tunable.monitor_interval, 0), 
				ctdb_check_health, ctdb);
	}	
}

/* stop any monitoring */
void ctdb_stop_monitoring(struct ctdb_context *ctdb)
{
	talloc_free(ctdb->monitor_context);
	ctdb->monitor_context = talloc_new(ctdb);
	CTDB_NO_MEMORY_FATAL(ctdb, ctdb->monitor_context);
}

/*
  start watching for nodes that might be dead
 */
void ctdb_start_monitoring(struct ctdb_context *ctdb)
{
	struct timed_event *te;

	ctdb_stop_monitoring(ctdb);

	te = event_add_timed(ctdb->ev, ctdb->monitor_context,
			     timeval_current_ofs(ctdb->tunable.keepalive_interval, 0), 
			     ctdb_check_for_dead_nodes, ctdb);
	CTDB_NO_MEMORY_FATAL(ctdb, te);

	te = event_add_timed(ctdb->ev, ctdb->monitor_context,
			     timeval_current_ofs(ctdb->tunable.monitor_interval, 0), 
			     ctdb_check_health, ctdb);
	CTDB_NO_MEMORY_FATAL(ctdb, te);
}


/*
  modify flags on a node
 */
int32_t ctdb_control_modflags(struct ctdb_context *ctdb, TDB_DATA indata)
{
	struct ctdb_node_modflags *m = (struct ctdb_node_modflags *)indata.dptr;
	TDB_DATA data;
	struct ctdb_node_flag_change c;
	struct ctdb_node *node = ctdb->nodes[ctdb->vnn];
	uint32_t old_flags = node->flags;

	node->flags |= m->set;
	node->flags &= ~m->clear;

	if (node->flags == old_flags) {
		/* no change */
		return 0;
	}

	DEBUG(0, ("Control modflags on node %u - flags now 0x%x\n", ctdb->vnn, node->flags));

	/* if we have been banned, go into recovery mode */
	c.vnn = ctdb->vnn;
	c.flags = node->flags;

	data.dptr = (uint8_t *)&c;
	data.dsize = sizeof(c);

	/* tell the other nodes that something has changed */
	ctdb_daemon_send_message(ctdb, CTDB_BROADCAST_CONNECTED,
				 CTDB_SRVID_NODE_FLAGS_CHANGED, data);

	if ((node->flags & NODE_FLAGS_BANNED) && !(old_flags & NODE_FLAGS_BANNED)) {
		/* make sure we are frozen */
		DEBUG(0,("This node has been banned - forcing freeze and recovery\n"));
		ctdb_start_freeze(ctdb);
		ctdb_release_all_ips(ctdb);
		ctdb->recovery_mode = CTDB_RECOVERY_ACTIVE;
	}
	
	return 0;
}
