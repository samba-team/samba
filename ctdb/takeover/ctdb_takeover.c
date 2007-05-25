/* 
   ctdb recovery code

   Copyright (C) Ronnie Sahlberg  2007
   Copyright (C) Andrew Tridgell  2007

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
#include "lib/tdb/include/tdb.h"
#include "system/network.h"
#include "system/filesys.h"
#include "system/wait.h"
#include "../include/ctdb_private.h"


#define TAKEOVER_TIMEOUT() timeval_current_ofs(5,0)

#define CTDB_ARP_INTERVAL 5
#define CTDB_ARP_REPEAT  24

struct ctdb_takeover_arp {
	struct ctdb_context *ctdb;
	uint32_t count;
	struct sockaddr_in sin;
};


/*
  send a gratuitous arp
 */
static void ctdb_control_send_arp(struct event_context *ev, struct timed_event *te, 
				  struct timeval t, void *private_data)
{
	struct ctdb_takeover_arp *arp = talloc_get_type(private_data, 
							struct ctdb_takeover_arp);
	int ret;

	ret = ctdb_sys_send_arp(&arp->sin, arp->ctdb->takeover.interface);
	if (ret != 0) {
		DEBUG(0,(__location__ "sending of arp failed (%s)\n", strerror(errno)));
	}

	arp->count++;

	if (arp->count == CTDB_ARP_REPEAT) {
		talloc_free(arp);
		return;
	}
	
	event_add_timed(arp->ctdb->ev, arp->ctdb->takeover.last_ctx, 
			timeval_current_ofs(CTDB_ARP_INTERVAL, 0), 
			ctdb_control_send_arp, arp);
}

/*
  take over an ip address
 */
int32_t ctdb_control_takeover_ip(struct ctdb_context *ctdb, TDB_DATA indata)
{
	int ret;
	struct sockaddr_in *sin = (struct sockaddr_in *)indata.dptr;
	char *cmdstr;
	struct ctdb_takeover_arp *arp;

	cmdstr = talloc_asprintf(ctdb, "ip addr add %s/32 dev %s 2> /dev/null",
				 inet_ntoa(sin->sin_addr), ctdb->takeover.interface);
	CTDB_NO_MEMORY(ctdb, cmdstr);

	DEBUG(0,("Taking over IP : %s\n", cmdstr));
	system(cmdstr);
	talloc_free(cmdstr);

	if (!ctdb->takeover.last_ctx) {
		ctdb->takeover.last_ctx = talloc_new(ctdb);
		CTDB_NO_MEMORY(ctdb, ctdb->takeover.last_ctx);
	}

	arp = talloc_zero(ctdb->takeover.last_ctx, struct ctdb_takeover_arp);
	CTDB_NO_MEMORY(ctdb, arp);
	
	arp->ctdb = ctdb;
	arp->sin = *sin;

	event_add_timed(arp->ctdb->ev, arp->ctdb->takeover.last_ctx, 
			timeval_zero(), ctdb_control_send_arp, arp);

	return ret;
}

/*
  release an ip address
 */
int32_t ctdb_control_release_ip(struct ctdb_context *ctdb, TDB_DATA indata)
{
	struct sockaddr_in *sin = (struct sockaddr_in *)indata.dptr;
	char *cmdstr;

	/* stop any previous arps */
	talloc_free(ctdb->takeover.last_ctx);
	ctdb->takeover.last_ctx = NULL;

	cmdstr = talloc_asprintf(ctdb, "ip addr del %s/32 dev %s 2> /dev/null",
				 inet_ntoa(sin->sin_addr), ctdb->takeover.interface);
		
	DEBUG(0,("Releasing IP : %s\n", cmdstr));
	system(cmdstr);

	talloc_free(cmdstr);

	return 0;
}


/*
  setup the public address list from a file
*/
int ctdb_set_public_addresses(struct ctdb_context *ctdb, const char *alist)
{
	char **lines;
	int nlines;
	int i;

	lines = file_lines_load(alist, &nlines, ctdb);
	if (lines == NULL) {
		ctdb_set_error(ctdb, "Failed to load public address list '%s'\n", alist);
		return -1;
	}

	if (nlines != ctdb->num_nodes) {
		DEBUG(0,("Number of lines in %s does not match number of nodes!\n"));
		talloc_free(lines);
		return -1;
	}

	for (i=0;i<nlines;i++) {
		ctdb->nodes[i]->public_address = talloc_strdup(ctdb->nodes[i], lines[i]);
		CTDB_NO_MEMORY(ctdb, ctdb->nodes[i]->public_address);
		ctdb->nodes[i]->takeover_vnn = -1;
	}

	talloc_free(lines);
	return 0;
}


/*
  make any IP alias changes for public addresses that are necessary 
 */
int ctdb_takeover_run(struct ctdb_context *ctdb, struct ctdb_node_map *nodemap)
{
	int i, j;
	int ret;

	/* work out which node will look after each public IP */
	for (i=0;i<nodemap->num;i++) {
		if (nodemap->nodes[i].flags & NODE_FLAGS_CONNECTED) {
			ctdb->nodes[i]->takeover_vnn = nodemap->nodes[i].vnn;
		} else {
			/* assign this dead nodes IP to the next higher node */
			for (j=(i+1)%nodemap->num;
			     j != i;
			     j=(j+1)%nodemap->num) {
				if (nodemap->nodes[j].flags & NODE_FLAGS_CONNECTED) {
					ctdb->nodes[i]->takeover_vnn = nodemap->nodes[j].vnn;
					break;
				}
			}
			if (j == i) {
				DEBUG(0,(__location__ " No node available to assign to??\n"));
				return -1;
			}
		}
	}	

	/* at this point ctdb->nodes[i]->takeover_vnn is the vnn which will own each IP */


	/* now tell all nodes to delete any alias that they should not
	   have.  This will be a NOOP on nodes that don't currently
	   hold the given alias */
	for (i=0;i<nodemap->num;i++) {
		/* don't talk to unconnected nodes */
		if (!(nodemap->nodes[i].flags & NODE_FLAGS_CONNECTED)) continue;

		/* tell this node to delete all of the aliases that it should not have */
		for (j=0;j<nodemap->num;j++) {
			if (ctdb->nodes[j]->takeover_vnn != nodemap->nodes[i].vnn) {
				ret = ctdb_ctrl_release_ip(ctdb, TAKEOVER_TIMEOUT(),
							   nodemap->nodes[i].vnn, 
							   ctdb->nodes[j]->public_address);
				if (ret != 0) {
					DEBUG(0,("Failed to tell vnn %u to release IP %s\n",
						 nodemap->nodes[i].vnn,
						 ctdb->nodes[j]->public_address));
					return -1;
				}
			}
		}
	}

	/* tell all nodes to get their own IPs */
	for (i=0;i<nodemap->num;i++) {
		ret = ctdb_ctrl_takeover_ip(ctdb, TAKEOVER_TIMEOUT(), 
					    ctdb->nodes[i]->takeover_vnn, 
					    ctdb->nodes[i]->public_address);
		if (ret != 0) {
			DEBUG(0,("Failed asking vnn %u to take over IP %s\n",
				 ctdb->nodes[i]->takeover_vnn, 
				 ctdb->nodes[i]->public_address));
			return -1;
		}
	}

	return 0;
}
