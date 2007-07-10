/* 
   ctdb recovery code

   Copyright (C) Ronnie Sahlberg  2007
   Copyright (C) Andrew Tridgell  2007

   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 3 of the License, or (at your option) any later version.

   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with this library; if not, see <http://www.gnu.org/licenses/>.
*/
#include "includes.h"
#include "lib/events/events.h"
#include "lib/tdb/include/tdb.h"
#include "system/network.h"
#include "system/filesys.h"
#include "system/wait.h"
#include "../include/ctdb_private.h"


#define TAKEOVER_TIMEOUT() timeval_current_ofs(5,0)

#define CTDB_ARP_INTERVAL 1
#define CTDB_ARP_REPEAT   3

struct ctdb_takeover_arp {
	struct ctdb_context *ctdb;
	uint32_t count;
	struct sockaddr_in sin;
	struct ctdb_tcp_list *tcp_list;
};

/*
  lists of tcp endpoints
 */
struct ctdb_tcp_list {
	struct ctdb_tcp_list *prev, *next;
	uint32_t vnn;
	struct sockaddr_in saddr;
	struct sockaddr_in daddr;
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
	struct ctdb_tcp_list *tcp;

	ret = ctdb_sys_send_arp(&arp->sin, arp->ctdb->takeover.interface);
	if (ret != 0) {
		DEBUG(0,(__location__ "sending of arp failed (%s)\n", strerror(errno)));
	}

	for (tcp=arp->tcp_list;tcp;tcp=tcp->next) {
		DEBUG(2,("sending tcp tickle ack for %u->%s:%u\n",
			 (unsigned)ntohs(tcp->daddr.sin_port), 
			 inet_ntoa(tcp->saddr.sin_addr),
			 (unsigned)ntohs(tcp->saddr.sin_port)));
		ret = ctdb_sys_send_ack(&tcp->saddr, &tcp->daddr);
		if (ret != 0) {
			DEBUG(0,(__location__ " Failed to send tcp tickle ack for %s\n",
				 inet_ntoa(tcp->saddr.sin_addr)));
		}
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
	struct ctdb_takeover_arp *arp;
	char *ip = inet_ntoa(sin->sin_addr);
	struct ctdb_tcp_list *tcp;

	if (ctdb_sys_have_ip(ip)) {
		return 0;
	}

	DEBUG(0,("Takover of IP %s/%u on interface %s\n", 
		 ip, ctdb->nodes[ctdb->vnn]->public_netmask_bits, 
		 ctdb->takeover.interface));
	ret = ctdb_event_script(ctdb, "takeip %s %s %u",
				ctdb->takeover.interface, 
				ip,
				ctdb->nodes[ctdb->vnn]->public_netmask_bits);
	if (ret != 0) {
		DEBUG(0,(__location__ " Failed to takeover IP %s on interface %s\n",
			 ip, ctdb->takeover.interface));
		return -1;
	}

	if (!ctdb->takeover.last_ctx) {
		ctdb->takeover.last_ctx = talloc_new(ctdb);
		CTDB_NO_MEMORY(ctdb, ctdb->takeover.last_ctx);
	}

	arp = talloc_zero(ctdb->takeover.last_ctx, struct ctdb_takeover_arp);
	CTDB_NO_MEMORY(ctdb, arp);
	
	arp->ctdb = ctdb;
	arp->sin = *sin;

	/* add all of the known tcp connections for this IP to the
	   list of tcp connections to send tickle acks for */
	for (tcp=ctdb->tcp_list;tcp;tcp=tcp->next) {
		if (sin->sin_addr.s_addr == tcp->daddr.sin_addr.s_addr) {
			struct ctdb_tcp_list *t2 = talloc(arp, struct ctdb_tcp_list);
			CTDB_NO_MEMORY(ctdb, t2);
			*t2 = *tcp;
			DLIST_ADD(arp->tcp_list, t2);
		}
	}

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
	TDB_DATA data;
	char *ip = inet_ntoa(sin->sin_addr);
	int ret;
	struct ctdb_tcp_list *tcp;

	if (!ctdb_sys_have_ip(ip)) {
		return 0;
	}

	DEBUG(0,("Release of IP %s/%u on interface %s\n", 
		 ip, ctdb->nodes[ctdb->vnn]->public_netmask_bits, 
		 ctdb->takeover.interface));

	/* stop any previous arps */
	talloc_free(ctdb->takeover.last_ctx);
	ctdb->takeover.last_ctx = NULL;

	ret = ctdb_event_script(ctdb, "releaseip %s %s %u",
				ctdb->takeover.interface, 
				ip,
				ctdb->nodes[ctdb->vnn]->public_netmask_bits);
	if (ret != 0) {
		DEBUG(0,(__location__ " Failed to release IP %s on interface %s\n",
			 ip, ctdb->takeover.interface));
		return -1;
	}

	/* send a message to all clients of this node telling them
	   that the cluster has been reconfigured and they should
	   release any sockets on this IP */
	data.dptr = (uint8_t *)ip;
	data.dsize = strlen(ip)+1;

	ctdb_daemon_send_message(ctdb, ctdb->vnn, CTDB_SRVID_RELEASE_IP, data);

	/* tell other nodes about any tcp connections we were holding with this IP */
	for (tcp=ctdb->tcp_list;tcp;tcp=tcp->next) {
		if (tcp->vnn == ctdb->vnn && 
		    sin->sin_addr.s_addr == tcp->daddr.sin_addr.s_addr) {
			struct ctdb_control_tcp_vnn t;

			t.vnn  = ctdb->vnn;
			t.src  = tcp->saddr;
			t.dest = tcp->daddr;

			data.dptr = (uint8_t *)&t;
			data.dsize = sizeof(t);

			ctdb_daemon_send_control(ctdb, CTDB_BROADCAST_VNNMAP, 0, 
						 CTDB_CONTROL_TCP_ADD,
						 0, CTDB_CTRL_FLAG_NOREPLY, data, NULL, NULL);
		}
	}


	return 0;
}


/*
  setup the event script
*/
int ctdb_set_event_script(struct ctdb_context *ctdb, const char *script)
{
	ctdb->takeover.event_script = talloc_strdup(ctdb, script);
	CTDB_NO_MEMORY(ctdb, ctdb->takeover.event_script);
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
	while (nlines > 0 && strcmp(lines[nlines-1], "") == 0) {
		nlines--;
	}

	if (nlines != ctdb->num_nodes) {
		DEBUG(0,("Number of lines in %s does not match number of nodes!\n", alist));
		talloc_free(lines);
		return -1;
	}

	for (i=0;i<nlines;i++) {
		char *p;
		struct in_addr in;

		ctdb->nodes[i]->public_address = talloc_strdup(ctdb->nodes[i], lines[i]);
		CTDB_NO_MEMORY(ctdb, ctdb->nodes[i]->public_address);
		ctdb->nodes[i]->takeover_vnn = -1;

		/* see if they supplied a netmask length */
		p = strchr(ctdb->nodes[i]->public_address, '/');
		if (!p) {
			DEBUG(0,("You must supply a netmask for public address %s\n",
				 ctdb->nodes[i]->public_address));
			return -1;
		}
		*p = 0;
		ctdb->nodes[i]->public_netmask_bits = atoi(p+1);

		if (ctdb->nodes[i]->public_netmask_bits > 32) {
			DEBUG(0, ("Illegal netmask for IP %s\n", ctdb->nodes[i]->public_address));
			return -1;
		}

		if (inet_aton(ctdb->nodes[i]->public_address, &in) == 0) {
			DEBUG(0,("Badly formed IP '%s' in public address list\n", ctdb->nodes[i]->public_address));
			return -1;
		}
	}

	talloc_free(lines);
	return 0;
}

/*
  see if two IPs are on the same subnet
 */
static bool ctdb_same_subnet(const char *ip1, const char *ip2, uint8_t netmask_bits)
{
	struct in_addr in1, in2;
	uint32_t mask;

	inet_aton(ip1, &in1);
	inet_aton(ip2, &in2);

	mask = ~((1LL<<(32-netmask_bits))-1);

	if ((ntohl(in1.s_addr) & mask) != (ntohl(in2.s_addr) & mask)) {
		return false;
	}

	return true;
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
				if ((nodemap->nodes[j].flags & NODE_FLAGS_CONNECTED) &&
				    ctdb_same_subnet(ctdb->nodes[j]->public_address, 
						     ctdb->nodes[i]->public_address, 
						     ctdb->nodes[j]->public_netmask_bits)) {
					ctdb->nodes[i]->takeover_vnn = nodemap->nodes[j].vnn;
					break;
				}
			}
			if (j == i) {
				DEBUG(0,(__location__ " No node available on same network to take %s\n",
					 ctdb->nodes[i]->public_address));
				ctdb->nodes[i]->takeover_vnn = -1;	
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


/*
  called by a client to inform us of a TCP connection that it is managing
  that should tickled with an ACK when IP takeover is done
 */
int32_t ctdb_control_tcp_client(struct ctdb_context *ctdb, uint32_t client_id, uint32_t vnn,
				TDB_DATA indata)
{
	struct ctdb_client *client = ctdb_reqid_find(ctdb, client_id, struct ctdb_client);
	struct ctdb_control_tcp *p = (struct ctdb_control_tcp *)indata.dptr;
	struct ctdb_tcp_list *tcp;
	struct ctdb_control_tcp_vnn t;
	int ret;
	TDB_DATA data;

	tcp = talloc(client, struct ctdb_tcp_list);
	CTDB_NO_MEMORY(ctdb, tcp);

	tcp->vnn   = vnn;
	tcp->saddr = p->src;
	tcp->daddr = p->dest;

	DLIST_ADD(client->tcp_list, tcp);

	t.vnn  = vnn;
	t.src  = p->src;
	t.dest = p->dest;

	data.dptr = (uint8_t *)&t;
	data.dsize = sizeof(t);

	/* tell all nodes about this tcp connection */
	ret = ctdb_daemon_send_control(ctdb, CTDB_BROADCAST_VNNMAP, 0, 
				       CTDB_CONTROL_TCP_ADD,
				       0, CTDB_CTRL_FLAG_NOREPLY, data, NULL, NULL);
	if (ret != 0) {
		DEBUG(0,(__location__ " Failed to send CTDB_CONTROL_TCP_ADD\n"));
		return -1;
	}

	return 0;
}

/*
  see if two sockaddr_in are the same
 */
static bool same_sockaddr_in(struct sockaddr_in *in1, struct sockaddr_in *in2)
{
	return in1->sin_family == in2->sin_family &&
		in1->sin_port == in2->sin_port &&
		in1->sin_addr.s_addr == in2->sin_addr.s_addr;
}

/*
  find a tcp address on a list
 */
static struct ctdb_tcp_list *ctdb_tcp_find(struct ctdb_tcp_list *list, 
					   struct ctdb_tcp_list *tcp)
{
	while (list) {
		if (same_sockaddr_in(&list->saddr, &tcp->saddr) &&
		    same_sockaddr_in(&list->daddr, &tcp->daddr)) {
			return list;
		}
		list = list->next;
	}
	return NULL;
}

/*
  called by a daemon to inform us of a TCP connection that one of its
  clients managing that should tickled with an ACK when IP takeover is
  done
 */
int32_t ctdb_control_tcp_add(struct ctdb_context *ctdb, TDB_DATA indata)
{
	struct ctdb_control_tcp_vnn *p = (struct ctdb_control_tcp_vnn *)indata.dptr;
	struct ctdb_tcp_list *tcp;

	tcp = talloc(ctdb, struct ctdb_tcp_list);
	CTDB_NO_MEMORY(ctdb, tcp);

	tcp->vnn   = p->vnn;
	tcp->saddr = p->src;
	tcp->daddr = p->dest;

	if (NULL == ctdb_tcp_find(ctdb->tcp_list, tcp)) {
		DLIST_ADD(ctdb->tcp_list, tcp);
		DEBUG(2,("Added tickle info for %s:%u from vnn %u\n",
			 inet_ntoa(tcp->daddr.sin_addr), ntohs(tcp->daddr.sin_port),
			 tcp->vnn));
	} else {
		DEBUG(4,("Already had tickle info for %s:%u from vnn %u\n",
			 inet_ntoa(tcp->daddr.sin_addr), ntohs(tcp->daddr.sin_port),
			 tcp->vnn));
	}

	return 0;
}

/*
  called by a daemon to inform us of a TCP connection that one of its
  clients managing that should tickled with an ACK when IP takeover is
  done
 */
int32_t ctdb_control_tcp_remove(struct ctdb_context *ctdb, TDB_DATA indata)
{
	struct ctdb_control_tcp_vnn *p = (struct ctdb_control_tcp_vnn *)indata.dptr;
	struct ctdb_tcp_list t, *tcp;

	t.vnn   = p->vnn;
	t.saddr = p->src;
	t.daddr = p->dest;

	tcp = ctdb_tcp_find(ctdb->tcp_list, &t);
	if (tcp) {
		DEBUG(2,("Removed tickle info for %s:%u from vnn %u\n",
			 inet_ntoa(tcp->daddr.sin_addr), ntohs(tcp->daddr.sin_port),
			 tcp->vnn));
		DLIST_REMOVE(ctdb->tcp_list, tcp);
		talloc_free(tcp);
	}

	return 0;
}


/*
  called when a daemon restarts - wipes all tcp entries from that vnn
 */
int32_t ctdb_control_startup(struct ctdb_context *ctdb, uint32_t vnn)
{
	struct ctdb_tcp_list *tcp, *next;	
	for (tcp=ctdb->tcp_list;tcp;tcp=next) {
		next = tcp->next;
		if (tcp->vnn == vnn) {
			DLIST_REMOVE(ctdb->tcp_list, tcp);
			talloc_free(tcp);
		}

		/* and tell the new guy about any that he should have
		   from us */
		if (tcp->vnn == ctdb->vnn) {
			struct ctdb_control_tcp_vnn t;
			TDB_DATA data;

			t.vnn  = tcp->vnn;
			t.src  = tcp->saddr;
			t.dest = tcp->daddr;

			data.dptr = (uint8_t *)&t;
			data.dsize = sizeof(t);

			ctdb_daemon_send_control(ctdb, vnn, 0, 
						 CTDB_CONTROL_TCP_ADD,
						 0, CTDB_CTRL_FLAG_NOREPLY, data, NULL, NULL);
		}
	}
	return 0;
}


/*
  called when a client structure goes away - hook to remove
  elements from the tcp_list in all daemons
 */
void ctdb_takeover_client_destructor_hook(struct ctdb_client *client)
{
	while (client->tcp_list) {
		TDB_DATA data;
		struct ctdb_control_tcp_vnn p;
		struct ctdb_tcp_list *tcp = client->tcp_list;
		DLIST_REMOVE(client->tcp_list, tcp);
		p.vnn = tcp->vnn;
		p.src = tcp->saddr;
		p.dest = tcp->daddr;
		data.dptr = (uint8_t *)&p;
		data.dsize = sizeof(p);
		ctdb_daemon_send_control(client->ctdb, CTDB_BROADCAST_VNNMAP, 0, 
					 CTDB_CONTROL_TCP_REMOVE,
					 0, CTDB_CTRL_FLAG_NOREPLY, data, NULL, NULL);
		talloc_free(tcp);
	}
}


/*
  release all IPs on shutdown
 */
void ctdb_release_all_ips(struct ctdb_context *ctdb)
{
	int i;

	if (!ctdb->takeover.enabled) {
		return;
	}

	for (i=0;i<ctdb->num_nodes;i++) {
		struct ctdb_node *node = ctdb->nodes[i];
		if (ctdb_sys_have_ip(node->public_address)) {
			ctdb_event_script(ctdb, "releaseip %s %s %u",
					  ctdb->takeover.interface, 
					  node->public_address,
					  node->public_netmask_bits);
		}
	}
}
