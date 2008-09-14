/* 
   ctdb recovery code

   Copyright (C) Ronnie Sahlberg  2007
   Copyright (C) Andrew Tridgell  2007

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
#include "lib/tdb/include/tdb.h"
#include "lib/util/dlinklist.h"
#include "system/network.h"
#include "system/filesys.h"
#include "system/wait.h"
#include "../include/ctdb_private.h"


#define TAKEOVER_TIMEOUT() timeval_current_ofs(ctdb->tunable.takeover_timeout,0)

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
  list of clients to kill on IP release
 */
struct ctdb_client_ip {
	struct ctdb_client_ip *prev, *next;
	struct ctdb_context *ctdb;
	struct sockaddr_in ip;
	uint32_t client_id;
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
		DEBUG(0,(__location__ " sending of arp failed (%s)\n", strerror(errno)));
	}

	for (tcp=arp->tcp_list;tcp;tcp=tcp->next) {
		DEBUG(2,("sending tcp tickle ack for %u->%s:%u\n",
			 (unsigned)ntohs(tcp->daddr.sin_port), 
			 inet_ntoa(tcp->saddr.sin_addr),
			 (unsigned)ntohs(tcp->saddr.sin_port)));
		ret = ctdb_sys_send_tcp(&tcp->saddr, &tcp->daddr, 0, 0, 0);
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

struct takeover_callback_state {
	struct ctdb_req_control *c;
	struct sockaddr_in *sin;
};

/*
  called when takeip event finishes
 */
static void takeover_ip_callback(struct ctdb_context *ctdb, int status, 
				 void *private_data)
{
	struct takeover_callback_state *state = 
		talloc_get_type(private_data, struct takeover_callback_state);
	struct ctdb_takeover_arp *arp;
	char *ip = inet_ntoa(state->sin->sin_addr);
	struct ctdb_tcp_list *tcp;

	ctdb_start_monitoring(ctdb);

	if (status != 0) {
		DEBUG(0,(__location__ " Failed to takeover IP %s on interface %s\n",
			 ip, ctdb->takeover.interface));
		ctdb_request_control_reply(ctdb, state->c, NULL, status, NULL);
		talloc_free(state);
		return;
	}

	if (!ctdb->takeover.last_ctx) {
		ctdb->takeover.last_ctx = talloc_new(ctdb);
		if (!ctdb->takeover.last_ctx) goto failed;
	}

	arp = talloc_zero(ctdb->takeover.last_ctx, struct ctdb_takeover_arp);
	if (!arp) goto failed;
	
	arp->ctdb = ctdb;
	arp->sin = *state->sin;

	/* add all of the known tcp connections for this IP to the
	   list of tcp connections to send tickle acks for */
	for (tcp=ctdb->tcp_list;tcp;tcp=tcp->next) {
		if (state->sin->sin_addr.s_addr == tcp->daddr.sin_addr.s_addr) {
			struct ctdb_tcp_list *t2 = talloc(arp, struct ctdb_tcp_list);
			if (t2 == NULL) goto failed;
			*t2 = *tcp;
			DLIST_ADD(arp->tcp_list, t2);
		}
	}

	event_add_timed(arp->ctdb->ev, arp->ctdb->takeover.last_ctx, 
			timeval_zero(), ctdb_control_send_arp, arp);

	/* the control succeeded */
	ctdb_request_control_reply(ctdb, state->c, NULL, 0, NULL);
	talloc_free(state);
	return;

failed:
	ctdb_request_control_reply(ctdb, state->c, NULL, -1, NULL);
	talloc_free(state);
	return;
}

/*
  take over an ip address
 */
int32_t ctdb_control_takeover_ip(struct ctdb_context *ctdb, 
				 struct ctdb_req_control *c,
				 TDB_DATA indata, 
				 bool *async_reply)
{
	int ret;
	struct takeover_callback_state *state;
	struct ctdb_public_ip *pip = (struct ctdb_public_ip *)indata.dptr;
	char *ip = inet_ntoa(pip->sin.sin_addr);


	/* update out node table */
	ctdb->nodes[pip->vnn]->takeover_vnn = pip->takeover_vnn;

	/* if our kernel already has this IP, do nothing */
	if (ctdb_sys_have_ip(ip)) {
		return 0;
	}

	state = talloc(ctdb, struct takeover_callback_state);
	CTDB_NO_MEMORY(ctdb, state);

	state->c = talloc_steal(ctdb, c);
	state->sin = talloc(ctdb, struct sockaddr_in);       
	CTDB_NO_MEMORY(ctdb, state->sin);
	*state->sin = pip->sin;

	DEBUG(0,("Takover of IP %s/%u on interface %s\n", 
		 ip, ctdb->nodes[ctdb->vnn]->public_netmask_bits, 
		 ctdb->takeover.interface));

	ctdb_stop_monitoring(ctdb);

	ret = ctdb_event_script_callback(ctdb, 
					 timeval_current_ofs(ctdb->tunable.script_timeout, 0),
					 state, takeover_ip_callback, state,
					 "takeip %s %s %u",
					 ctdb->takeover.interface, 
					 ip,
					 ctdb->nodes[ctdb->vnn]->public_netmask_bits);
	if (ret != 0) {
		DEBUG(0,(__location__ " Failed to takeover IP %s on interface %s\n",
			 ip, ctdb->takeover.interface));
		talloc_free(state);
		return -1;
	}

	/* tell ctdb_control.c that we will be replying asynchronously */
	*async_reply = true;

	return 0;
}

/*
  kill any clients that are registered with a IP that is being released
 */
static void release_kill_clients(struct ctdb_context *ctdb, struct in_addr in)
{
	struct ctdb_client_ip *ip;

	for (ip=ctdb->client_ip_list; ip; ip=ip->next) {
		if (ip->ip.sin_addr.s_addr == in.s_addr) {
			struct ctdb_client *client = ctdb_reqid_find(ctdb, 
								     ip->client_id, 
								     struct ctdb_client);
			if (client->pid != 0) {
				DEBUG(0,(__location__ " Killing client pid %u for IP %s on client_id %u\n",
					 (unsigned)client->pid, inet_ntoa(in),
					 ip->client_id));
				kill(client->pid, SIGKILL);
			}
		}
	}
}

/*
  called when releaseip event finishes
 */
static void release_ip_callback(struct ctdb_context *ctdb, int status, 
				void *private_data)
{
	struct takeover_callback_state *state = 
		talloc_get_type(private_data, struct takeover_callback_state);
	char *ip = inet_ntoa(state->sin->sin_addr);
	TDB_DATA data;
	struct ctdb_tcp_list *tcp;

	ctdb_start_monitoring(ctdb);

	/* send a message to all clients of this node telling them
	   that the cluster has been reconfigured and they should
	   release any sockets on this IP */
	data.dptr = (uint8_t *)ip;
	data.dsize = strlen(ip)+1;

	ctdb_daemon_send_message(ctdb, ctdb->vnn, CTDB_SRVID_RELEASE_IP, data);

	/* kill clients that have registered with this IP */
	release_kill_clients(ctdb, state->sin->sin_addr);
	

	/* tell other nodes about any tcp connections we were holding with this IP */
	for (tcp=ctdb->tcp_list;tcp;tcp=tcp->next) {
		if (tcp->vnn == ctdb->vnn && 
		    state->sin->sin_addr.s_addr == tcp->daddr.sin_addr.s_addr) {
			struct ctdb_control_tcp_vnn t;

			t.vnn  = ctdb->vnn;
			t.src  = tcp->saddr;
			t.dest = tcp->daddr;

			data.dptr = (uint8_t *)&t;
			data.dsize = sizeof(t);

			ctdb_daemon_send_control(ctdb, CTDB_BROADCAST_CONNECTED, 0, 
						 CTDB_CONTROL_TCP_ADD,
						 0, CTDB_CTRL_FLAG_NOREPLY, data, NULL, NULL);
		}
	}

	/* the control succeeded */
	ctdb_request_control_reply(ctdb, state->c, NULL, 0, NULL);
	talloc_free(state);
}


/*
  release an ip address
 */
int32_t ctdb_control_release_ip(struct ctdb_context *ctdb, 
				struct ctdb_req_control *c,
				TDB_DATA indata, 
				bool *async_reply)
{
	int ret;
	struct takeover_callback_state *state;
	struct ctdb_public_ip *pip = (struct ctdb_public_ip *)indata.dptr;
	char *ip = inet_ntoa(pip->sin.sin_addr);

	/* update out node table */
	ctdb->nodes[pip->vnn]->takeover_vnn = pip->takeover_vnn;

	if (!ctdb_sys_have_ip(ip)) {
		return 0;
	}

	DEBUG(0,("Release of IP %s/%u on interface %s\n", 
		 ip, ctdb->nodes[ctdb->vnn]->public_netmask_bits, 
		 ctdb->takeover.interface));

	/* stop any previous arps */
	talloc_free(ctdb->takeover.last_ctx);
	ctdb->takeover.last_ctx = NULL;

	state = talloc(ctdb, struct takeover_callback_state);
	CTDB_NO_MEMORY(ctdb, state);

	state->c = talloc_steal(state, c);
	state->sin = talloc(state, struct sockaddr_in);       
	CTDB_NO_MEMORY(ctdb, state->sin);
	*state->sin = pip->sin;

	ctdb_stop_monitoring(ctdb);

	ret = ctdb_event_script_callback(ctdb, 
					 timeval_current_ofs(ctdb->tunable.script_timeout, 0),
					 state, release_ip_callback, state,
					 "releaseip %s %s %u",
					 ctdb->takeover.interface, 
					 ip,
					 ctdb->nodes[ctdb->vnn]->public_netmask_bits);
	if (ret != 0) {
		DEBUG(0,(__location__ " Failed to release IP %s on interface %s\n",
			 ip, ctdb->takeover.interface));
		talloc_free(state);
		return -1;
	}

	/* tell the control that we will be reply asynchronously */
	*async_reply = true;

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
  try to find an available node to take a given nodes IP that meets the
  criterion given by the flags
 */
static void ctdb_takeover_find_node(struct ctdb_context *ctdb, struct ctdb_node_map *nodemap,
				    int start_node, uint32_t mask_flags)
{
	int j;
	for (j=(start_node+1)%nodemap->num;
	     j != start_node;
	     j=(j+1)%nodemap->num) {
		if (!(nodemap->nodes[j].flags & mask_flags) &&
		    ctdb_same_subnet(ctdb->nodes[j]->public_address, 
				     ctdb->nodes[start_node]->public_address, 
				     ctdb->nodes[j]->public_netmask_bits)) {
			ctdb->nodes[start_node]->takeover_vnn = nodemap->nodes[j].vnn;
			break;
		}
	}
}


/*
  make any IP alias changes for public addresses that are necessary 
 */
int ctdb_takeover_run(struct ctdb_context *ctdb, struct ctdb_node_map *nodemap)
{
	int i, j;
	int ret;
	struct ctdb_public_ip ip;

	ZERO_STRUCT(ip);

	/* Work out which node will look after each public IP.
	 * takeover_node cycles over the nodes and is incremented each time a 
	 * node has been assigned to take over for another node.
	 * This spreads the failed nodes out across the remaining
	 * nodes more evenly
	 */
	for (i=0;i<nodemap->num;i++) {
		if (!(nodemap->nodes[i].flags & (NODE_FLAGS_INACTIVE|NODE_FLAGS_DISABLED))) {
			ctdb->nodes[i]->takeover_vnn = nodemap->nodes[i].vnn;
		} else {
			ctdb->nodes[i]->takeover_vnn = (uint32_t)-1;	

			ctdb_takeover_find_node(ctdb, nodemap, i, NODE_FLAGS_INACTIVE|NODE_FLAGS_DISABLED);
			
			/* if no enabled node can take it, then we
			   might as well use any active node. It
			   probably means that some subsystem (such as
			   NFS) is sick on all nodes. Best we can do
			   is to keep the other services up. */
			if (ctdb->nodes[i]->takeover_vnn == (uint32_t)-1) {
				ctdb_takeover_find_node(ctdb, nodemap, i, NODE_FLAGS_INACTIVE);
			}

			if (ctdb->nodes[i]->takeover_vnn == (uint32_t)-1) {
				DEBUG(0,(__location__ " No node available on same network to take %s\n",
					 ctdb->nodes[i]->public_address));
			}
		}
	}	

	/* at this point ctdb->nodes[i]->takeover_vnn is the vnn which will own each IP */

	/* now tell all nodes to delete any alias that they should not
	   have.  This will be a NOOP on nodes that don't currently
	   hold the given alias */
	for (i=0;i<nodemap->num;i++) {
		/* don't talk to unconnected nodes, but do talk to banned nodes */
		if (nodemap->nodes[i].flags & NODE_FLAGS_DISCONNECTED) {
			continue;
		}

		/* tell this node to delete all of the aliases that it should not have */
		for (j=0;j<nodemap->num;j++) {
			if (ctdb->nodes[j]->takeover_vnn != nodemap->nodes[i].vnn) {
				ip.vnn = j;
				ip.takeover_vnn = ctdb->nodes[j]->takeover_vnn;
				ip.sin.sin_family = AF_INET;
				inet_aton(ctdb->nodes[j]->public_address, &ip.sin.sin_addr);

				ret = ctdb_ctrl_release_ip(ctdb, TAKEOVER_TIMEOUT(),
							   nodemap->nodes[i].vnn, 
							   &ip);
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
		if (ctdb->nodes[i]->takeover_vnn == -1) {
			/* this IP won't be taken over */
			continue;
		}
		ip.vnn = i;
		ip.takeover_vnn = ctdb->nodes[i]->takeover_vnn;
		ip.sin.sin_family = AF_INET;
		inet_aton(ctdb->nodes[i]->public_address, &ip.sin.sin_addr);

		ret = ctdb_ctrl_takeover_ip(ctdb, TAKEOVER_TIMEOUT(), 
					    ctdb->nodes[i]->takeover_vnn, 
					    &ip);
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
  destroy a ctdb_client_ip structure
 */
static int ctdb_client_ip_destructor(struct ctdb_client_ip *ip)
{
	DLIST_REMOVE(ip->ctdb->client_ip_list, ip);
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
	struct ctdb_client_ip *ip;

	ip = talloc(client, struct ctdb_client_ip);
	CTDB_NO_MEMORY(ctdb, ip);

	ip->ctdb = ctdb;
	ip->ip = p->dest;
	ip->client_id = client_id;
	talloc_set_destructor(ip, ctdb_client_ip_destructor);
	DLIST_ADD(ctdb->client_ip_list, ip);

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
	ret = ctdb_daemon_send_control(ctdb, CTDB_BROADCAST_CONNECTED, 0, 
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
		ctdb_daemon_send_control(client->ctdb, CTDB_BROADCAST_CONNECTED, 0, 
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
			struct in_addr in;
			ctdb_event_script(ctdb, "releaseip %s %s %u",
					  ctdb->takeover.interface, 
					  node->public_address,
					  node->public_netmask_bits);
			if (inet_aton(node->public_address, &in) != 0) {
				release_kill_clients(ctdb, in);
			}
		}
	}
}


/*
  get list of public IPs
 */
int32_t ctdb_control_get_public_ips(struct ctdb_context *ctdb, struct ctdb_req_control *c, TDB_DATA *outdata)
{
	int i, len;
	struct ctdb_all_public_ips *ips;

	len = offsetof(struct ctdb_all_public_ips, ips) + ctdb->num_nodes*sizeof(struct ctdb_public_ip);

	ips = talloc_zero_size(outdata, len);
	CTDB_NO_MEMORY(ctdb, ips);

	outdata->dsize = len;
	outdata->dptr  = (uint8_t *)ips;

	ips->num = ctdb->num_nodes;
	for(i=0;i<ctdb->num_nodes;i++){
		ips->ips[i].vnn = i;
		ips->ips[i].takeover_vnn = ctdb->nodes[i]->takeover_vnn;
		ips->ips[i].sin.sin_family = AF_INET;
		if (ctdb->nodes[i]->public_address) {
			inet_aton(ctdb->nodes[i]->public_address, &ips->ips[i].sin.sin_addr);
		}
	}

	return 0;
}
