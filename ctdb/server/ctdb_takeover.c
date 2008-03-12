/* 
   ctdb ip takeover code

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
#include "../common/rb_tree.h"


#define TAKEOVER_TIMEOUT() timeval_current_ofs(ctdb->tunable.takeover_timeout,0)

#define CTDB_ARP_INTERVAL 1
#define CTDB_ARP_REPEAT   3

struct ctdb_takeover_arp {
	struct ctdb_context *ctdb;
	uint32_t count;
	struct sockaddr_in sin;
	struct ctdb_tcp_array *tcparray;
	struct ctdb_vnn *vnn;
};


/*
  lists of tcp endpoints
 */
struct ctdb_tcp_list {
	struct ctdb_tcp_list *prev, *next;
	struct ctdb_tcp_connection connection;
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
	int i, s, ret;
	struct ctdb_tcp_array *tcparray;


	ret = ctdb_sys_send_arp(&arp->sin, arp->vnn->iface);
	if (ret != 0) {
		DEBUG(DEBUG_CRIT,(__location__ " sending of arp failed (%s)\n", strerror(errno)));
	}

	s = ctdb_sys_open_sending_socket();
	if (s == -1) {
		DEBUG(DEBUG_CRIT,(__location__ " failed to open raw socket for sending tickles\n"));
		return;
	}

	tcparray = arp->tcparray;
	if (tcparray) {
		for (i=0;i<tcparray->num;i++) {
			DEBUG(DEBUG_INFO,("sending tcp tickle ack for %u->%s:%u\n",
				 (unsigned)ntohs(tcparray->connections[i].daddr.sin_port), 
				 inet_ntoa(tcparray->connections[i].saddr.sin_addr),
				 (unsigned)ntohs(tcparray->connections[i].saddr.sin_port)));
			ret = ctdb_sys_send_tcp(s, &tcparray->connections[i].saddr, 
						&tcparray->connections[i].daddr, 0, 0, 0);
			if (ret != 0) {
				DEBUG(DEBUG_CRIT,(__location__ " Failed to send tcp tickle ack for %s\n",
					 inet_ntoa(tcparray->connections[i].saddr.sin_addr)));
			}
		}
	}

	close(s);
	arp->count++;

	if (arp->count == CTDB_ARP_REPEAT) {
		talloc_free(arp);
		return;
	}

	event_add_timed(arp->ctdb->ev, arp->vnn->takeover_ctx, 
			timeval_current_ofs(CTDB_ARP_INTERVAL, 0), 
			ctdb_control_send_arp, arp);
}

struct takeover_callback_state {
	struct ctdb_req_control *c;
	struct sockaddr_in *sin;
	struct ctdb_vnn *vnn;
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
	struct ctdb_tcp_array *tcparray;

	ctdb_enable_monitoring(ctdb);

	if (status != 0) {
		DEBUG(DEBUG_ERR,(__location__ " Failed to takeover IP %s on interface %s\n",
			 ip, state->vnn->iface));
		ctdb_request_control_reply(ctdb, state->c, NULL, status, NULL);
		talloc_free(state);
		return;
	}

	if (!state->vnn->takeover_ctx) {
		state->vnn->takeover_ctx = talloc_new(ctdb);
		if (!state->vnn->takeover_ctx) {
			goto failed;
		}
	}

	arp = talloc_zero(state->vnn->takeover_ctx, struct ctdb_takeover_arp);
	if (!arp) goto failed;
	
	arp->ctdb = ctdb;
	arp->sin = *state->sin;
	arp->vnn = state->vnn;

	tcparray = state->vnn->tcp_array;
	if (tcparray) {
		/* add all of the known tcp connections for this IP to the
		   list of tcp connections to send tickle acks for */
		arp->tcparray = talloc_steal(arp, tcparray);

		state->vnn->tcp_array = NULL;
		state->vnn->tcp_update_needed = true;
	}

	event_add_timed(arp->ctdb->ev, state->vnn->takeover_ctx, 
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
  Find the vnn of the node that has a public ip address
  returns -1 if the address is not known as a public address
 */
static struct ctdb_vnn *find_public_ip_vnn(struct ctdb_context *ctdb, struct sockaddr_in ip)
{
	struct ctdb_vnn *vnn;

	for (vnn=ctdb->vnn;vnn;vnn=vnn->next) {
		if (ctdb_same_ip(&vnn->public_address, &ip)) {
			return vnn;
		}
	}

	return NULL;
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
	struct ctdb_vnn *vnn;

	/* update out vnn list */
	vnn = find_public_ip_vnn(ctdb, pip->sin);
	if (vnn == NULL) {
		DEBUG(DEBUG_ERR,("takeoverip called for an ip '%s' that is not a public address\n", 
			 inet_ntoa(pip->sin.sin_addr)));
		return 0;
	}
	vnn->pnn = pip->pnn;

	/* if our kernel already has this IP, do nothing */
	if (ctdb_sys_have_ip(pip->sin)) {
		return 0;
	}

	state = talloc(ctdb, struct takeover_callback_state);
	CTDB_NO_MEMORY(ctdb, state);

	state->c = talloc_steal(ctdb, c);
	state->sin = talloc(ctdb, struct sockaddr_in);       
	CTDB_NO_MEMORY(ctdb, state->sin);
	*state->sin = pip->sin;

	state->vnn = vnn;

	DEBUG(DEBUG_NOTICE,("Takeover of IP %s/%u on interface %s\n", 
		 inet_ntoa(pip->sin.sin_addr), vnn->public_netmask_bits, 
		 vnn->iface));

	ctdb_disable_monitoring(ctdb);

	ret = ctdb_event_script_callback(ctdb, 
					 timeval_current_ofs(ctdb->tunable.script_timeout, 0),
					 state, takeover_ip_callback, state,
					 "takeip %s %s %u",
					 vnn->iface, 
					 inet_ntoa(pip->sin.sin_addr),
					 vnn->public_netmask_bits);

	if (ret != 0) {
		ctdb_enable_monitoring(ctdb);
		DEBUG(DEBUG_ERR,(__location__ " Failed to takeover IP %s on interface %s\n",
			 inet_ntoa(pip->sin.sin_addr), vnn->iface));
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
static void release_kill_clients(struct ctdb_context *ctdb, struct sockaddr_in in)
{
	struct ctdb_client_ip *ip;

	DEBUG(DEBUG_INFO,("release_kill_clients for ip %s\n", inet_ntoa(in.sin_addr)));

	for (ip=ctdb->client_ip_list; ip; ip=ip->next) {
		DEBUG(DEBUG_INFO,("checking for client %u with IP %s\n", 
			 ip->client_id, inet_ntoa(ip->ip.sin_addr)));
		if (ctdb_same_ip(&ip->ip, &in)) {
			struct ctdb_client *client = ctdb_reqid_find(ctdb, 
								     ip->client_id, 
								     struct ctdb_client);
			DEBUG(DEBUG_INFO,("matched client %u with IP %s and pid %u\n", 
				 ip->client_id, inet_ntoa(ip->ip.sin_addr), client->pid));
			if (client->pid != 0) {
				DEBUG(DEBUG_INFO,(__location__ " Killing client pid %u for IP %s on client_id %u\n",
					 (unsigned)client->pid, inet_ntoa(in.sin_addr),
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

	ctdb_enable_monitoring(ctdb);

	/* send a message to all clients of this node telling them
	   that the cluster has been reconfigured and they should
	   release any sockets on this IP */
	data.dptr = (uint8_t *)ip;
	data.dsize = strlen(ip)+1;

	ctdb_daemon_send_message(ctdb, ctdb->pnn, CTDB_SRVID_RELEASE_IP, data);

	/* kill clients that have registered with this IP */
	release_kill_clients(ctdb, *state->sin);
	
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
	struct ctdb_vnn *vnn;

	/* update our vnn list */
	vnn = find_public_ip_vnn(ctdb, pip->sin);
	if (vnn == NULL) {
		DEBUG(DEBUG_ERR,("releaseip called for an ip '%s' that is not a public address\n", 
			 inet_ntoa(pip->sin.sin_addr)));
		return 0;
	}
	vnn->pnn = pip->pnn;

	/* stop any previous arps */
	talloc_free(vnn->takeover_ctx);
	vnn->takeover_ctx = NULL;

	if (!ctdb_sys_have_ip(pip->sin)) {
		DEBUG(DEBUG_INFO,("Redundant release of IP %s/%u on interface %s (ip not held)\n", 
			 inet_ntoa(pip->sin.sin_addr), vnn->public_netmask_bits, 
			 vnn->iface));
		return 0;
	}

	DEBUG(DEBUG_NOTICE,("Release of IP %s/%u on interface %s\n", 
		 inet_ntoa(pip->sin.sin_addr), vnn->public_netmask_bits, 
		 vnn->iface));

	state = talloc(ctdb, struct takeover_callback_state);
	CTDB_NO_MEMORY(ctdb, state);

	state->c = talloc_steal(state, c);
	state->sin = talloc(state, struct sockaddr_in);       
	CTDB_NO_MEMORY(ctdb, state->sin);
	*state->sin = pip->sin;

	state->vnn = vnn;

	ctdb_disable_monitoring(ctdb);

	ret = ctdb_event_script_callback(ctdb, 
					 timeval_current_ofs(ctdb->tunable.script_timeout, 0),
					 state, release_ip_callback, state,
					 "releaseip %s %s %u",
					 vnn->iface, 
					 inet_ntoa(pip->sin.sin_addr),
					 vnn->public_netmask_bits);
	if (ret != 0) {
		ctdb_enable_monitoring(ctdb);

		DEBUG(DEBUG_ERR,(__location__ " Failed to release IP %s on interface %s\n",
			 inet_ntoa(pip->sin.sin_addr), vnn->iface));
		talloc_free(state);
		return -1;
	}

	/* tell the control that we will be reply asynchronously */
	*async_reply = true;
	return 0;
}



static int add_public_address(struct ctdb_context *ctdb, struct sockaddr_in addr, unsigned mask, const char *iface)
{
	struct ctdb_vnn      *vnn;

	/* Verify that we dont have an entry for this ip yet */
	for (vnn=ctdb->vnn;vnn;vnn=vnn->next) {
		if (ctdb_same_sockaddr(&addr, &vnn->public_address)) {
			DEBUG(DEBUG_CRIT,("Same ip '%s' specified multiple times in the public address list \n", 
				 inet_ntoa(addr.sin_addr)));
			exit(1);
		}		
	}

	/* create a new vnn structure for this ip address */
	vnn = talloc_zero(ctdb, struct ctdb_vnn);
	CTDB_NO_MEMORY_FATAL(ctdb, vnn);
	vnn->iface = talloc_strdup(vnn, iface);
	vnn->public_address      = addr;
	vnn->public_netmask_bits = mask;
	vnn->pnn                 = -1;
	
	DLIST_ADD(ctdb->vnn, vnn);

	return 0;
}


/*
  setup the event script directory
*/
int ctdb_set_event_script_dir(struct ctdb_context *ctdb, const char *script_dir)
{
	ctdb->event_script_dir = talloc_strdup(ctdb, script_dir);
	CTDB_NO_MEMORY(ctdb, ctdb->event_script_dir);
	return 0;
}

/*
  setup the public address lists from a file
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

	for (i=0;i<nlines;i++) {
		unsigned mask;
		struct sockaddr_in addr;
		const char *iface;
		char *tok;

		tok = strtok(lines[i], " \t");
		if (!tok || !parse_ip_mask(tok, &addr, &mask)) {
			DEBUG(DEBUG_CRIT,("Badly formed line %u in public address list\n", i+1));
			talloc_free(lines);
			return -1;
		}
		tok = strtok(NULL, " \t");
		if (tok == NULL) {
			if (NULL == ctdb->default_public_interface) {
				DEBUG(DEBUG_CRIT,("No default public interface and no interface specified at line %u of public address list\n",
					 i+1));
				talloc_free(lines);
				return -1;
			}
			iface = ctdb->default_public_interface;
		} else {
			iface = tok;
		}

		if (add_public_address(ctdb, addr, mask, iface)) {
			DEBUG(DEBUG_CRIT,("Failed to add line %u to the public address list\n", i+1));
			talloc_free(lines);
			return -1;
		}
	}

	talloc_free(lines);
	return 0;
}




struct ctdb_public_ip_list {
	struct ctdb_public_ip_list *next;
	uint32_t pnn;
	struct sockaddr_in sin;
};


/* Given a physical node, return the number of
   public addresses that is currently assigned to this node.
*/
static int node_ip_coverage(struct ctdb_context *ctdb, 
	int32_t pnn,
	struct ctdb_public_ip_list *ips)
{
	int num=0;

	for (;ips;ips=ips->next) {
		if (ips->pnn == pnn) {
			num++;
		}
	}
	return num;
}


/* Check if this is a public ip known to the node, i.e. can that
   node takeover this ip ?
*/
static int can_node_serve_ip(struct ctdb_context *ctdb, int32_t pnn, 
		struct ctdb_public_ip_list *ip)
{
	struct ctdb_all_public_ips *public_ips;
	int i;

	public_ips = ctdb->nodes[pnn]->public_ips;

	if (public_ips == NULL) {
		return -1;
	}

	for (i=0;i<public_ips->num;i++) {
		if (ip->sin.sin_addr.s_addr == public_ips->ips[i].sin.sin_addr.s_addr) {
			/* yes, this node can serve this public ip */
			return 0;
		}
	}

	return -1;
}


/* search the node lists list for a node to takeover this ip.
   pick the node that currently are serving the least number of ips
   so that the ips get spread out evenly.
*/
static int find_takeover_node(struct ctdb_context *ctdb, 
		struct ctdb_node_map *nodemap, uint32_t mask, 
		struct ctdb_public_ip_list *ip,
		struct ctdb_public_ip_list *all_ips)
{
	int pnn, min=0, num;
	int i;

	pnn    = -1;
	for (i=0;i<nodemap->num;i++) {
		if (nodemap->nodes[i].flags & mask) {
			/* This node is not healty and can not be used to serve
			   a public address 
			*/
			continue;
		}

		/* verify that this node can serve this ip */
		if (can_node_serve_ip(ctdb, i, ip)) {
			/* no it couldnt   so skip to the next node */
			continue;
		}

		num = node_ip_coverage(ctdb, i, all_ips);
		/* was this the first node we checked ? */
		if (pnn == -1) {
			pnn = i;
			min  = num;
		} else {
			if (num < min) {
				pnn = i;
				min  = num;
			}
		}
	}	
	if (pnn == -1) {
		DEBUG(DEBUG_WARNING,(__location__ " Could not find node to take over public address '%s'\n", inet_ntoa(ip->sin.sin_addr)));
		return -1;
	}

	ip->pnn = pnn;
	return 0;
}

struct ctdb_public_ip_list *
add_ip_to_merged_list(struct ctdb_context *ctdb,
			TALLOC_CTX *tmp_ctx, 
			struct ctdb_public_ip_list *ip_list, 
			struct ctdb_public_ip *ip)
{
	struct ctdb_public_ip_list *tmp_ip; 

	/* do we already have this ip in our merged list ?*/
	for (tmp_ip=ip_list;tmp_ip;tmp_ip=tmp_ip->next) {

		/* we already  have this public ip in the list */
		if (tmp_ip->sin.sin_addr.s_addr == ip->sin.sin_addr.s_addr) {
			return ip_list;
		}
	}

	/* this is a new public ip, we must add it to the list */
	tmp_ip = talloc_zero(tmp_ctx, struct ctdb_public_ip_list);
	CTDB_NO_MEMORY_NULL(ctdb, tmp_ip);
	tmp_ip->pnn  = ip->pnn;
	tmp_ip->sin  = ip->sin;
	tmp_ip->next = ip_list;

	return tmp_ip;
}

struct ctdb_public_ip_list *
create_merged_ip_list(struct ctdb_context *ctdb, TALLOC_CTX *tmp_ctx)
{
	int i, j;
	struct ctdb_public_ip_list *ip_list = NULL;
	struct ctdb_all_public_ips *public_ips;

	for (i=0;i<ctdb->num_nodes;i++) {
		public_ips = ctdb->nodes[i]->public_ips;

		/* there were no public ips for this node */
		if (public_ips == NULL) {
			continue;
		}		

		for (j=0;j<public_ips->num;j++) {
			ip_list = add_ip_to_merged_list(ctdb, tmp_ctx,
					ip_list, &public_ips->ips[j]);
		}
	}

	return ip_list;
}

/*
  make any IP alias changes for public addresses that are necessary 
 */
int ctdb_takeover_run(struct ctdb_context *ctdb, struct ctdb_node_map *nodemap)
{
	int i, num_healthy, retries;
	struct ctdb_public_ip ip;
	uint32_t mask;
	struct ctdb_public_ip_list *all_ips, *tmp_ip;
	int maxnode, maxnum=0, minnode, minnum=0, num;
	TDB_DATA data;
	struct timeval timeout;
	struct client_async_data *async_data;
	struct ctdb_client_control_state *state;
	TALLOC_CTX *tmp_ctx = talloc_new(ctdb);


	ZERO_STRUCT(ip);

	/* Count how many completely healthy nodes we have */
	num_healthy = 0;
	for (i=0;i<nodemap->num;i++) {
		if (!(nodemap->nodes[i].flags & (NODE_FLAGS_INACTIVE|NODE_FLAGS_DISABLED))) {
			num_healthy++;
		}
	}

	if (num_healthy > 0) {
		/* We have healthy nodes, so only consider them for 
		   serving public addresses
		*/
		mask = NODE_FLAGS_INACTIVE|NODE_FLAGS_DISABLED;
	} else {
		/* We didnt have any completely healthy nodes so
		   use "disabled" nodes as a fallback
		*/
		mask = NODE_FLAGS_INACTIVE;
	}

	/* since nodes only know about those public addresses that
	   can be served by that particular node, no single node has
	   a full list of all public addresses that exist in the cluster.
	   Walk over all node structures and create a merged list of
	   all public addresses that exist in the cluster.
	*/
	all_ips = create_merged_ip_list(ctdb, tmp_ctx);

	/* If we want deterministic ip allocations, i.e. that the ip addresses
	   will always be allocated the same way for a specific set of
	   available/unavailable nodes.
	*/
	if (1 == ctdb->tunable.deterministic_public_ips) {		
		DEBUG(DEBUG_NOTICE,("Deterministic IPs enabled. Resetting all ip allocations\n"));
		for (i=0,tmp_ip=all_ips;tmp_ip;tmp_ip=tmp_ip->next,i++) {
			tmp_ip->pnn = i%nodemap->num;
		}
	}


	/* mark all public addresses with a masked node as being served by
	   node -1
	*/
	for (tmp_ip=all_ips;tmp_ip;tmp_ip=tmp_ip->next) {
		if (tmp_ip->pnn == -1) {
			continue;
		}
		if (nodemap->nodes[tmp_ip->pnn].flags & mask) {
			tmp_ip->pnn = -1;
		}
	}

	/* verify that the assigned nodes can serve that public ip
	   and set it to -1 if not
	*/
	for (tmp_ip=all_ips;tmp_ip;tmp_ip=tmp_ip->next) {
		if (tmp_ip->pnn == -1) {
			continue;
		}
		if (can_node_serve_ip(ctdb, tmp_ip->pnn, tmp_ip) != 0) {
			/* this node can not serve this ip. */
			tmp_ip->pnn = -1;
		}
	}


	/* now we must redistribute all public addresses with takeover node
	   -1 among the nodes available
	*/
	retries = 0;
try_again:
	/* loop over all ip's and find a physical node to cover for 
	   each unassigned ip.
	*/
	for (tmp_ip=all_ips;tmp_ip;tmp_ip=tmp_ip->next) {
		if (tmp_ip->pnn == -1) {
			if (find_takeover_node(ctdb, nodemap, mask, tmp_ip, all_ips)) {
				DEBUG(DEBUG_WARNING,("Failed to find node to cover ip %s\n", inet_ntoa(tmp_ip->sin.sin_addr)));
			}
		}
	}

	/* If we dont want ips to fail back after a node becomes healthy
	   again, we wont even try to reallocat the ip addresses so that
	   they are evenly spread out.
	   This can NOT be used at the same time as DeterministicIPs !
	*/
	if (1 == ctdb->tunable.no_ip_failback) {
		if (1 == ctdb->tunable.deterministic_public_ips) {
			DEBUG(DEBUG_ERR, ("ERROR: You can not use 'DeterministicIPs' and 'NoIPFailback' at the same time\n"));
		}
		goto finished;
	}


	/* now, try to make sure the ip adresses are evenly distributed
	   across the node.
	   for each ip address, loop over all nodes that can serve this
	   ip and make sure that the difference between the node
	   serving the most and the node serving the least ip's are not greater
	   than 1.
	*/
	for (tmp_ip=all_ips;tmp_ip;tmp_ip=tmp_ip->next) {
		if (tmp_ip->pnn == -1) {
			continue;
		}

		/* Get the highest and lowest number of ips's served by any 
		   valid node which can serve this ip.
		*/
		maxnode = -1;
		minnode = -1;
		for (i=0;i<nodemap->num;i++) {
			if (nodemap->nodes[i].flags & mask) {
				continue;
			}

			/* only check nodes that can actually serve this ip */
			if (can_node_serve_ip(ctdb, i, tmp_ip)) {
				/* no it couldnt   so skip to the next node */
				continue;
			}

			num = node_ip_coverage(ctdb, i, all_ips);
			if (maxnode == -1) {
				maxnode = i;
				maxnum  = num;
			} else {
				if (num > maxnum) {
					maxnode = i;
					maxnum  = num;
				}
			}
			if (minnode == -1) {
				minnode = i;
				minnum  = num;
			} else {
				if (num < minnum) {
					minnode = i;
					minnum  = num;
				}
			}
		}
		if (maxnode == -1) {
			DEBUG(DEBUG_WARNING,(__location__ " Could not find maxnode. May not be able to serve ip '%s'\n", inet_ntoa(tmp_ip->sin.sin_addr)));
			continue;
		}

		/* If we want deterministic IPs then dont try to reallocate 
		   them to spread out the load.
		*/
		if (1 == ctdb->tunable.deterministic_public_ips) {
			continue;
		}

		/* if the spread between the smallest and largest coverage by
		   a node is >=2 we steal one of the ips from the node with
		   most coverage to even things out a bit.
		   try to do this at most 5 times  since we dont want to spend
		   too much time balancing the ip coverage.
		*/
		if ( (maxnum > minnum+1)
		  && (retries < 5) ){
			struct ctdb_public_ip_list *tmp;

			/* mark one of maxnode's vnn's as unassigned and try
			   again
			*/
			for (tmp=all_ips;tmp;tmp=tmp->next) {
				if (tmp->pnn == maxnode) {
					tmp->pnn = -1;
					retries++;
					goto try_again;
				}
			}
		}
	}


	/* finished distributing the public addresses, now just send the 
	   info out to the nodes
	*/
finished:

	/* at this point ->pnn is the node which will own each IP
	   or -1 if there is no node that can cover this ip
	*/

	/* now tell all nodes to delete any alias that they should not
	   have.  This will be a NOOP on nodes that don't currently
	   hold the given alias */
	async_data = talloc_zero(tmp_ctx, struct client_async_data);
	CTDB_NO_MEMORY_FATAL(ctdb, async_data);

	for (i=0;i<nodemap->num;i++) {
		/* don't talk to unconnected nodes, but do talk to banned nodes */
		if (nodemap->nodes[i].flags & NODE_FLAGS_DISCONNECTED) {
			continue;
		}

		for (tmp_ip=all_ips;tmp_ip;tmp_ip=tmp_ip->next) {
			if (tmp_ip->pnn == nodemap->nodes[i].pnn) {
				/* This node should be serving this
				   vnn so dont tell it to release the ip
				*/
				continue;
			}
			ip.pnn = tmp_ip->pnn;
			ip.sin.sin_family = AF_INET;
			ip.sin.sin_addr   = tmp_ip->sin.sin_addr;

			timeout = TAKEOVER_TIMEOUT();
			data.dsize = sizeof(ip);
			data.dptr  = (uint8_t *)&ip;
			state = ctdb_control_send(ctdb, nodemap->nodes[i].pnn,
					0, CTDB_CONTROL_RELEASE_IP, 0,
					data, async_data,
					&timeout, NULL);
			if (state == NULL) {
				DEBUG(DEBUG_ERR,(__location__ " Failed to call async control CTDB_CONTROL_RELEASE_IP to node %u\n", nodemap->nodes[i].pnn));
				talloc_free(tmp_ctx);
				return -1;
			}
		
			ctdb_client_async_add(async_data, state);
		}
	}
	if (ctdb_client_async_wait(ctdb, async_data) != 0) {
		DEBUG(DEBUG_ERR,(__location__ " Async control CTDB_CONTROL_RELEASE_IP failed\n"));
		talloc_free(tmp_ctx);
		return -1;
	}
	talloc_free(async_data);


	/* tell all nodes to get their own IPs */
	async_data = talloc_zero(tmp_ctx, struct client_async_data);
	CTDB_NO_MEMORY_FATAL(ctdb, async_data);
	for (tmp_ip=all_ips;tmp_ip;tmp_ip=tmp_ip->next) {
		if (tmp_ip->pnn == -1) {
			/* this IP won't be taken over */
			continue;
		}
		ip.pnn = tmp_ip->pnn;
		ip.sin.sin_family = AF_INET;
		ip.sin.sin_addr = tmp_ip->sin.sin_addr;

		timeout = TAKEOVER_TIMEOUT();
		data.dsize = sizeof(ip);
		data.dptr  = (uint8_t *)&ip;
		state = ctdb_control_send(ctdb, tmp_ip->pnn,
				0, CTDB_CONTROL_TAKEOVER_IP, 0,
				data, async_data,
				&timeout, NULL);
		if (state == NULL) {
			DEBUG(DEBUG_ERR,(__location__ " Failed to call async control CTDB_CONTROL_TAKEOVER_IP to node %u\n", tmp_ip->pnn));
			talloc_free(tmp_ctx);
			return -1;
		}
		
		ctdb_client_async_add(async_data, state);
	}
	if (ctdb_client_async_wait(ctdb, async_data) != 0) {
		DEBUG(DEBUG_ERR,(__location__ " Async control CTDB_CONTROL_TAKEOVER_IP failed\n"));
		talloc_free(tmp_ctx);
		return -1;
	}

	talloc_free(tmp_ctx);
	return 0;
}


/*
  destroy a ctdb_client_ip structure
 */
static int ctdb_client_ip_destructor(struct ctdb_client_ip *ip)
{
	DEBUG(DEBUG_DEBUG,("destroying client tcp for %s:%u (client_id %u)\n",
		 inet_ntoa(ip->ip.sin_addr), ntohs(ip->ip.sin_port), ip->client_id));
	DLIST_REMOVE(ip->ctdb->client_ip_list, ip);
	return 0;
}

/*
  called by a client to inform us of a TCP connection that it is managing
  that should tickled with an ACK when IP takeover is done
 */
int32_t ctdb_control_tcp_client(struct ctdb_context *ctdb, uint32_t client_id,
				TDB_DATA indata)
{
	struct ctdb_client *client = ctdb_reqid_find(ctdb, client_id, struct ctdb_client);
	struct ctdb_control_tcp *p = (struct ctdb_control_tcp *)indata.dptr;
	struct ctdb_tcp_list *tcp;
	struct ctdb_control_tcp_vnn t;
	int ret;
	TDB_DATA data;
	struct ctdb_client_ip *ip;
	struct ctdb_vnn *vnn;

	vnn = find_public_ip_vnn(ctdb, p->dest);
	if (vnn == NULL) {
		if (ntohl(p->dest.sin_addr.s_addr) != INADDR_LOOPBACK) {
			DEBUG(DEBUG_INFO,("Could not add client IP %s. This is not a public address.\n", 
				 inet_ntoa(p->dest.sin_addr))); 
		}
		return 0;
	}

	if (vnn->pnn != ctdb->pnn) {
		DEBUG(DEBUG_ERR,("Attempt to register tcp client for IP %s we don't hold - failing (client_id %u pid %u)\n",
			 inet_ntoa(p->dest.sin_addr),
			 client_id, client->pid));
		/* failing this call will tell smbd to die */
		return -1;
	}

	ip = talloc(client, struct ctdb_client_ip);
	CTDB_NO_MEMORY(ctdb, ip);

	ip->ctdb = ctdb;
	ip->ip = p->dest;
	ip->client_id = client_id;
	talloc_set_destructor(ip, ctdb_client_ip_destructor);
	DLIST_ADD(ctdb->client_ip_list, ip);

	tcp = talloc(client, struct ctdb_tcp_list);
	CTDB_NO_MEMORY(ctdb, tcp);

	tcp->connection.saddr = p->src;
	tcp->connection.daddr = p->dest;

	DLIST_ADD(client->tcp_list, tcp);

	t.src  = p->src;
	t.dest = p->dest;

	data.dptr = (uint8_t *)&t;
	data.dsize = sizeof(t);

	DEBUG(DEBUG_INFO,("registered tcp client for %u->%s:%u (client_id %u pid %u)\n",
		 (unsigned)ntohs(p->dest.sin_port), 
		 inet_ntoa(p->src.sin_addr),
		 (unsigned)ntohs(p->src.sin_port), client_id, client->pid));

	/* tell all nodes about this tcp connection */
	ret = ctdb_daemon_send_control(ctdb, CTDB_BROADCAST_CONNECTED, 0, 
				       CTDB_CONTROL_TCP_ADD,
				       0, CTDB_CTRL_FLAG_NOREPLY, data, NULL, NULL);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,(__location__ " Failed to send CTDB_CONTROL_TCP_ADD\n"));
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
static struct ctdb_tcp_connection *ctdb_tcp_find(struct ctdb_tcp_array *array, 
					   struct ctdb_tcp_connection *tcp)
{
	int i;

	if (array == NULL) {
		return NULL;
	}

	for (i=0;i<array->num;i++) {
		if (same_sockaddr_in(&array->connections[i].saddr, &tcp->saddr) &&
		    same_sockaddr_in(&array->connections[i].daddr, &tcp->daddr)) {
			return &array->connections[i];
		}
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
	struct ctdb_tcp_array *tcparray;
	struct ctdb_tcp_connection tcp;
	struct ctdb_vnn *vnn;

	vnn = find_public_ip_vnn(ctdb, p->dest);
	if (vnn == NULL) {
		DEBUG(DEBUG_ERR,(__location__ " got TCP_ADD control for an address which is not a public address '%s'\n", 
			 inet_ntoa(p->dest.sin_addr)));
		return -1;
	}


	tcparray = vnn->tcp_array;

	/* If this is the first tickle */
	if (tcparray == NULL) {
		tcparray = talloc_size(ctdb->nodes, 
			offsetof(struct ctdb_tcp_array, connections) +
			sizeof(struct ctdb_tcp_connection) * 1);
		CTDB_NO_MEMORY(ctdb, tcparray);
		vnn->tcp_array = tcparray;

		tcparray->num = 0;
		tcparray->connections = talloc_size(tcparray, sizeof(struct ctdb_tcp_connection));
		CTDB_NO_MEMORY(ctdb, tcparray->connections);

		tcparray->connections[tcparray->num].saddr = p->src;
		tcparray->connections[tcparray->num].daddr = p->dest;
		tcparray->num++;
		return 0;
	}


	/* Do we already have this tickle ?*/
	tcp.saddr = p->src;
	tcp.daddr = p->dest;
	if (ctdb_tcp_find(vnn->tcp_array, &tcp) != NULL) {
		DEBUG(DEBUG_DEBUG,("Already had tickle info for %s:%u for vnn:%u\n",
			 inet_ntoa(tcp.daddr.sin_addr),
			 ntohs(tcp.daddr.sin_port),
			 vnn->pnn));
		return 0;
	}

	/* A new tickle, we must add it to the array */
	tcparray->connections = talloc_realloc(tcparray, tcparray->connections,
					struct ctdb_tcp_connection,
					tcparray->num+1);
	CTDB_NO_MEMORY(ctdb, tcparray->connections);

	vnn->tcp_array = tcparray;
	tcparray->connections[tcparray->num].saddr = p->src;
	tcparray->connections[tcparray->num].daddr = p->dest;
	tcparray->num++;
				
	DEBUG(DEBUG_INFO,("Added tickle info for %s:%u from vnn %u\n",
		 inet_ntoa(tcp.daddr.sin_addr),
		 ntohs(tcp.daddr.sin_port),
		 vnn->pnn));

	return 0;
}


/*
  called by a daemon to inform us of a TCP connection that one of its
  clients managing that should tickled with an ACK when IP takeover is
  done
 */
static void ctdb_remove_tcp_connection(struct ctdb_context *ctdb, struct ctdb_tcp_connection *conn)
{
	struct ctdb_tcp_connection *tcpp;
	struct ctdb_vnn *vnn = find_public_ip_vnn(ctdb, conn->daddr);

	if (vnn == NULL) {
		DEBUG(DEBUG_ERR,(__location__ " unable to find public address %s\n", inet_ntoa(conn->daddr.sin_addr)));
		return;
	}

	/* if the array is empty we cant remove it
	   and we dont need to do anything
	 */
	if (vnn->tcp_array == NULL) {
		DEBUG(DEBUG_INFO,("Trying to remove tickle that doesnt exist (array is empty) %s:%u\n",
			 inet_ntoa(conn->daddr.sin_addr),
			 ntohs(conn->daddr.sin_port)));
		return;
	}


	/* See if we know this connection
	   if we dont know this connection  then we dont need to do anything
	 */
	tcpp = ctdb_tcp_find(vnn->tcp_array, conn);
	if (tcpp == NULL) {
		DEBUG(DEBUG_INFO,("Trying to remove tickle that doesnt exist %s:%u\n",
			 inet_ntoa(conn->daddr.sin_addr),
			 ntohs(conn->daddr.sin_port)));
		return;
	}


	/* We need to remove this entry from the array.
           Instead of allocating a new array and copying data to it
	   we cheat and just copy the last entry in the existing array
	   to the entry that is to be removed and just shring the 
	   ->num field
	 */
	*tcpp = vnn->tcp_array->connections[vnn->tcp_array->num - 1];
	vnn->tcp_array->num--;

	/* If we deleted the last entry we also need to remove the entire array
	 */
	if (vnn->tcp_array->num == 0) {
		talloc_free(vnn->tcp_array);
		vnn->tcp_array = NULL;
	}		

	vnn->tcp_update_needed = true;

	DEBUG(DEBUG_INFO,("Removed tickle info for %s:%u\n",
		 inet_ntoa(conn->saddr.sin_addr),
		 ntohs(conn->saddr.sin_port)));
}


/*
  called when a daemon restarts - send all tickes for all public addresses
  we are serving immediately to the new node.
 */
int32_t ctdb_control_startup(struct ctdb_context *ctdb, uint32_t vnn)
{
/*XXX here we should send all tickes we are serving to the new node */
	return 0;
}


/*
  called when a client structure goes away - hook to remove
  elements from the tcp_list in all daemons
 */
void ctdb_takeover_client_destructor_hook(struct ctdb_client *client)
{
	while (client->tcp_list) {
		struct ctdb_tcp_list *tcp = client->tcp_list;
		DLIST_REMOVE(client->tcp_list, tcp);
		ctdb_remove_tcp_connection(client->ctdb, &tcp->connection);
	}
}


/*
  release all IPs on shutdown
 */
void ctdb_release_all_ips(struct ctdb_context *ctdb)
{
	struct ctdb_vnn *vnn;

	for (vnn=ctdb->vnn;vnn;vnn=vnn->next) {
		if (!ctdb_sys_have_ip(vnn->public_address)) {
			continue;
		}
		ctdb_event_script(ctdb, "releaseip %s %s %u",
				  vnn->iface, 
				  inet_ntoa(vnn->public_address.sin_addr),
				  vnn->public_netmask_bits);
		release_kill_clients(ctdb, vnn->public_address);
	}
}


/*
  get list of public IPs
 */
int32_t ctdb_control_get_public_ips(struct ctdb_context *ctdb, 
				    struct ctdb_req_control *c, TDB_DATA *outdata)
{
	int i, num, len;
	struct ctdb_all_public_ips *ips;
	struct ctdb_vnn *vnn;

	/* count how many public ip structures we have */
	num = 0;
	for (vnn=ctdb->vnn;vnn;vnn=vnn->next) {
		num++;
	}

	len = offsetof(struct ctdb_all_public_ips, ips) + 
		num*sizeof(struct ctdb_public_ip);
	ips = talloc_zero_size(outdata, len);
	CTDB_NO_MEMORY(ctdb, ips);

	outdata->dsize = len;
	outdata->dptr  = (uint8_t *)ips;

	ips->num = num;
	i = 0;
	for (vnn=ctdb->vnn;vnn;vnn=vnn->next) {
		ips->ips[i].pnn = vnn->pnn;
		ips->ips[i].sin = vnn->public_address;
		i++;
	}

	return 0;
}



/* 
   structure containing the listening socket and the list of tcp connections
   that the ctdb daemon is to kill
*/
struct ctdb_kill_tcp {
	struct ctdb_vnn *vnn;
	struct ctdb_context *ctdb;
	int capture_fd;
	int sending_fd;
	struct fd_event *fde;
	trbt_tree_t *connections;
	void *private_data;
};

/*
  a tcp connection that is to be killed
 */
struct ctdb_killtcp_con {
	struct sockaddr_in src;
	struct sockaddr_in dst;
	int count;
	struct ctdb_kill_tcp *killtcp;
};

/* this function is used to create a key to represent this socketpair
   in the killtcp tree.
   this key is used to insert and lookup matching socketpairs that are
   to be tickled and RST
*/
#define KILLTCP_KEYLEN	4
static uint32_t *killtcp_key(struct sockaddr_in *src, struct sockaddr_in *dst)
{
	static uint32_t key[KILLTCP_KEYLEN];

	key[0]	= dst->sin_addr.s_addr;
	key[1]	= src->sin_addr.s_addr;
	key[2]	= dst->sin_port;
	key[3]	= src->sin_port;

	return key;
}

/*
  called when we get a read event on the raw socket
 */
static void capture_tcp_handler(struct event_context *ev, struct fd_event *fde, 
				uint16_t flags, void *private_data)
{
	struct ctdb_kill_tcp *killtcp = talloc_get_type(private_data, struct ctdb_kill_tcp);
	struct ctdb_killtcp_con *con;
	struct sockaddr_in src, dst;
	uint32_t ack_seq, seq;

	if (!(flags & EVENT_FD_READ)) {
		return;
	}

	if (ctdb_sys_read_tcp_packet(killtcp->capture_fd,
				killtcp->private_data,
				&src, &dst,
				&ack_seq, &seq) != 0) {
		/* probably a non-tcp ACK packet */
		return;
	}

	/* check if we have this guy in our list of connections
	   to kill
	*/
	con = trbt_lookuparray32(killtcp->connections, 
			KILLTCP_KEYLEN, killtcp_key(&src, &dst));
	if (con == NULL) {
		/* no this was some other packet we can just ignore */
		return;
	}

	/* This one has been tickled !
	   now reset him and remove him from the list.
	 */
	DEBUG(DEBUG_INFO, ("sending a tcp reset to kill connection :%d -> %s:%d\n", ntohs(con->dst.sin_port), inet_ntoa(con->src.sin_addr), ntohs(con->src.sin_port)));

	ctdb_sys_send_tcp(killtcp->sending_fd, &con->dst, 
			  &con->src, ack_seq, seq, 1);
	talloc_free(con);
}


/* when traversing the list of all tcp connections to send tickle acks to
   (so that we can capture the ack coming back and kill the connection
    by a RST)
   this callback is called for each connection we are currently trying to kill
*/
static void tickle_connection_traverse(void *param, void *data)
{
	struct ctdb_killtcp_con *con = talloc_get_type(data, struct ctdb_killtcp_con);
	struct ctdb_kill_tcp *killtcp = talloc_get_type(param, struct ctdb_kill_tcp);

	/* have tried too many times, just give up */
	if (con->count >= 5) {
		talloc_free(con);
		return;
	}

	/* othervise, try tickling it again */
	con->count++;
	ctdb_sys_send_tcp(killtcp->sending_fd, &con->dst, &con->src, 0, 0, 0);
}


/* 
   called every second until all sentenced connections have been reset
 */
static void ctdb_tickle_sentenced_connections(struct event_context *ev, struct timed_event *te, 
					      struct timeval t, void *private_data)
{
	struct ctdb_kill_tcp *killtcp = talloc_get_type(private_data, struct ctdb_kill_tcp);


	/* loop over all connections sending tickle ACKs */
	trbt_traversearray32(killtcp->connections, KILLTCP_KEYLEN, tickle_connection_traverse, killtcp);


	/* If there are no more connections to kill we can remove the
	   entire killtcp structure
	 */
	if ( (killtcp->connections == NULL) || 
	     (killtcp->connections->root == NULL) ) {
		talloc_free(killtcp);
		return;
	}

	/* try tickling them again in a seconds time
	 */
	event_add_timed(killtcp->ctdb->ev, killtcp, timeval_current_ofs(1, 0), 
			ctdb_tickle_sentenced_connections, killtcp);
}

/*
  destroy the killtcp structure
 */
static int ctdb_killtcp_destructor(struct ctdb_kill_tcp *killtcp)
{
	if (killtcp->sending_fd != -1) {
		close(killtcp->sending_fd);
		killtcp->sending_fd = -1;
	}
	killtcp->vnn->killtcp = NULL;
	return 0;
}


/* nothing fancy here, just unconditionally replace any existing
   connection structure with the new one.

   dont even free the old one if it did exist, that one is talloc_stolen
   by the same node in the tree anyway and will be deleted when the new data 
   is deleted
*/
static void *add_killtcp_callback(void *parm, void *data)
{
	return parm;
}

/*
  add a tcp socket to the list of connections we want to RST
 */
static int ctdb_killtcp_add_connection(struct ctdb_context *ctdb, 
				       struct sockaddr_in *src, struct sockaddr_in *dst)
{
	struct ctdb_kill_tcp *killtcp;
	struct ctdb_killtcp_con *con;
	struct ctdb_vnn *vnn;

	vnn = find_public_ip_vnn(ctdb, *dst);
	if (vnn == NULL) {
		vnn = find_public_ip_vnn(ctdb, *src);
	}
	if (vnn == NULL) {
		/* if it is not a public ip   it could be our 'single ip' */
		if (ctdb->single_ip_vnn) {
			if (ctdb_same_ip(&ctdb->single_ip_vnn->public_address, dst)) {
				vnn = ctdb->single_ip_vnn;
			}
		}
	}
	if (vnn == NULL) {
		DEBUG(DEBUG_ERR,(__location__ " Could not killtcp, not a public address\n")); 
		return -1;
	}

	killtcp = vnn->killtcp;
	
	/* If this is the first connection to kill we must allocate
	   a new structure
	 */
	if (killtcp == NULL) {
		killtcp = talloc_zero(ctdb, struct ctdb_kill_tcp);
		CTDB_NO_MEMORY(ctdb, killtcp);

		killtcp->vnn         = vnn;
		killtcp->ctdb        = ctdb;
		killtcp->capture_fd  = -1;
		killtcp->sending_fd  = -1;
		killtcp->connections = trbt_create(killtcp, 0);

		vnn->killtcp         = killtcp;
		talloc_set_destructor(killtcp, ctdb_killtcp_destructor);
	}



	/* create a structure that describes this connection we want to
	   RST and store it in killtcp->connections
	*/
	con = talloc(killtcp, struct ctdb_killtcp_con);
	CTDB_NO_MEMORY(ctdb, con);
	con->src     = *src;
	con->dst     = *dst;
	con->count   = 0;
	con->killtcp = killtcp;


	trbt_insertarray32_callback(killtcp->connections,
			KILLTCP_KEYLEN, killtcp_key(&con->dst, &con->src),
			add_killtcp_callback, con);

	/* 
	   If we dont have a socket to send from yet we must create it
	 */
	if (killtcp->sending_fd == -1) {
		killtcp->sending_fd = ctdb_sys_open_sending_socket();
		if (killtcp->sending_fd == -1) {
			DEBUG(DEBUG_CRIT,(__location__ " Failed to open sending socket for killtcp\n"));
			goto failed;
		}
	}

	/* 
	   If we dont have a socket to listen on yet we must create it
	 */
	if (killtcp->capture_fd == -1) {
		killtcp->capture_fd = ctdb_sys_open_capture_socket(vnn->iface, &killtcp->private_data);
		if (killtcp->capture_fd == -1) {
			DEBUG(DEBUG_CRIT,(__location__ " Failed to open capturing socket for killtcp\n"));
			goto failed;
		}
	}


	if (killtcp->fde == NULL) {
		killtcp->fde = event_add_fd(ctdb->ev, killtcp, killtcp->capture_fd, 
					    EVENT_FD_READ | EVENT_FD_AUTOCLOSE, 
					    capture_tcp_handler, killtcp);

		/* We also need to set up some events to tickle all these connections
		   until they are all reset
		*/
		event_add_timed(ctdb->ev, killtcp, timeval_current_ofs(1, 0), 
				ctdb_tickle_sentenced_connections, killtcp);
	}

	/* tickle him once now */
	ctdb_sys_send_tcp(killtcp->sending_fd, &con->dst, &con->src, 0, 0, 0);

	return 0;

failed:
	talloc_free(vnn->killtcp);
	vnn->killtcp = NULL;
	return -1;
}

/*
  kill a TCP connection.
 */
int32_t ctdb_control_kill_tcp(struct ctdb_context *ctdb, TDB_DATA indata)
{
	struct ctdb_control_killtcp *killtcp = (struct ctdb_control_killtcp *)indata.dptr;

	return ctdb_killtcp_add_connection(ctdb, &killtcp->src, &killtcp->dst);
}

/*
  called by a daemon to inform us of the entire list of TCP tickles for
  a particular public address.
  this control should only be sent by the node that is currently serving
  that public address.
 */
int32_t ctdb_control_set_tcp_tickle_list(struct ctdb_context *ctdb, TDB_DATA indata)
{
	struct ctdb_control_tcp_tickle_list *list = (struct ctdb_control_tcp_tickle_list *)indata.dptr;
	struct ctdb_tcp_array *tcparray;
	struct ctdb_vnn *vnn;

	/* We must at least have tickles.num or else we cant verify the size
	   of the received data blob
	 */
	if (indata.dsize < offsetof(struct ctdb_control_tcp_tickle_list, 
					tickles.connections)) {
		DEBUG(DEBUG_ERR,("Bad indata in ctdb_control_set_tcp_tickle_list. Not enough data for the tickle.num field\n"));
		return -1;
	}

	/* verify that the size of data matches what we expect */
	if (indata.dsize < offsetof(struct ctdb_control_tcp_tickle_list, 
				tickles.connections)
			 + sizeof(struct ctdb_tcp_connection)
				 * list->tickles.num) {
		DEBUG(DEBUG_ERR,("Bad indata in ctdb_control_set_tcp_tickle_list\n"));
		return -1;
	}	

	vnn = find_public_ip_vnn(ctdb, list->ip);
	if (vnn == NULL) {
		DEBUG(DEBUG_ERR,(__location__ " Could not set tcp tickle list, '%s' is not a public address\n", 
			 inet_ntoa(list->ip.sin_addr))); 
		return 1;
	}

	/* remove any old ticklelist we might have */
	talloc_free(vnn->tcp_array);
	vnn->tcp_array = NULL;

	tcparray = talloc(ctdb->nodes, struct ctdb_tcp_array);
	CTDB_NO_MEMORY(ctdb, tcparray);

	tcparray->num = list->tickles.num;

	tcparray->connections = talloc_array(tcparray, struct ctdb_tcp_connection, tcparray->num);
	CTDB_NO_MEMORY(ctdb, tcparray->connections);

	memcpy(tcparray->connections, &list->tickles.connections[0], 
	       sizeof(struct ctdb_tcp_connection)*tcparray->num);

	/* We now have a new fresh tickle list array for this vnn */
	vnn->tcp_array = talloc_steal(vnn, tcparray);
	
	return 0;
}

/*
  called to return the full list of tickles for the puclic address associated 
  with the provided vnn
 */
int32_t ctdb_control_get_tcp_tickle_list(struct ctdb_context *ctdb, TDB_DATA indata, TDB_DATA *outdata)
{
	struct sockaddr_in *ip = (struct sockaddr_in *)indata.dptr;
	struct ctdb_control_tcp_tickle_list *list;
	struct ctdb_tcp_array *tcparray;
	int num;
	struct ctdb_vnn *vnn;

	vnn = find_public_ip_vnn(ctdb, *ip);
	if (vnn == NULL) {
		DEBUG(DEBUG_ERR,(__location__ " Could not get tcp tickle list, '%s' is not a public address\n", 
			 inet_ntoa(ip->sin_addr))); 
		return 1;
	}

	tcparray = vnn->tcp_array;
	if (tcparray) {
		num = tcparray->num;
	} else {
		num = 0;
	}

	outdata->dsize = offsetof(struct ctdb_control_tcp_tickle_list, 
				tickles.connections)
			+ sizeof(struct ctdb_tcp_connection) * num;

	outdata->dptr  = talloc_size(outdata, outdata->dsize);
	CTDB_NO_MEMORY(ctdb, outdata->dptr);
	list = (struct ctdb_control_tcp_tickle_list *)outdata->dptr;

	list->ip = *ip;
	list->tickles.num = num;
	if (num) {
		memcpy(&list->tickles.connections[0], tcparray->connections, 
			sizeof(struct ctdb_tcp_connection) * num);
	}

	return 0;
}


/*
  set the list of all tcp tickles for a public address
 */
static int ctdb_ctrl_set_tcp_tickles(struct ctdb_context *ctdb, 
			      struct timeval timeout, uint32_t destnode, 
			      struct sockaddr_in *ip,
			      struct ctdb_tcp_array *tcparray)
{
	int ret, num;
	TDB_DATA data;
	struct ctdb_control_tcp_tickle_list *list;

	if (tcparray) {
		num = tcparray->num;
	} else {
		num = 0;
	}

	data.dsize = offsetof(struct ctdb_control_tcp_tickle_list, 
				tickles.connections) +
			sizeof(struct ctdb_tcp_connection) * num;
	data.dptr = talloc_size(ctdb, data.dsize);
	CTDB_NO_MEMORY(ctdb, data.dptr);

	list = (struct ctdb_control_tcp_tickle_list *)data.dptr;
	list->ip = *ip;
	list->tickles.num = num;
	if (tcparray) {
		memcpy(&list->tickles.connections[0], tcparray->connections, sizeof(struct ctdb_tcp_connection) * num);
	}

	ret = ctdb_daemon_send_control(ctdb, CTDB_BROADCAST_CONNECTED, 0, 
				       CTDB_CONTROL_SET_TCP_TICKLE_LIST,
				       0, CTDB_CTRL_FLAG_NOREPLY, data, NULL, NULL);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,(__location__ " ctdb_control for set tcp tickles failed\n"));
		return -1;
	}

	talloc_free(data.dptr);

	return ret;
}


/*
  perform tickle updates if required
 */
static void ctdb_update_tcp_tickles(struct event_context *ev, 
				struct timed_event *te, 
				struct timeval t, void *private_data)
{
	struct ctdb_context *ctdb = talloc_get_type(private_data, struct ctdb_context);
	int ret;
	struct ctdb_vnn *vnn;

	for (vnn=ctdb->vnn;vnn;vnn=vnn->next) {
		/* we only send out updates for public addresses that 
		   we have taken over
		 */
		if (ctdb->pnn != vnn->pnn) {
			continue;
		}
		/* We only send out the updates if we need to */
		if (!vnn->tcp_update_needed) {
			continue;
		}
		ret = ctdb_ctrl_set_tcp_tickles(ctdb, 
				TAKEOVER_TIMEOUT(),
				CTDB_BROADCAST_CONNECTED,
				&vnn->public_address,
				vnn->tcp_array);
		if (ret != 0) {
			DEBUG(DEBUG_ERR,("Failed to send the tickle update for public address %s\n", 
				 inet_ntoa(vnn->public_address.sin_addr)));
		}
	}

	event_add_timed(ctdb->ev, ctdb->tickle_update_context,
			     timeval_current_ofs(ctdb->tunable.tickle_update_interval, 0), 
			     ctdb_update_tcp_tickles, ctdb);
}		
	

/*
  start periodic update of tcp tickles
 */
void ctdb_start_tcp_tickle_update(struct ctdb_context *ctdb)
{
	ctdb->tickle_update_context = talloc_new(ctdb);

	event_add_timed(ctdb->ev, ctdb->tickle_update_context,
			     timeval_current_ofs(ctdb->tunable.tickle_update_interval, 0), 
			     ctdb_update_tcp_tickles, ctdb);
}




struct control_gratious_arp {
	struct ctdb_context *ctdb;
	struct sockaddr_in sin;
	const char *iface;
	int count;
};

/*
  send a control_gratuitous arp
 */
static void send_gratious_arp(struct event_context *ev, struct timed_event *te, 
				  struct timeval t, void *private_data)
{
	int ret;
	struct control_gratious_arp *arp = talloc_get_type(private_data, 
							struct control_gratious_arp);

	ret = ctdb_sys_send_arp(&arp->sin, arp->iface);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,(__location__ " sending of gratious arp failed (%s)\n", strerror(errno)));
	}


	arp->count++;
	if (arp->count == CTDB_ARP_REPEAT) {
		talloc_free(arp);
		return;
	}

	event_add_timed(arp->ctdb->ev, arp, 
			timeval_current_ofs(CTDB_ARP_INTERVAL, 0), 
			send_gratious_arp, arp);
}


/*
  send a gratious arp 
 */
int32_t ctdb_control_send_gratious_arp(struct ctdb_context *ctdb, TDB_DATA indata)
{
	struct ctdb_control_gratious_arp *gratious_arp = (struct ctdb_control_gratious_arp *)indata.dptr;
	struct control_gratious_arp *arp;


	/* verify the size of indata */
	if (indata.dsize < offsetof(struct ctdb_control_gratious_arp, iface)) {
		DEBUG(DEBUG_ERR,(__location__ " Too small indata to hold a ctdb_control_gratious_arp structure\n"));
		return -1;
	}
	if (indata.dsize != 
		( offsetof(struct ctdb_control_gratious_arp, iface)
		+ gratious_arp->len ) ){

		DEBUG(DEBUG_ERR,(__location__ " Wrong size of indata. Was %u bytes "
			"but should be %u bytes\n", 
			 (unsigned)indata.dsize, 
			 (unsigned)(offsetof(struct ctdb_control_gratious_arp, iface)+gratious_arp->len)));
		return -1;
	}


	arp = talloc(ctdb, struct control_gratious_arp);
	CTDB_NO_MEMORY(ctdb, arp);

	arp->ctdb  = ctdb;
	arp->sin   = gratious_arp->sin;
	arp->iface = talloc_strdup(arp, gratious_arp->iface);
	CTDB_NO_MEMORY(ctdb, arp->iface);
	arp->count = 0;
	
	event_add_timed(arp->ctdb->ev, arp, 
			timeval_zero(), send_gratious_arp, arp);

	return 0;
}

