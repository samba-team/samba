/* 
   ctdb ip takeover code

   Copyright (C) Ronnie Sahlberg  2007
   Copyright (C) Andrew Tridgell  2007
   Copyright (C) Martin Schwenke  2011

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
#include "tdb.h"
#include "lib/util/dlinklist.h"
#include "system/network.h"
#include "system/filesys.h"
#include "system/wait.h"
#include "../include/ctdb_private.h"
#include "../common/rb_tree.h"


#define TAKEOVER_TIMEOUT() timeval_current_ofs(ctdb->tunable.takeover_timeout,0)

#define CTDB_ARP_INTERVAL 1
#define CTDB_ARP_REPEAT   3

/* Flags used in IP allocation algorithms. */
struct ctdb_ipflags {
	bool noiptakeover;
	bool noiphost;
};

struct ctdb_iface {
	struct ctdb_iface *prev, *next;
	const char *name;
	bool link_up;
	uint32_t references;
};

static const char *ctdb_vnn_iface_string(const struct ctdb_vnn *vnn)
{
	if (vnn->iface) {
		return vnn->iface->name;
	}

	return "__none__";
}

static int ctdb_add_local_iface(struct ctdb_context *ctdb, const char *iface)
{
	struct ctdb_iface *i;

	/* Verify that we dont have an entry for this ip yet */
	for (i=ctdb->ifaces;i;i=i->next) {
		if (strcmp(i->name, iface) == 0) {
			return 0;
		}
	}

	/* create a new structure for this interface */
	i = talloc_zero(ctdb, struct ctdb_iface);
	CTDB_NO_MEMORY_FATAL(ctdb, i);
	i->name = talloc_strdup(i, iface);
	CTDB_NO_MEMORY(ctdb, i->name);
	/*
	 * If link_up defaults to true then IPs can be allocated to a
	 * node during the first recovery.  However, then an interface
	 * could have its link marked down during the startup event,
	 * causing the IP to move almost immediately.  If link_up
	 * defaults to false then, during normal operation, IPs added
	 * to a new interface can't be assigned until a monitor cycle
	 * has occurred and marked the new interfaces up.  This makes
	 * IP allocation unpredictable.  The following is a neat
	 * compromise: early in startup link_up defaults to false, so
	 * IPs can't be assigned, and after startup IPs can be
	 * assigned immediately.
	 */
	i->link_up = (ctdb->runstate == CTDB_RUNSTATE_RUNNING);

	DLIST_ADD(ctdb->ifaces, i);

	return 0;
}

static bool vnn_has_interface_with_name(struct ctdb_vnn *vnn,
					const char *name)
{
	int n;

	for (n = 0; vnn->ifaces[n] != NULL; n++) {
		if (strcmp(name, vnn->ifaces[n]) == 0) {
			return true;
		}
	}

	return false;
}

/* If any interfaces now have no possible IPs then delete them.  This
 * implementation is naive (i.e. simple) rather than clever
 * (i.e. complex).  Given that this is run on delip and that operation
 * is rare, this doesn't need to be efficient - it needs to be
 * foolproof.  One alternative is reference counting, where the logic
 * is distributed and can, therefore, be broken in multiple places.
 * Another alternative is to build a red-black tree of interfaces that
 * can have addresses (by walking ctdb->vnn and ctdb->single_ip_vnn
 * once) and then walking ctdb->ifaces once and deleting those not in
 * the tree.  Let's go to one of those if the naive implementation
 * causes problems...  :-)
 */
static void ctdb_remove_orphaned_ifaces(struct ctdb_context *ctdb,
					struct ctdb_vnn *vnn)
{
	struct ctdb_iface *i, *next;

	/* For each interface, check if there's an IP using it. */
	for (i = ctdb->ifaces; i != NULL; i = next) {
		struct ctdb_vnn *tv;
		bool found;
		next = i->next;

		/* Only consider interfaces named in the given VNN. */
		if (!vnn_has_interface_with_name(vnn, i->name)) {
			continue;
		}

		/* Is the "single IP" on this interface? */
		if ((ctdb->single_ip_vnn != NULL) &&
		    (ctdb->single_ip_vnn->ifaces[0] != NULL) &&
		    (strcmp(i->name, ctdb->single_ip_vnn->ifaces[0]) == 0)) {
			/* Found, next interface please... */
			continue;
		}
		/* Search for a vnn with this interface. */
		found = false;
		for (tv=ctdb->vnn; tv; tv=tv->next) {
			if (vnn_has_interface_with_name(tv, i->name)) {
				found = true;
				break;
			}
		}

		if (!found) {
			/* None of the VNNs are using this interface. */
			DLIST_REMOVE(ctdb->ifaces, i);
			talloc_free(i);
		}
	}
}


static struct ctdb_iface *ctdb_find_iface(struct ctdb_context *ctdb,
					  const char *iface)
{
	struct ctdb_iface *i;

	for (i=ctdb->ifaces;i;i=i->next) {
		if (strcmp(i->name, iface) == 0) {
			return i;
		}
	}

	return NULL;
}

static struct ctdb_iface *ctdb_vnn_best_iface(struct ctdb_context *ctdb,
					      struct ctdb_vnn *vnn)
{
	int i;
	struct ctdb_iface *cur = NULL;
	struct ctdb_iface *best = NULL;

	for (i=0; vnn->ifaces[i]; i++) {

		cur = ctdb_find_iface(ctdb, vnn->ifaces[i]);
		if (cur == NULL) {
			continue;
		}

		if (!cur->link_up) {
			continue;
		}

		if (best == NULL) {
			best = cur;
			continue;
		}

		if (cur->references < best->references) {
			best = cur;
			continue;
		}
	}

	return best;
}

static int32_t ctdb_vnn_assign_iface(struct ctdb_context *ctdb,
				     struct ctdb_vnn *vnn)
{
	struct ctdb_iface *best = NULL;

	if (vnn->iface) {
		DEBUG(DEBUG_INFO, (__location__ " public address '%s' "
				   "still assigned to iface '%s'\n",
				   ctdb_addr_to_str(&vnn->public_address),
				   ctdb_vnn_iface_string(vnn)));
		return 0;
	}

	best = ctdb_vnn_best_iface(ctdb, vnn);
	if (best == NULL) {
		DEBUG(DEBUG_ERR, (__location__ " public address '%s' "
				  "cannot assign to iface any iface\n",
				  ctdb_addr_to_str(&vnn->public_address)));
		return -1;
	}

	vnn->iface = best;
	best->references++;
	vnn->pnn = ctdb->pnn;

	DEBUG(DEBUG_INFO, (__location__ " public address '%s' "
			   "now assigned to iface '%s' refs[%d]\n",
			   ctdb_addr_to_str(&vnn->public_address),
			   ctdb_vnn_iface_string(vnn),
			   best->references));
	return 0;
}

static void ctdb_vnn_unassign_iface(struct ctdb_context *ctdb,
				    struct ctdb_vnn *vnn)
{
	DEBUG(DEBUG_INFO, (__location__ " public address '%s' "
			   "now unassigned (old iface '%s' refs[%d])\n",
			   ctdb_addr_to_str(&vnn->public_address),
			   ctdb_vnn_iface_string(vnn),
			   vnn->iface?vnn->iface->references:0));
	if (vnn->iface) {
		vnn->iface->references--;
	}
	vnn->iface = NULL;
	if (vnn->pnn == ctdb->pnn) {
		vnn->pnn = -1;
	}
}

static bool ctdb_vnn_available(struct ctdb_context *ctdb,
			       struct ctdb_vnn *vnn)
{
	int i;

	if (vnn->delete_pending) {
		return false;
	}

	if (vnn->iface && vnn->iface->link_up) {
		return true;
	}

	for (i=0; vnn->ifaces[i]; i++) {
		struct ctdb_iface *cur;

		cur = ctdb_find_iface(ctdb, vnn->ifaces[i]);
		if (cur == NULL) {
			continue;
		}

		if (cur->link_up) {
			return true;
		}
	}

	return false;
}

struct ctdb_takeover_arp {
	struct ctdb_context *ctdb;
	uint32_t count;
	ctdb_sock_addr addr;
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
	ctdb_sock_addr addr;
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
	int i, ret;
	struct ctdb_tcp_array *tcparray;
	const char *iface = ctdb_vnn_iface_string(arp->vnn);

	ret = ctdb_sys_send_arp(&arp->addr, iface);
	if (ret != 0) {
		DEBUG(DEBUG_CRIT,(__location__ " sending of arp failed on iface '%s' (%s)\n",
				  iface, strerror(errno)));
	}

	tcparray = arp->tcparray;
	if (tcparray) {
		for (i=0;i<tcparray->num;i++) {
			struct ctdb_tcp_connection *tcon;

			tcon = &tcparray->connections[i];
			DEBUG(DEBUG_INFO,("sending tcp tickle ack for %u->%s:%u\n",
				(unsigned)ntohs(tcon->dst_addr.ip.sin_port), 
				ctdb_addr_to_str(&tcon->src_addr),
				(unsigned)ntohs(tcon->src_addr.ip.sin_port)));
			ret = ctdb_sys_send_tcp(
				&tcon->src_addr, 
				&tcon->dst_addr,
				0, 0, 0);
			if (ret != 0) {
				DEBUG(DEBUG_CRIT,(__location__ " Failed to send tcp tickle ack for %s\n",
					ctdb_addr_to_str(&tcon->src_addr)));
			}
		}
	}

	arp->count++;

	if (arp->count == CTDB_ARP_REPEAT) {
		talloc_free(arp);
		return;
	}

	event_add_timed(arp->ctdb->ev, arp->vnn->takeover_ctx, 
			timeval_current_ofs(CTDB_ARP_INTERVAL, 100000), 
			ctdb_control_send_arp, arp);
}

static int32_t ctdb_announce_vnn_iface(struct ctdb_context *ctdb,
				       struct ctdb_vnn *vnn)
{
	struct ctdb_takeover_arp *arp;
	struct ctdb_tcp_array *tcparray;

	if (!vnn->takeover_ctx) {
		vnn->takeover_ctx = talloc_new(vnn);
		if (!vnn->takeover_ctx) {
			return -1;
		}
	}

	arp = talloc_zero(vnn->takeover_ctx, struct ctdb_takeover_arp);
	if (!arp) {
		return -1;
	}

	arp->ctdb = ctdb;
	arp->addr = vnn->public_address;
	arp->vnn  = vnn;

	tcparray = vnn->tcp_array;
	if (tcparray) {
		/* add all of the known tcp connections for this IP to the
		   list of tcp connections to send tickle acks for */
		arp->tcparray = talloc_steal(arp, tcparray);

		vnn->tcp_array = NULL;
		vnn->tcp_update_needed = true;
	}

	event_add_timed(arp->ctdb->ev, vnn->takeover_ctx,
			timeval_zero(), ctdb_control_send_arp, arp);

	return 0;
}

struct takeover_callback_state {
	struct ctdb_req_control *c;
	ctdb_sock_addr *addr;
	struct ctdb_vnn *vnn;
};

struct ctdb_do_takeip_state {
	struct ctdb_req_control *c;
	struct ctdb_vnn *vnn;
};

/*
  called when takeip event finishes
 */
static void ctdb_do_takeip_callback(struct ctdb_context *ctdb, int status,
				    void *private_data)
{
	struct ctdb_do_takeip_state *state =
		talloc_get_type(private_data, struct ctdb_do_takeip_state);
	int32_t ret;
	TDB_DATA data;

	if (status != 0) {
		struct ctdb_node *node = ctdb->nodes[ctdb->pnn];
	
		if (status == -ETIME) {
			ctdb_ban_self(ctdb);
		}
		DEBUG(DEBUG_ERR,(__location__ " Failed to takeover IP %s on interface %s\n",
				 ctdb_addr_to_str(&state->vnn->public_address),
				 ctdb_vnn_iface_string(state->vnn)));
		ctdb_request_control_reply(ctdb, state->c, NULL, status, NULL);

		node->flags |= NODE_FLAGS_UNHEALTHY;
		talloc_free(state);
		return;
	}

	if (ctdb->do_checkpublicip) {

	ret = ctdb_announce_vnn_iface(ctdb, state->vnn);
	if (ret != 0) {
		ctdb_request_control_reply(ctdb, state->c, NULL, -1, NULL);
		talloc_free(state);
		return;
	}

	}

	data.dptr  = (uint8_t *)ctdb_addr_to_str(&state->vnn->public_address);
	data.dsize = strlen((char *)data.dptr) + 1;
	DEBUG(DEBUG_INFO,(__location__ " sending TAKE_IP for '%s'\n", data.dptr));

	ctdb_daemon_send_message(ctdb, ctdb->pnn, CTDB_SRVID_TAKE_IP, data);


	/* the control succeeded */
	ctdb_request_control_reply(ctdb, state->c, NULL, 0, NULL);
	talloc_free(state);
	return;
}

static int ctdb_takeip_destructor(struct ctdb_do_takeip_state *state)
{
	state->vnn->update_in_flight = false;
	return 0;
}

/*
  take over an ip address
 */
static int32_t ctdb_do_takeip(struct ctdb_context *ctdb,
			      struct ctdb_req_control *c,
			      struct ctdb_vnn *vnn)
{
	int ret;
	struct ctdb_do_takeip_state *state;

	if (vnn->update_in_flight) {
		DEBUG(DEBUG_NOTICE,("Takeover of IP %s/%u rejected "
				    "update for this IP already in flight\n",
				    ctdb_addr_to_str(&vnn->public_address),
				    vnn->public_netmask_bits));
		return -1;
	}

	ret = ctdb_vnn_assign_iface(ctdb, vnn);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,("Takeover of IP %s/%u failed to "
				 "assign a usable interface\n",
				 ctdb_addr_to_str(&vnn->public_address),
				 vnn->public_netmask_bits));
		return -1;
	}

	state = talloc(vnn, struct ctdb_do_takeip_state);
	CTDB_NO_MEMORY(ctdb, state);

	state->c = talloc_steal(ctdb, c);
	state->vnn   = vnn;

	vnn->update_in_flight = true;
	talloc_set_destructor(state, ctdb_takeip_destructor);

	DEBUG(DEBUG_NOTICE,("Takeover of IP %s/%u on interface %s\n",
			    ctdb_addr_to_str(&vnn->public_address),
			    vnn->public_netmask_bits,
			    ctdb_vnn_iface_string(vnn)));

	ret = ctdb_event_script_callback(ctdb,
					 state,
					 ctdb_do_takeip_callback,
					 state,
					 CTDB_EVENT_TAKE_IP,
					 "%s %s %u",
					 ctdb_vnn_iface_string(vnn),
					 ctdb_addr_to_str(&vnn->public_address),
					 vnn->public_netmask_bits);

	if (ret != 0) {
		DEBUG(DEBUG_ERR,(__location__ " Failed to takeover IP %s on interface %s\n",
			ctdb_addr_to_str(&vnn->public_address),
			ctdb_vnn_iface_string(vnn)));
		talloc_free(state);
		return -1;
	}

	return 0;
}

struct ctdb_do_updateip_state {
	struct ctdb_req_control *c;
	struct ctdb_iface *old;
	struct ctdb_vnn *vnn;
};

/*
  called when updateip event finishes
 */
static void ctdb_do_updateip_callback(struct ctdb_context *ctdb, int status,
				      void *private_data)
{
	struct ctdb_do_updateip_state *state =
		talloc_get_type(private_data, struct ctdb_do_updateip_state);
	int32_t ret;

	if (status != 0) {
		if (status == -ETIME) {
			ctdb_ban_self(ctdb);
		}
		DEBUG(DEBUG_ERR,(__location__ " Failed to move IP %s from interface %s to %s\n",
			ctdb_addr_to_str(&state->vnn->public_address),
			state->old->name,
			ctdb_vnn_iface_string(state->vnn)));

		/*
		 * All we can do is reset the old interface
		 * and let the next run fix it
		 */
		ctdb_vnn_unassign_iface(ctdb, state->vnn);
		state->vnn->iface = state->old;
		state->vnn->iface->references++;

		ctdb_request_control_reply(ctdb, state->c, NULL, status, NULL);
		talloc_free(state);
		return;
	}

	if (ctdb->do_checkpublicip) {

	ret = ctdb_announce_vnn_iface(ctdb, state->vnn);
	if (ret != 0) {
		ctdb_request_control_reply(ctdb, state->c, NULL, -1, NULL);
		talloc_free(state);
		return;
	}

	}

	/* the control succeeded */
	ctdb_request_control_reply(ctdb, state->c, NULL, 0, NULL);
	talloc_free(state);
	return;
}

static int ctdb_updateip_destructor(struct ctdb_do_updateip_state *state)
{
	state->vnn->update_in_flight = false;
	return 0;
}

/*
  update (move) an ip address
 */
static int32_t ctdb_do_updateip(struct ctdb_context *ctdb,
				struct ctdb_req_control *c,
				struct ctdb_vnn *vnn)
{
	int ret;
	struct ctdb_do_updateip_state *state;
	struct ctdb_iface *old = vnn->iface;
	const char *new_name;

	if (vnn->update_in_flight) {
		DEBUG(DEBUG_NOTICE,("Update of IP %s/%u rejected "
				    "update for this IP already in flight\n",
				    ctdb_addr_to_str(&vnn->public_address),
				    vnn->public_netmask_bits));
		return -1;
	}

	ctdb_vnn_unassign_iface(ctdb, vnn);
	ret = ctdb_vnn_assign_iface(ctdb, vnn);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,("update of IP %s/%u failed to "
				 "assin a usable interface (old iface '%s')\n",
				 ctdb_addr_to_str(&vnn->public_address),
				 vnn->public_netmask_bits,
				 old->name));
		return -1;
	}

	new_name = ctdb_vnn_iface_string(vnn);
	if (old->name != NULL && new_name != NULL && !strcmp(old->name, new_name)) {
		/* A benign update from one interface onto itself.
		 * no need to run the eventscripts in this case, just return
		 * success.
		 */
		ctdb_request_control_reply(ctdb, c, NULL, 0, NULL);
		return 0;
	}

	state = talloc(vnn, struct ctdb_do_updateip_state);
	CTDB_NO_MEMORY(ctdb, state);

	state->c = talloc_steal(ctdb, c);
	state->old = old;
	state->vnn = vnn;

	vnn->update_in_flight = true;
	talloc_set_destructor(state, ctdb_updateip_destructor);

	DEBUG(DEBUG_NOTICE,("Update of IP %s/%u from "
			    "interface %s to %s\n",
			    ctdb_addr_to_str(&vnn->public_address),
			    vnn->public_netmask_bits,
			    old->name,
			    new_name));

	ret = ctdb_event_script_callback(ctdb,
					 state,
					 ctdb_do_updateip_callback,
					 state,
					 CTDB_EVENT_UPDATE_IP,
					 "%s %s %s %u",
					 state->old->name,
					 new_name,
					 ctdb_addr_to_str(&vnn->public_address),
					 vnn->public_netmask_bits);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,(__location__ " Failed update IP %s from interface %s to %s\n",
				 ctdb_addr_to_str(&vnn->public_address),
				 old->name, new_name));
		talloc_free(state);
		return -1;
	}

	return 0;
}

/*
  Find the vnn of the node that has a public ip address
  returns -1 if the address is not known as a public address
 */
static struct ctdb_vnn *find_public_ip_vnn(struct ctdb_context *ctdb, ctdb_sock_addr *addr)
{
	struct ctdb_vnn *vnn;

	for (vnn=ctdb->vnn;vnn;vnn=vnn->next) {
		if (ctdb_same_ip(&vnn->public_address, addr)) {
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
	struct ctdb_public_ip *pip = (struct ctdb_public_ip *)indata.dptr;
	struct ctdb_vnn *vnn;
	bool have_ip = false;
	bool do_updateip = false;
	bool do_takeip = false;
	struct ctdb_iface *best_iface = NULL;

	if (pip->pnn != ctdb->pnn) {
		DEBUG(DEBUG_ERR,(__location__" takeoverip called for an ip '%s' "
				 "with pnn %d, but we're node %d\n",
				 ctdb_addr_to_str(&pip->addr),
				 pip->pnn, ctdb->pnn));
		return -1;
	}

	/* update out vnn list */
	vnn = find_public_ip_vnn(ctdb, &pip->addr);
	if (vnn == NULL) {
		DEBUG(DEBUG_INFO,("takeoverip called for an ip '%s' that is not a public address\n",
			ctdb_addr_to_str(&pip->addr)));
		return 0;
	}

	if (ctdb->do_checkpublicip) {
		have_ip = ctdb_sys_have_ip(&pip->addr);
	}
	best_iface = ctdb_vnn_best_iface(ctdb, vnn);
	if (best_iface == NULL) {
		DEBUG(DEBUG_ERR,("takeoverip of IP %s/%u failed to find"
				 "a usable interface (old %s, have_ip %d)\n",
				 ctdb_addr_to_str(&vnn->public_address),
				 vnn->public_netmask_bits,
				 ctdb_vnn_iface_string(vnn),
				 have_ip));
		return -1;
	}

	if (vnn->iface == NULL && vnn->pnn == -1 && have_ip && best_iface != NULL) {
		DEBUG(DEBUG_ERR,("Taking over newly created ip\n"));
		have_ip = false;
	}


	if (vnn->iface == NULL && have_ip) {
		DEBUG(DEBUG_CRIT,(__location__ " takeoverip of IP %s is known to the kernel, "
				  "but we have no interface assigned, has someone manually configured it? Ignore for now.\n",
				 ctdb_addr_to_str(&vnn->public_address)));
		return 0;
	}

	if (vnn->pnn != ctdb->pnn && have_ip && vnn->pnn != -1) {
		DEBUG(DEBUG_CRIT,(__location__ " takeoverip of IP %s is known to the kernel, "
				  "and we have it on iface[%s], but it was assigned to node %d"
				  "and we are node %d, banning ourself\n",
				 ctdb_addr_to_str(&vnn->public_address),
				 ctdb_vnn_iface_string(vnn), vnn->pnn, ctdb->pnn));
		ctdb_ban_self(ctdb);
		return -1;
	}

	if (vnn->pnn == -1 && have_ip) {
		vnn->pnn = ctdb->pnn;
		DEBUG(DEBUG_CRIT,(__location__ " takeoverip of IP %s is known to the kernel, "
				  "and we already have it on iface[%s], update local daemon\n",
				 ctdb_addr_to_str(&vnn->public_address),
				  ctdb_vnn_iface_string(vnn)));
		return 0;
	}

	if (vnn->iface) {
		if (vnn->iface != best_iface) {
			if (!vnn->iface->link_up) {
				do_updateip = true;
			} else if (vnn->iface->references > (best_iface->references + 1)) {
				/* only move when the rebalance gains something */
					do_updateip = true;
			}
		}
	}

	if (!have_ip) {
		if (do_updateip) {
			ctdb_vnn_unassign_iface(ctdb, vnn);
			do_updateip = false;
		}
		do_takeip = true;
	}

	if (do_takeip) {
		ret = ctdb_do_takeip(ctdb, c, vnn);
		if (ret != 0) {
			return -1;
		}
	} else if (do_updateip) {
		ret = ctdb_do_updateip(ctdb, c, vnn);
		if (ret != 0) {
			return -1;
		}
	} else {
		/*
		 * The interface is up and the kernel known the ip
		 * => do nothing
		 */
		DEBUG(DEBUG_INFO,("Redundant takeover of IP %s/%u on interface %s (ip already held)\n",
			ctdb_addr_to_str(&pip->addr),
			vnn->public_netmask_bits,
			ctdb_vnn_iface_string(vnn)));
		return 0;
	}

	/* tell ctdb_control.c that we will be replying asynchronously */
	*async_reply = true;

	return 0;
}

/*
  takeover an ip address old v4 style
 */
int32_t ctdb_control_takeover_ipv4(struct ctdb_context *ctdb, 
				struct ctdb_req_control *c,
				TDB_DATA indata, 
				bool *async_reply)
{
	TDB_DATA data;
	
	data.dsize = sizeof(struct ctdb_public_ip);
	data.dptr  = (uint8_t *)talloc_zero(c, struct ctdb_public_ip);
	CTDB_NO_MEMORY(ctdb, data.dptr);
	
	memcpy(data.dptr, indata.dptr, indata.dsize);
	return ctdb_control_takeover_ip(ctdb, c, data, async_reply);
}

/*
  kill any clients that are registered with a IP that is being released
 */
static void release_kill_clients(struct ctdb_context *ctdb, ctdb_sock_addr *addr)
{
	struct ctdb_client_ip *ip;

	DEBUG(DEBUG_INFO,("release_kill_clients for ip %s\n",
		ctdb_addr_to_str(addr)));

	for (ip=ctdb->client_ip_list; ip; ip=ip->next) {
		ctdb_sock_addr tmp_addr;

		tmp_addr = ip->addr;
		DEBUG(DEBUG_INFO,("checking for client %u with IP %s\n", 
			ip->client_id,
			ctdb_addr_to_str(&ip->addr)));

		if (ctdb_same_ip(&tmp_addr, addr)) {
			struct ctdb_client *client = ctdb_reqid_find(ctdb, 
								     ip->client_id, 
								     struct ctdb_client);
			DEBUG(DEBUG_INFO,("matched client %u with IP %s and pid %u\n", 
				ip->client_id,
				ctdb_addr_to_str(&ip->addr),
				client->pid));

			if (client->pid != 0) {
				DEBUG(DEBUG_INFO,(__location__ " Killing client pid %u for IP %s on client_id %u\n",
					(unsigned)client->pid,
					ctdb_addr_to_str(addr),
					ip->client_id));
				kill(client->pid, SIGKILL);
			}
		}
	}
}

static void do_delete_ip(struct ctdb_context *ctdb, struct ctdb_vnn *vnn)
{
	DLIST_REMOVE(ctdb->vnn, vnn);
	ctdb_vnn_unassign_iface(ctdb, vnn);
	ctdb_remove_orphaned_ifaces(ctdb, vnn);
	talloc_free(vnn);
}

/*
  called when releaseip event finishes
 */
static void release_ip_callback(struct ctdb_context *ctdb, int status, 
				void *private_data)
{
	struct takeover_callback_state *state = 
		talloc_get_type(private_data, struct takeover_callback_state);
	TDB_DATA data;

	if (status == -ETIME) {
		ctdb_ban_self(ctdb);
	}

	if (ctdb->do_checkpublicip && ctdb_sys_have_ip(state->addr)) {
		DEBUG(DEBUG_ERR, ("IP %s still hosted during release IP callback, failing\n",
				  ctdb_addr_to_str(state->addr)));
		ctdb_request_control_reply(ctdb, state->c, NULL, -1, NULL);
		talloc_free(state);
		return;
	}

	/* send a message to all clients of this node telling them
	   that the cluster has been reconfigured and they should
	   release any sockets on this IP */
	data.dptr = (uint8_t *)talloc_strdup(state, ctdb_addr_to_str(state->addr));
	CTDB_NO_MEMORY_VOID(ctdb, data.dptr);
	data.dsize = strlen((char *)data.dptr)+1;

	DEBUG(DEBUG_INFO,(__location__ " sending RELEASE_IP for '%s'\n", data.dptr));

	ctdb_daemon_send_message(ctdb, ctdb->pnn, CTDB_SRVID_RELEASE_IP, data);

	/* kill clients that have registered with this IP */
	release_kill_clients(ctdb, state->addr);

	ctdb_vnn_unassign_iface(ctdb, state->vnn);

	/* Process the IP if it has been marked for deletion */
	if (state->vnn->delete_pending) {
		do_delete_ip(ctdb, state->vnn);
		state->vnn = NULL;
	}

	/* the control succeeded */
	ctdb_request_control_reply(ctdb, state->c, NULL, 0, NULL);
	talloc_free(state);
}

static int ctdb_releaseip_destructor(struct takeover_callback_state *state)
{
	if (state->vnn != NULL) {
		state->vnn->update_in_flight = false;
	}
	return 0;
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
	char *iface;

	/* update our vnn list */
	vnn = find_public_ip_vnn(ctdb, &pip->addr);
	if (vnn == NULL) {
		DEBUG(DEBUG_INFO,("releaseip called for an ip '%s' that is not a public address\n",
			ctdb_addr_to_str(&pip->addr)));
		return 0;
	}
	vnn->pnn = pip->pnn;

	/* stop any previous arps */
	talloc_free(vnn->takeover_ctx);
	vnn->takeover_ctx = NULL;

	/* Some ctdb tool commands (e.g. moveip, rebalanceip) send
	 * lazy multicast to drop an IP from any node that isn't the
	 * intended new node.  The following causes makes ctdbd ignore
	 * a release for any address it doesn't host.
	 */
	if (ctdb->do_checkpublicip) {
		if (!ctdb_sys_have_ip(&pip->addr)) {
			DEBUG(DEBUG_DEBUG,("Redundant release of IP %s/%u on interface %s (ip not held)\n",
				ctdb_addr_to_str(&pip->addr),
				vnn->public_netmask_bits,
				ctdb_vnn_iface_string(vnn)));
			ctdb_vnn_unassign_iface(ctdb, vnn);
			return 0;
		}
	} else {
		if (vnn->iface == NULL) {
			DEBUG(DEBUG_DEBUG,("Redundant release of IP %s/%u (ip not held)\n",
					   ctdb_addr_to_str(&pip->addr),
					   vnn->public_netmask_bits));
			return 0;
		}
	}

	/* There is a potential race between take_ip and us because we
	 * update the VNN via a callback that run when the
	 * eventscripts have been run.  Avoid the race by allowing one
	 * update to be in flight at a time.
	 */
	if (vnn->update_in_flight) {
		DEBUG(DEBUG_NOTICE,("Release of IP %s/%u rejected "
				    "update for this IP already in flight\n",
				    ctdb_addr_to_str(&vnn->public_address),
				    vnn->public_netmask_bits));
		return -1;
	}

	iface = strdup(ctdb_vnn_iface_string(vnn));

	DEBUG(DEBUG_NOTICE,("Release of IP %s/%u on interface %s  node:%d\n",
		ctdb_addr_to_str(&pip->addr),
		vnn->public_netmask_bits,
		iface,
		pip->pnn));

	state = talloc(ctdb, struct takeover_callback_state);
	CTDB_NO_MEMORY(ctdb, state);

	state->c = talloc_steal(state, c);
	state->addr = talloc(state, ctdb_sock_addr);       
	CTDB_NO_MEMORY(ctdb, state->addr);
	*state->addr = pip->addr;
	state->vnn   = vnn;

	vnn->update_in_flight = true;
	talloc_set_destructor(state, ctdb_releaseip_destructor);

	ret = ctdb_event_script_callback(ctdb, 
					 state, release_ip_callback, state,
					 CTDB_EVENT_RELEASE_IP,
					 "%s %s %u",
					 iface,
					 ctdb_addr_to_str(&pip->addr),
					 vnn->public_netmask_bits);
	free(iface);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,(__location__ " Failed to release IP %s on interface %s\n",
			ctdb_addr_to_str(&pip->addr),
			ctdb_vnn_iface_string(vnn)));
		talloc_free(state);
		return -1;
	}

	/* tell the control that we will be reply asynchronously */
	*async_reply = true;
	return 0;
}

/*
  release an ip address old v4 style
 */
int32_t ctdb_control_release_ipv4(struct ctdb_context *ctdb, 
				struct ctdb_req_control *c,
				TDB_DATA indata, 
				bool *async_reply)
{
	TDB_DATA data;
	
	data.dsize = sizeof(struct ctdb_public_ip);
	data.dptr  = (uint8_t *)talloc_zero(c, struct ctdb_public_ip);
	CTDB_NO_MEMORY(ctdb, data.dptr);
	
	memcpy(data.dptr, indata.dptr, indata.dsize);
	return ctdb_control_release_ip(ctdb, c, data, async_reply);
}


static int ctdb_add_public_address(struct ctdb_context *ctdb,
				   ctdb_sock_addr *addr,
				   unsigned mask, const char *ifaces,
				   bool check_address)
{
	struct ctdb_vnn      *vnn;
	uint32_t num = 0;
	char *tmp;
	const char *iface;
	int i;
	int ret;

	tmp = strdup(ifaces);
	for (iface = strtok(tmp, ","); iface; iface = strtok(NULL, ",")) {
		if (!ctdb_sys_check_iface_exists(iface)) {
			DEBUG(DEBUG_CRIT,("Interface %s does not exist. Can not add public-address : %s\n", iface, ctdb_addr_to_str(addr)));
			free(tmp);
			return -1;
		}
	}
	free(tmp);

	/* Verify that we dont have an entry for this ip yet */
	for (vnn=ctdb->vnn;vnn;vnn=vnn->next) {
		if (ctdb_same_sockaddr(addr, &vnn->public_address)) {
			DEBUG(DEBUG_CRIT,("Same ip '%s' specified multiple times in the public address list \n", 
				ctdb_addr_to_str(addr)));
			return -1;
		}		
	}

	/* create a new vnn structure for this ip address */
	vnn = talloc_zero(ctdb, struct ctdb_vnn);
	CTDB_NO_MEMORY_FATAL(ctdb, vnn);
	vnn->ifaces = talloc_array(vnn, const char *, num + 2);
	tmp = talloc_strdup(vnn, ifaces);
	CTDB_NO_MEMORY_FATAL(ctdb, tmp);
	for (iface = strtok(tmp, ","); iface; iface = strtok(NULL, ",")) {
		vnn->ifaces = talloc_realloc(vnn, vnn->ifaces, const char *, num + 2);
		CTDB_NO_MEMORY_FATAL(ctdb, vnn->ifaces);
		vnn->ifaces[num] = talloc_strdup(vnn, iface);
		CTDB_NO_MEMORY_FATAL(ctdb, vnn->ifaces[num]);
		num++;
	}
	talloc_free(tmp);
	vnn->ifaces[num] = NULL;
	vnn->public_address      = *addr;
	vnn->public_netmask_bits = mask;
	vnn->pnn                 = -1;
	if (check_address) {
		if (ctdb_sys_have_ip(addr)) {
			DEBUG(DEBUG_ERR,("We are already hosting public address '%s'. setting PNN to ourself:%d\n", ctdb_addr_to_str(addr), ctdb->pnn));
			vnn->pnn = ctdb->pnn;
		}
	}

	for (i=0; vnn->ifaces[i]; i++) {
		ret = ctdb_add_local_iface(ctdb, vnn->ifaces[i]);
		if (ret != 0) {
			DEBUG(DEBUG_CRIT, (__location__ " failed to add iface[%s] "
					   "for public_address[%s]\n",
					   vnn->ifaces[i], ctdb_addr_to_str(addr)));
			talloc_free(vnn);
			return -1;
		}
	}

	DLIST_ADD(ctdb->vnn, vnn);

	return 0;
}

static void ctdb_check_interfaces_event(struct event_context *ev, struct timed_event *te, 
				  struct timeval t, void *private_data)
{
	struct ctdb_context *ctdb = talloc_get_type(private_data, 
							struct ctdb_context);
	struct ctdb_vnn *vnn;

	for (vnn=ctdb->vnn;vnn;vnn=vnn->next) {
		int i;

		for (i=0; vnn->ifaces[i] != NULL; i++) {
			if (!ctdb_sys_check_iface_exists(vnn->ifaces[i])) {
				DEBUG(DEBUG_CRIT,("Interface %s does not exist but is used by public ip %s\n",
					vnn->ifaces[i],
					ctdb_addr_to_str(&vnn->public_address)));
			}
		}
	}

	event_add_timed(ctdb->ev, ctdb->check_public_ifaces_ctx, 
		timeval_current_ofs(30, 0), 
		ctdb_check_interfaces_event, ctdb);
}


int ctdb_start_monitoring_interfaces(struct ctdb_context *ctdb)
{
	if (ctdb->check_public_ifaces_ctx != NULL) {
		talloc_free(ctdb->check_public_ifaces_ctx);
		ctdb->check_public_ifaces_ctx = NULL;
	}

	ctdb->check_public_ifaces_ctx = talloc_new(ctdb);
	if (ctdb->check_public_ifaces_ctx == NULL) {
		ctdb_fatal(ctdb, "failed to allocate context for checking interfaces");
	}

	event_add_timed(ctdb->ev, ctdb->check_public_ifaces_ctx, 
		timeval_current_ofs(30, 0), 
		ctdb_check_interfaces_event, ctdb);

	return 0;
}


/*
  setup the public address lists from a file
*/
int ctdb_set_public_addresses(struct ctdb_context *ctdb, bool check_addresses)
{
	char **lines;
	int nlines;
	int i;

	lines = file_lines_load(ctdb->public_addresses_file, &nlines, 0, ctdb);
	if (lines == NULL) {
		ctdb_set_error(ctdb, "Failed to load public address list '%s'\n", ctdb->public_addresses_file);
		return -1;
	}
	while (nlines > 0 && strcmp(lines[nlines-1], "") == 0) {
		nlines--;
	}

	for (i=0;i<nlines;i++) {
		unsigned mask;
		ctdb_sock_addr addr;
		const char *addrstr;
		const char *ifaces;
		char *tok, *line;

		line = lines[i];
		while ((*line == ' ') || (*line == '\t')) {
			line++;
		}
		if (*line == '#') {
			continue;
		}
		if (strcmp(line, "") == 0) {
			continue;
		}
		tok = strtok(line, " \t");
		addrstr = tok;
		tok = strtok(NULL, " \t");
		if (tok == NULL) {
			if (NULL == ctdb->default_public_interface) {
				DEBUG(DEBUG_CRIT,("No default public interface and no interface specified at line %u of public address list\n",
					 i+1));
				talloc_free(lines);
				return -1;
			}
			ifaces = ctdb->default_public_interface;
		} else {
			ifaces = tok;
		}

		if (!addrstr || !parse_ip_mask(addrstr, ifaces, &addr, &mask)) {
			DEBUG(DEBUG_CRIT,("Badly formed line %u in public address list\n", i+1));
			talloc_free(lines);
			return -1;
		}
		if (ctdb_add_public_address(ctdb, &addr, mask, ifaces, check_addresses)) {
			DEBUG(DEBUG_CRIT,("Failed to add line %u to the public address list\n", i+1));
			talloc_free(lines);
			return -1;
		}
	}


	talloc_free(lines);
	return 0;
}

int ctdb_set_single_public_ip(struct ctdb_context *ctdb,
			      const char *iface,
			      const char *ip)
{
	struct ctdb_vnn *svnn;
	struct ctdb_iface *cur = NULL;
	bool ok;
	int ret;

	svnn = talloc_zero(ctdb, struct ctdb_vnn);
	CTDB_NO_MEMORY(ctdb, svnn);

	svnn->ifaces = talloc_array(svnn, const char *, 2);
	CTDB_NO_MEMORY(ctdb, svnn->ifaces);
	svnn->ifaces[0] = talloc_strdup(svnn->ifaces, iface);
	CTDB_NO_MEMORY(ctdb, svnn->ifaces[0]);
	svnn->ifaces[1] = NULL;

	ok = parse_ip(ip, iface, 0, &svnn->public_address);
	if (!ok) {
		talloc_free(svnn);
		return -1;
	}

	ret = ctdb_add_local_iface(ctdb, svnn->ifaces[0]);
	if (ret != 0) {
		DEBUG(DEBUG_CRIT, (__location__ " failed to add iface[%s] "
				   "for single_ip[%s]\n",
				   svnn->ifaces[0],
				   ctdb_addr_to_str(&svnn->public_address)));
		talloc_free(svnn);
		return -1;
	}

	/* assume the single public ip interface is initially "good" */
	cur = ctdb_find_iface(ctdb, iface);
	if (cur == NULL) {
		DEBUG(DEBUG_CRIT,("Can not find public interface %s used by --single-public-ip", iface));
		return -1;
	}
	cur->link_up = true;

	ret = ctdb_vnn_assign_iface(ctdb, svnn);
	if (ret != 0) {
		talloc_free(svnn);
		return -1;
	}

	ctdb->single_ip_vnn = svnn;
	return 0;
}

struct ctdb_public_ip_list {
	struct ctdb_public_ip_list *next;
	uint32_t pnn;
	ctdb_sock_addr addr;
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


/* Can the given node host the given IP: is the public IP known to the
 * node and is NOIPHOST unset?
*/
static bool can_node_host_ip(struct ctdb_context *ctdb, int32_t pnn, 
			     struct ctdb_ipflags ipflags,
			     struct ctdb_public_ip_list *ip)
{
	struct ctdb_all_public_ips *public_ips;
	int i;

	if (ipflags.noiphost) {
		return false;
	}

	public_ips = ctdb->nodes[pnn]->available_public_ips;

	if (public_ips == NULL) {
		return false;
	}

	for (i=0; i<public_ips->num; i++) {
		if (ctdb_same_ip(&ip->addr, &public_ips->ips[i].addr)) {
			/* yes, this node can serve this public ip */
			return true;
		}
	}

	return false;
}

static bool can_node_takeover_ip(struct ctdb_context *ctdb, int32_t pnn, 
				 struct ctdb_ipflags ipflags,
				 struct ctdb_public_ip_list *ip)
{
	if (ipflags.noiptakeover) {
		return false;
	}

	return can_node_host_ip(ctdb, pnn, ipflags, ip);
}

/* search the node lists list for a node to takeover this ip.
   pick the node that currently are serving the least number of ips
   so that the ips get spread out evenly.
*/
static int find_takeover_node(struct ctdb_context *ctdb, 
		struct ctdb_ipflags *ipflags,
		struct ctdb_public_ip_list *ip,
		struct ctdb_public_ip_list *all_ips)
{
	int pnn, min=0, num;
	int i, numnodes;

	numnodes = talloc_array_length(ipflags);
	pnn    = -1;
	for (i=0; i<numnodes; i++) {
		/* verify that this node can serve this ip */
		if (!can_node_takeover_ip(ctdb, i, ipflags[i], ip)) {
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
		DEBUG(DEBUG_WARNING,(__location__ " Could not find node to take over public address '%s'\n",
			ctdb_addr_to_str(&ip->addr)));

		return -1;
	}

	ip->pnn = pnn;
	return 0;
}

#define IP_KEYLEN	4
static uint32_t *ip_key(ctdb_sock_addr *ip)
{
	static uint32_t key[IP_KEYLEN];

	bzero(key, sizeof(key));

	switch (ip->sa.sa_family) {
	case AF_INET:
		key[3]	= htonl(ip->ip.sin_addr.s_addr);
		break;
	case AF_INET6: {
		uint32_t *s6_a32 = (uint32_t *)&(ip->ip6.sin6_addr.s6_addr);
		key[0]	= htonl(s6_a32[0]);
		key[1]	= htonl(s6_a32[1]);
		key[2]	= htonl(s6_a32[2]);
		key[3]	= htonl(s6_a32[3]);
		break;
	}
	default:
		DEBUG(DEBUG_ERR, (__location__ " ERROR, unknown family passed :%u\n", ip->sa.sa_family));
		return key;
	}

	return key;
}

static void *add_ip_callback(void *parm, void *data)
{
	struct ctdb_public_ip_list *this_ip = parm; 
	struct ctdb_public_ip_list *prev_ip = data; 

	if (prev_ip == NULL) {
		return parm;
	}
	if (this_ip->pnn == -1) {
		this_ip->pnn = prev_ip->pnn;
	}

	return parm;
}

static int getips_count_callback(void *param, void *data)
{
	struct ctdb_public_ip_list **ip_list = (struct ctdb_public_ip_list **)param;
	struct ctdb_public_ip_list *new_ip = (struct ctdb_public_ip_list *)data;

	new_ip->next = *ip_list;
	*ip_list     = new_ip;
	return 0;
}

static struct ctdb_public_ip_list *
create_merged_ip_list(struct ctdb_context *ctdb)
{
	int i, j;
	struct ctdb_public_ip_list *ip_list;
	struct ctdb_all_public_ips *public_ips;

	if (ctdb->ip_tree != NULL) {
		talloc_free(ctdb->ip_tree);
		ctdb->ip_tree = NULL;
	}
	ctdb->ip_tree = trbt_create(ctdb, 0);

	for (i=0;i<ctdb->num_nodes;i++) {
		public_ips = ctdb->nodes[i]->known_public_ips;

		if (ctdb->nodes[i]->flags & NODE_FLAGS_DELETED) {
			continue;
		}

		/* there were no public ips for this node */
		if (public_ips == NULL) {
			continue;
		}		

		for (j=0;j<public_ips->num;j++) {
			struct ctdb_public_ip_list *tmp_ip; 

			tmp_ip = talloc_zero(ctdb->ip_tree, struct ctdb_public_ip_list);
			CTDB_NO_MEMORY_NULL(ctdb, tmp_ip);
			/* Do not use information about IP addresses hosted
			 * on other nodes, it may not be accurate */
			if (public_ips->ips[j].pnn == ctdb->nodes[i]->pnn) {
				tmp_ip->pnn = public_ips->ips[j].pnn;
			} else {
				tmp_ip->pnn = -1;
			}
			tmp_ip->addr = public_ips->ips[j].addr;
			tmp_ip->next = NULL;

			trbt_insertarray32_callback(ctdb->ip_tree,
				IP_KEYLEN, ip_key(&public_ips->ips[j].addr),
				add_ip_callback,
				tmp_ip);
		}
	}

	ip_list = NULL;
	trbt_traversearray32(ctdb->ip_tree, IP_KEYLEN, getips_count_callback, &ip_list);

	return ip_list;
}

/* 
 * This is the length of the longtest common prefix between the IPs.
 * It is calculated by XOR-ing the 2 IPs together and counting the
 * number of leading zeroes.  The implementation means that all
 * addresses end up being 128 bits long.
 *
 * FIXME? Should we consider IPv4 and IPv6 separately given that the
 * 12 bytes of 0 prefix padding will hurt the algorithm if there are
 * lots of nodes and IP addresses?
 */
static uint32_t ip_distance(ctdb_sock_addr *ip1, ctdb_sock_addr *ip2)
{
	uint32_t ip1_k[IP_KEYLEN];
	uint32_t *t;
	int i;
	uint32_t x;

	uint32_t distance = 0;

	memcpy(ip1_k, ip_key(ip1), sizeof(ip1_k));
	t = ip_key(ip2);
	for (i=0; i<IP_KEYLEN; i++) {
		x = ip1_k[i] ^ t[i];
		if (x == 0) {
			distance += 32;
		} else {
			/* Count number of leading zeroes. 
			 * FIXME? This could be optimised...
			 */
			while ((x & (1 << 31)) == 0) {
				x <<= 1;
				distance += 1;
			}
		}
	}

	return distance;
}

/* Calculate the IP distance for the given IP relative to IPs on the
   given node.  The ips argument is generally the all_ips variable
   used in the main part of the algorithm.
 */
static uint32_t ip_distance_2_sum(ctdb_sock_addr *ip,
				  struct ctdb_public_ip_list *ips,
				  int pnn)
{
	struct ctdb_public_ip_list *t;
	uint32_t d;

	uint32_t sum = 0;

	for (t=ips; t != NULL; t=t->next) {
		if (t->pnn != pnn) {
			continue;
		}

		/* Optimisation: We never calculate the distance
		 * between an address and itself.  This allows us to
		 * calculate the effect of removing an address from a
		 * node by simply calculating the distance between
		 * that address and all of the exitsing addresses.
		 * Moreover, we assume that we're only ever dealing
		 * with addresses from all_ips so we can identify an
		 * address via a pointer rather than doing a more
		 * expensive address comparison. */
		if (&(t->addr) == ip) {
			continue;
		}

		d = ip_distance(ip, &(t->addr));
		sum += d * d;  /* Cheaper than pulling in math.h :-) */
	}

	return sum;
}

/* Return the LCP2 imbalance metric for addresses currently assigned
   to the given node.
 */
static uint32_t lcp2_imbalance(struct ctdb_public_ip_list * all_ips, int pnn)
{
	struct ctdb_public_ip_list *t;

	uint32_t imbalance = 0;

	for (t=all_ips; t!=NULL; t=t->next) {
		if (t->pnn != pnn) {
			continue;
		}
		/* Pass the rest of the IPs rather than the whole
		   all_ips input list.
		*/
		imbalance += ip_distance_2_sum(&(t->addr), t->next, pnn);
	}

	return imbalance;
}

/* Allocate any unassigned IPs just by looping through the IPs and
 * finding the best node for each.
 */
static void basic_allocate_unassigned(struct ctdb_context *ctdb,
				      struct ctdb_ipflags *ipflags,
				      struct ctdb_public_ip_list *all_ips)
{
	struct ctdb_public_ip_list *tmp_ip;

	/* loop over all ip's and find a physical node to cover for 
	   each unassigned ip.
	*/
	for (tmp_ip=all_ips;tmp_ip;tmp_ip=tmp_ip->next) {
		if (tmp_ip->pnn == -1) {
			if (find_takeover_node(ctdb, ipflags, tmp_ip, all_ips)) {
				DEBUG(DEBUG_WARNING,("Failed to find node to cover ip %s\n",
					ctdb_addr_to_str(&tmp_ip->addr)));
			}
		}
	}
}

/* Basic non-deterministic rebalancing algorithm.
 */
static void basic_failback(struct ctdb_context *ctdb,
			   struct ctdb_ipflags *ipflags,
			   struct ctdb_public_ip_list *all_ips,
			   int num_ips)
{
	int i, numnodes;
	int maxnode, maxnum, minnode, minnum, num, retries;
	struct ctdb_public_ip_list *tmp_ip;

	numnodes = talloc_array_length(ipflags);
	retries = 0;

try_again:
	maxnum=0;
	minnum=0;

	/* for each ip address, loop over all nodes that can serve
	   this ip and make sure that the difference between the node
	   serving the most and the node serving the least ip's are
	   not greater than 1.
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
		for (i=0; i<numnodes; i++) {
			/* only check nodes that can actually serve this ip */
			if (!can_node_takeover_ip(ctdb, i, ipflags[i], tmp_ip)) {
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
			DEBUG(DEBUG_WARNING,(__location__ " Could not find maxnode. May not be able to serve ip '%s'\n",
				ctdb_addr_to_str(&tmp_ip->addr)));

			continue;
		}

		/* if the spread between the smallest and largest coverage by
		   a node is >=2 we steal one of the ips from the node with
		   most coverage to even things out a bit.
		   try to do this a limited number of times since we dont
		   want to spend too much time balancing the ip coverage.
		*/
		if ( (maxnum > minnum+1)
		     && (retries < (num_ips + 5)) ){
			struct ctdb_public_ip_list *tmp;

			/* Reassign one of maxnode's VNNs */
			for (tmp=all_ips;tmp;tmp=tmp->next) {
				if (tmp->pnn == maxnode) {
					(void)find_takeover_node(ctdb, ipflags, tmp, all_ips);
					retries++;
					goto try_again;;
				}
			}
		}
	}
}

static void lcp2_init(struct ctdb_context *tmp_ctx,
		      struct ctdb_ipflags *ipflags,
		      struct ctdb_public_ip_list *all_ips,
		      uint32_t *force_rebalance_nodes,
		      uint32_t **lcp2_imbalances,
		      bool **rebalance_candidates)
{
	int i, numnodes;
	struct ctdb_public_ip_list *tmp_ip;

	numnodes = talloc_array_length(ipflags);

	*rebalance_candidates = talloc_array(tmp_ctx, bool, numnodes);
	CTDB_NO_MEMORY_FATAL(tmp_ctx, *rebalance_candidates);
	*lcp2_imbalances = talloc_array(tmp_ctx, uint32_t, numnodes);
	CTDB_NO_MEMORY_FATAL(tmp_ctx, *lcp2_imbalances);

	for (i=0; i<numnodes; i++) {
		(*lcp2_imbalances)[i] = lcp2_imbalance(all_ips, i);
		/* First step: assume all nodes are candidates */
		(*rebalance_candidates)[i] = true;
	}

	/* 2nd step: if a node has IPs assigned then it must have been
	 * healthy before, so we remove it from consideration.  This
	 * is overkill but is all we have because we don't maintain
	 * state between takeover runs.  An alternative would be to
	 * keep state and invalidate it every time the recovery master
	 * changes.
	 */
	for (tmp_ip=all_ips;tmp_ip;tmp_ip=tmp_ip->next) {
		if (tmp_ip->pnn != -1) {
			(*rebalance_candidates)[tmp_ip->pnn] = false;
		}
	}

	/* 3rd step: if a node is forced to re-balance then
	   we allow failback onto the node */
	if (force_rebalance_nodes == NULL) {
		return;
	}
	for (i = 0; i < talloc_array_length(force_rebalance_nodes); i++) {
		uint32_t pnn = force_rebalance_nodes[i];
		if (pnn >= numnodes) {
			DEBUG(DEBUG_ERR,
			      (__location__ "unknown node %u\n", pnn));
			continue;
		}

		DEBUG(DEBUG_NOTICE,
		      ("Forcing rebalancing of IPs to node %u\n", pnn));
		(*rebalance_candidates)[pnn] = true;
	}
}

/* Allocate any unassigned addresses using the LCP2 algorithm to find
 * the IP/node combination that will cost the least.
 */
static void lcp2_allocate_unassigned(struct ctdb_context *ctdb,
				     struct ctdb_ipflags *ipflags,
				     struct ctdb_public_ip_list *all_ips,
				     uint32_t *lcp2_imbalances)
{
	struct ctdb_public_ip_list *tmp_ip;
	int dstnode, numnodes;

	int minnode;
	uint32_t mindsum, dstdsum, dstimbl, minimbl;
	struct ctdb_public_ip_list *minip;

	bool should_loop = true;
	bool have_unassigned = true;

	numnodes = talloc_array_length(ipflags);

	while (have_unassigned && should_loop) {
		should_loop = false;

		DEBUG(DEBUG_DEBUG,(" ----------------------------------------\n"));
		DEBUG(DEBUG_DEBUG,(" CONSIDERING MOVES (UNASSIGNED)\n"));

		minnode = -1;
		mindsum = 0;
		minip = NULL;

		/* loop over each unassigned ip. */
		for (tmp_ip=all_ips;tmp_ip;tmp_ip=tmp_ip->next) {
			if (tmp_ip->pnn != -1) {
				continue;
			}

			for (dstnode=0; dstnode<numnodes; dstnode++) {
				/* only check nodes that can actually takeover this ip */
				if (!can_node_takeover_ip(ctdb, dstnode,
							  ipflags[dstnode],
							  tmp_ip)) {
					/* no it couldnt   so skip to the next node */
					continue;
				}

				dstdsum = ip_distance_2_sum(&(tmp_ip->addr), all_ips, dstnode);
				dstimbl = lcp2_imbalances[dstnode] + dstdsum;
				DEBUG(DEBUG_DEBUG,(" %s -> %d [+%d]\n",
						   ctdb_addr_to_str(&(tmp_ip->addr)),
						   dstnode,
						   dstimbl - lcp2_imbalances[dstnode]));


				if ((minnode == -1) || (dstdsum < mindsum)) {
					minnode = dstnode;
					minimbl = dstimbl;
					mindsum = dstdsum;
					minip = tmp_ip;
					should_loop = true;
				}
			}
		}

		DEBUG(DEBUG_DEBUG,(" ----------------------------------------\n"));

		/* If we found one then assign it to the given node. */
		if (minnode != -1) {
			minip->pnn = minnode;
			lcp2_imbalances[minnode] = minimbl;
			DEBUG(DEBUG_INFO,(" %s -> %d [+%d]\n",
					  ctdb_addr_to_str(&(minip->addr)),
					  minnode,
					  mindsum));
		}

		/* There might be a better way but at least this is clear. */
		have_unassigned = false;
		for (tmp_ip=all_ips;tmp_ip;tmp_ip=tmp_ip->next) {
			if (tmp_ip->pnn == -1) {
				have_unassigned = true;
			}
		}
	}

	/* We know if we have an unassigned addresses so we might as
	 * well optimise.
	 */
	if (have_unassigned) {
		for (tmp_ip=all_ips;tmp_ip;tmp_ip=tmp_ip->next) {
			if (tmp_ip->pnn == -1) {
				DEBUG(DEBUG_WARNING,("Failed to find node to cover ip %s\n",
						     ctdb_addr_to_str(&tmp_ip->addr)));
			}
		}
	}
}

/* LCP2 algorithm for rebalancing the cluster.  Given a candidate node
 * to move IPs from, determines the best IP/destination node
 * combination to move from the source node.
 */
static bool lcp2_failback_candidate(struct ctdb_context *ctdb,
				    struct ctdb_ipflags *ipflags,
				    struct ctdb_public_ip_list *all_ips,
				    int srcnode,
				    uint32_t *lcp2_imbalances,
				    bool *rebalance_candidates)
{
	int dstnode, mindstnode, numnodes;
	uint32_t srcimbl, srcdsum, dstimbl, dstdsum;
	uint32_t minsrcimbl, mindstimbl;
	struct ctdb_public_ip_list *minip;
	struct ctdb_public_ip_list *tmp_ip;

	/* Find an IP and destination node that best reduces imbalance. */
	srcimbl = 0;
	minip = NULL;
	minsrcimbl = 0;
	mindstnode = -1;
	mindstimbl = 0;

	numnodes = talloc_array_length(ipflags);

	DEBUG(DEBUG_DEBUG,(" ----------------------------------------\n"));
	DEBUG(DEBUG_DEBUG,(" CONSIDERING MOVES FROM %d [%d]\n",
			   srcnode, lcp2_imbalances[srcnode]));

	for (tmp_ip=all_ips; tmp_ip; tmp_ip=tmp_ip->next) {
		/* Only consider addresses on srcnode. */
		if (tmp_ip->pnn != srcnode) {
			continue;
		}

		/* What is this IP address costing the source node? */
		srcdsum = ip_distance_2_sum(&(tmp_ip->addr), all_ips, srcnode);
		srcimbl = lcp2_imbalances[srcnode] - srcdsum;

		/* Consider this IP address would cost each potential
		 * destination node.  Destination nodes are limited to
		 * those that are newly healthy, since we don't want
		 * to do gratuitous failover of IPs just to make minor
		 * balance improvements.
		 */
		for (dstnode=0; dstnode<numnodes; dstnode++) {
			if (!rebalance_candidates[dstnode]) {
				continue;
			}

			/* only check nodes that can actually takeover this ip */
			if (!can_node_takeover_ip(ctdb, dstnode,
						  ipflags[dstnode], tmp_ip)) {
				/* no it couldnt   so skip to the next node */
				continue;
			}

			dstdsum = ip_distance_2_sum(&(tmp_ip->addr), all_ips, dstnode);
			dstimbl = lcp2_imbalances[dstnode] + dstdsum;
			DEBUG(DEBUG_DEBUG,(" %d [%d] -> %s -> %d [+%d]\n",
					   srcnode, -srcdsum,
					   ctdb_addr_to_str(&(tmp_ip->addr)),
					   dstnode, dstdsum));

			if ((dstimbl < lcp2_imbalances[srcnode]) &&
			    (dstdsum < srcdsum) &&			\
			    ((mindstnode == -1) ||				\
			     ((srcimbl + dstimbl) < (minsrcimbl + mindstimbl)))) {

				minip = tmp_ip;
				minsrcimbl = srcimbl;
				mindstnode = dstnode;
				mindstimbl = dstimbl;
			}
		}
	}
	DEBUG(DEBUG_DEBUG,(" ----------------------------------------\n"));

        if (mindstnode != -1) {
		/* We found a move that makes things better... */
		DEBUG(DEBUG_INFO,("%d [%d] -> %s -> %d [+%d]\n",
				  srcnode, minsrcimbl - lcp2_imbalances[srcnode],
				  ctdb_addr_to_str(&(minip->addr)),
				  mindstnode, mindstimbl - lcp2_imbalances[mindstnode]));


		lcp2_imbalances[srcnode] = minsrcimbl;
		lcp2_imbalances[mindstnode] = mindstimbl;
		minip->pnn = mindstnode;

		return true;
	}

        return false;
	
}

struct lcp2_imbalance_pnn {
	uint32_t imbalance;
	int pnn;
};

static int lcp2_cmp_imbalance_pnn(const void * a, const void * b)
{
	const struct lcp2_imbalance_pnn * lipa = (const struct lcp2_imbalance_pnn *) a;
	const struct lcp2_imbalance_pnn * lipb = (const struct lcp2_imbalance_pnn *) b;

	if (lipa->imbalance > lipb->imbalance) {
		return -1;
	} else if (lipa->imbalance == lipb->imbalance) {
		return 0;
	} else {
		return 1;
	}
}

/* LCP2 algorithm for rebalancing the cluster.  This finds the source
 * node with the highest LCP2 imbalance, and then determines the best
 * IP/destination node combination to move from the source node.
 */
static void lcp2_failback(struct ctdb_context *ctdb,
			  struct ctdb_ipflags *ipflags,
			  struct ctdb_public_ip_list *all_ips,
			  uint32_t *lcp2_imbalances,
			  bool *rebalance_candidates)
{
	int i, numnodes;
	struct lcp2_imbalance_pnn * lips;
	bool again;

	numnodes = talloc_array_length(ipflags);

try_again:
	/* Put the imbalances and nodes into an array, sort them and
	 * iterate through candidates.  Usually the 1st one will be
	 * used, so this doesn't cost much...
	 */
	DEBUG(DEBUG_DEBUG,("+++++++++++++++++++++++++++++++++++++++++\n"));
	DEBUG(DEBUG_DEBUG,("Selecting most imbalanced node from:\n"));
	lips = talloc_array(ctdb, struct lcp2_imbalance_pnn, numnodes);
	for (i=0; i<numnodes; i++) {
		lips[i].imbalance = lcp2_imbalances[i];
		lips[i].pnn = i;
		DEBUG(DEBUG_DEBUG,(" %d [%d]\n", i, lcp2_imbalances[i]));
	}
	qsort(lips, numnodes, sizeof(struct lcp2_imbalance_pnn),
	      lcp2_cmp_imbalance_pnn);

	again = false;
	for (i=0; i<numnodes; i++) {
		/* This means that all nodes had 0 or 1 addresses, so
		 * can't be imbalanced.
		 */
		if (lips[i].imbalance == 0) {
			break;
		}

		if (lcp2_failback_candidate(ctdb,
					    ipflags,
					    all_ips,
					    lips[i].pnn,
					    lcp2_imbalances,
					    rebalance_candidates)) {
			again = true;
			break;
		}
	}

	talloc_free(lips);
	if (again) {
		goto try_again;
	}
}

static void unassign_unsuitable_ips(struct ctdb_context *ctdb,
				    struct ctdb_ipflags *ipflags,
				    struct ctdb_public_ip_list *all_ips)
{
	struct ctdb_public_ip_list *tmp_ip;

	/* verify that the assigned nodes can serve that public ip
	   and set it to -1 if not
	*/
	for (tmp_ip=all_ips;tmp_ip;tmp_ip=tmp_ip->next) {
		if (tmp_ip->pnn == -1) {
			continue;
		}
		if (!can_node_host_ip(ctdb, tmp_ip->pnn,
				      ipflags[tmp_ip->pnn], tmp_ip) != 0) {
			/* this node can not serve this ip. */
			DEBUG(DEBUG_DEBUG,("Unassign IP: %s from %d\n",
					   ctdb_addr_to_str(&(tmp_ip->addr)),
					   tmp_ip->pnn));
			tmp_ip->pnn = -1;
		}
	}
}

static void ip_alloc_deterministic_ips(struct ctdb_context *ctdb,
				       struct ctdb_ipflags *ipflags,
				       struct ctdb_public_ip_list *all_ips)
{
	struct ctdb_public_ip_list *tmp_ip;
	int i, numnodes;

	numnodes = talloc_array_length(ipflags);

	DEBUG(DEBUG_NOTICE,("Deterministic IPs enabled. Resetting all ip allocations\n"));
       /* Allocate IPs to nodes in a modulo fashion so that IPs will
        *  always be allocated the same way for a specific set of
        *  available/unavailable nodes.
	*/

	for (i=0,tmp_ip=all_ips;tmp_ip;tmp_ip=tmp_ip->next,i++) {
		tmp_ip->pnn = i % numnodes;
	}

	/* IP failback doesn't make sense with deterministic
	 * IPs, since the modulo step above implicitly fails
	 * back IPs to their "home" node.
	 */
	if (1 == ctdb->tunable.no_ip_failback) {
		DEBUG(DEBUG_WARNING, ("WARNING: 'NoIPFailback' set but ignored - incompatible with 'DeterministicIPs\n"));
	}

	unassign_unsuitable_ips(ctdb, ipflags, all_ips);

	basic_allocate_unassigned(ctdb, ipflags, all_ips);

	/* No failback here! */
}

static void ip_alloc_nondeterministic_ips(struct ctdb_context *ctdb,
					  struct ctdb_ipflags *ipflags,
					  struct ctdb_public_ip_list *all_ips)
{
	/* This should be pushed down into basic_failback. */
	struct ctdb_public_ip_list *tmp_ip;
	int num_ips = 0;
	for (tmp_ip=all_ips;tmp_ip;tmp_ip=tmp_ip->next) {
		num_ips++;
	}

	unassign_unsuitable_ips(ctdb, ipflags, all_ips);

	basic_allocate_unassigned(ctdb, ipflags, all_ips);

	/* If we don't want IPs to fail back then don't rebalance IPs. */
	if (1 == ctdb->tunable.no_ip_failback) {
		return;
	}

	/* Now, try to make sure the ip adresses are evenly distributed
	   across the nodes.
	*/
	basic_failback(ctdb, ipflags, all_ips, num_ips);
}

static void ip_alloc_lcp2(struct ctdb_context *ctdb,
			  struct ctdb_ipflags *ipflags,
			  struct ctdb_public_ip_list *all_ips,
			  uint32_t *force_rebalance_nodes)
{
	uint32_t *lcp2_imbalances;
	bool *rebalance_candidates;
	int numnodes, num_rebalance_candidates, i;

	TALLOC_CTX *tmp_ctx = talloc_new(ctdb);

	unassign_unsuitable_ips(ctdb, ipflags, all_ips);

	lcp2_init(tmp_ctx, ipflags, all_ips,force_rebalance_nodes,
		  &lcp2_imbalances, &rebalance_candidates);

	lcp2_allocate_unassigned(ctdb, ipflags, all_ips, lcp2_imbalances);

	/* If we don't want IPs to fail back then don't rebalance IPs. */
	if (1 == ctdb->tunable.no_ip_failback) {
		goto finished;
	}

	/* It is only worth continuing if we have suitable target
	 * nodes to transfer IPs to.  This check is much cheaper than
	 * continuing on...
	 */
	numnodes = talloc_array_length(ipflags);
	num_rebalance_candidates = 0;
	for (i=0; i<numnodes; i++) {
		if (rebalance_candidates[i]) {
			num_rebalance_candidates++;
		}
	}
	if (num_rebalance_candidates == 0) {
		goto finished;
	}

	/* Now, try to make sure the ip adresses are evenly distributed
	   across the nodes.
	*/
	lcp2_failback(ctdb, ipflags, all_ips,
		      lcp2_imbalances, rebalance_candidates);

finished:
	talloc_free(tmp_ctx);
}

static bool all_nodes_are_disabled(struct ctdb_node_map *nodemap)
{
	int i;

	for (i=0;i<nodemap->num;i++) {
		if (!(nodemap->nodes[i].flags & (NODE_FLAGS_INACTIVE|NODE_FLAGS_DISABLED))) {
			/* Found one completely healthy node */
			return false;
		}
	}

	return true;
}

/* The calculation part of the IP allocation algorithm. */
static void ctdb_takeover_run_core(struct ctdb_context *ctdb,
				   struct ctdb_ipflags *ipflags,
				   struct ctdb_public_ip_list **all_ips_p,
				   uint32_t *force_rebalance_nodes)
{
	/* since nodes only know about those public addresses that
	   can be served by that particular node, no single node has
	   a full list of all public addresses that exist in the cluster.
	   Walk over all node structures and create a merged list of
	   all public addresses that exist in the cluster.

	   keep the tree of ips around as ctdb->ip_tree
	*/
	*all_ips_p = create_merged_ip_list(ctdb);

        if (1 == ctdb->tunable.lcp2_public_ip_assignment) {
		ip_alloc_lcp2(ctdb, ipflags, *all_ips_p, force_rebalance_nodes);
	} else if (1 == ctdb->tunable.deterministic_public_ips) {
		ip_alloc_deterministic_ips(ctdb, ipflags, *all_ips_p);
	} else {
		ip_alloc_nondeterministic_ips(ctdb, ipflags, *all_ips_p);
	}

	/* at this point ->pnn is the node which will own each IP
	   or -1 if there is no node that can cover this ip
	*/

	return;
}

struct get_tunable_callback_data {
	const char *tunable;
	uint32_t *out;
	bool fatal;
};

static void get_tunable_callback(struct ctdb_context *ctdb, uint32_t pnn,
				 int32_t res, TDB_DATA outdata,
				 void *callback)
{
	struct get_tunable_callback_data *cd =
		(struct get_tunable_callback_data *)callback;
	int size;

	if (res != 0) {
		/* Already handled in fail callback */
		return;
	}

	if (outdata.dsize != sizeof(uint32_t)) {
		DEBUG(DEBUG_ERR,("Wrong size of returned data when reading \"%s\" tunable from node %d. Expected %d bytes but received %d bytes\n",
				 cd->tunable, pnn, (int)sizeof(uint32_t),
				 (int)outdata.dsize));
		cd->fatal = true;
		return;
	}

	size = talloc_array_length(cd->out);
	if (pnn >= size) {
		DEBUG(DEBUG_ERR,("Got %s reply from node %d but nodemap only has %d entries\n",
				 cd->tunable, pnn, size));
		return;
	}

		
	cd->out[pnn] = *(uint32_t *)outdata.dptr;
}

static void get_tunable_fail_callback(struct ctdb_context *ctdb, uint32_t pnn,
				       int32_t res, TDB_DATA outdata,
				       void *callback)
{
	struct get_tunable_callback_data *cd =
		(struct get_tunable_callback_data *)callback;

	switch (res) {
	case -ETIME:
		DEBUG(DEBUG_ERR,
		      ("Timed out getting tunable \"%s\" from node %d\n",
		       cd->tunable, pnn));
		cd->fatal = true;
		break;
	case -EINVAL:
	case -1:
		DEBUG(DEBUG_WARNING,
		      ("Tunable \"%s\" not implemented on node %d\n",
		       cd->tunable, pnn));
		break;
	default:
		DEBUG(DEBUG_ERR,
		      ("Unexpected error getting tunable \"%s\" from node %d\n",
		       cd->tunable, pnn));
		cd->fatal = true;
	}
}

static uint32_t *get_tunable_from_nodes(struct ctdb_context *ctdb,
					TALLOC_CTX *tmp_ctx,
					struct ctdb_node_map *nodemap,
					const char *tunable,
					uint32_t default_value)
{
	TDB_DATA data;
	struct ctdb_control_get_tunable *t;
	uint32_t *nodes;
	uint32_t *tvals;
	struct get_tunable_callback_data callback_data;
	int i;

	tvals = talloc_array(tmp_ctx, uint32_t, nodemap->num);
	CTDB_NO_MEMORY_NULL(ctdb, tvals);
	for (i=0; i<nodemap->num; i++) {
		tvals[i] = default_value;
	}
		
	callback_data.out = tvals;
	callback_data.tunable = tunable;
	callback_data.fatal = false;

	data.dsize = offsetof(struct ctdb_control_get_tunable, name) + strlen(tunable) + 1;
	data.dptr  = talloc_size(tmp_ctx, data.dsize);
	t = (struct ctdb_control_get_tunable *)data.dptr;
	t->length = strlen(tunable)+1;
	memcpy(t->name, tunable, t->length);
	nodes = list_of_connected_nodes(ctdb, nodemap, tmp_ctx, true);
	if (ctdb_client_async_control(ctdb, CTDB_CONTROL_GET_TUNABLE,
				      nodes, 0, TAKEOVER_TIMEOUT(),
				      false, data,
				      get_tunable_callback,
				      get_tunable_fail_callback,
				      &callback_data) != 0) {
		if (callback_data.fatal) {
			talloc_free(tvals);
			tvals = NULL;
		}
	}
	talloc_free(nodes);
	talloc_free(data.dptr);

	return tvals;
}

struct get_runstate_callback_data {
	enum ctdb_runstate *out;
	bool fatal;
};

static void get_runstate_callback(struct ctdb_context *ctdb, uint32_t pnn,
				  int32_t res, TDB_DATA outdata,
				  void *callback_data)
{
	struct get_runstate_callback_data *cd =
		(struct get_runstate_callback_data *)callback_data;
	int size;

	if (res != 0) {
		/* Already handled in fail callback */
		return;
	}

	if (outdata.dsize != sizeof(uint32_t)) {
		DEBUG(DEBUG_ERR,("Wrong size of returned data when getting runstate from node %d. Expected %d bytes but received %d bytes\n",
				 pnn, (int)sizeof(uint32_t),
				 (int)outdata.dsize));
		cd->fatal = true;
		return;
	}

	size = talloc_array_length(cd->out);
	if (pnn >= size) {
		DEBUG(DEBUG_ERR,("Got reply from node %d but nodemap only has %d entries\n",
				 pnn, size));
		return;
	}

	cd->out[pnn] = (enum ctdb_runstate)*(uint32_t *)outdata.dptr;
}

static void get_runstate_fail_callback(struct ctdb_context *ctdb, uint32_t pnn,
				       int32_t res, TDB_DATA outdata,
				       void *callback)
{
	struct get_runstate_callback_data *cd =
		(struct get_runstate_callback_data *)callback;

	switch (res) {
	case -ETIME:
		DEBUG(DEBUG_ERR,
		      ("Timed out getting runstate from node %d\n", pnn));
		cd->fatal = true;
		break;
	default:
		DEBUG(DEBUG_WARNING,
		      ("Error getting runstate from node %d - assuming runstates not supported\n",
		       pnn));
	}
}

static enum ctdb_runstate * get_runstate_from_nodes(struct ctdb_context *ctdb,
						    TALLOC_CTX *tmp_ctx,
						    struct ctdb_node_map *nodemap,
						    enum ctdb_runstate default_value)
{
	uint32_t *nodes;
	enum ctdb_runstate *rs;
	struct get_runstate_callback_data callback_data;
	int i;

	rs = talloc_array(tmp_ctx, enum ctdb_runstate, nodemap->num);
	CTDB_NO_MEMORY_NULL(ctdb, rs);
	for (i=0; i<nodemap->num; i++) {
		rs[i] = default_value;
	}

	callback_data.out = rs;
	callback_data.fatal = false;

	nodes = list_of_connected_nodes(ctdb, nodemap, tmp_ctx, true);
	if (ctdb_client_async_control(ctdb, CTDB_CONTROL_GET_RUNSTATE,
				      nodes, 0, TAKEOVER_TIMEOUT(),
				      true, tdb_null,
				      get_runstate_callback,
				      get_runstate_fail_callback,
				      &callback_data) != 0) {
		if (callback_data.fatal) {
			free(rs);
			rs = NULL;
		}
	}
	talloc_free(nodes);

	return rs;
}

/* Set internal flags for IP allocation:
 *   Clear ip flags
 *   Set NOIPTAKOVER ip flags from per-node NoIPTakeover tunable
 *   Set NOIPHOST ip flag for each INACTIVE node
 *   if all nodes are disabled:
 *     Set NOIPHOST ip flags from per-node NoIPHostOnAllDisabled tunable
 *   else
 *     Set NOIPHOST ip flags for disabled nodes
 */
static struct ctdb_ipflags *
set_ipflags_internal(struct ctdb_context *ctdb,
		     TALLOC_CTX *tmp_ctx,
		     struct ctdb_node_map *nodemap,
		     uint32_t *tval_noiptakeover,
		     uint32_t *tval_noiphostonalldisabled,
		     enum ctdb_runstate *runstate)
{
	int i;
	struct ctdb_ipflags *ipflags;

	/* Clear IP flags - implicit due to talloc_zero */
	ipflags = talloc_zero_array(tmp_ctx, struct ctdb_ipflags, nodemap->num);
	CTDB_NO_MEMORY_NULL(ctdb, ipflags);

	for (i=0;i<nodemap->num;i++) {
		/* Can not take IPs on node with NoIPTakeover set */
		if (tval_noiptakeover[i] != 0) {
			ipflags[i].noiptakeover = true;
		}

		/* Can not host IPs on node not in RUNNING state */
		if (runstate[i] != CTDB_RUNSTATE_RUNNING) {
			ipflags[i].noiphost = true;
			continue;
		}
		/* Can not host IPs on INACTIVE node */
		if (nodemap->nodes[i].flags & NODE_FLAGS_INACTIVE) {
			ipflags[i].noiphost = true;
		}
	}

	if (all_nodes_are_disabled(nodemap)) {
		/* If all nodes are disabled, can not host IPs on node
		 * with NoIPHostOnAllDisabled set
		 */
		for (i=0;i<nodemap->num;i++) {
			if (tval_noiphostonalldisabled[i] != 0) {
				ipflags[i].noiphost = true;
			}
		}
	} else {
		/* If some nodes are not disabled, then can not host
		 * IPs on DISABLED node
		 */
		for (i=0;i<nodemap->num;i++) {
			if (nodemap->nodes[i].flags & NODE_FLAGS_DISABLED) {
				ipflags[i].noiphost = true;
			}
		}
	}

	return ipflags;
}

static struct ctdb_ipflags *set_ipflags(struct ctdb_context *ctdb,
					TALLOC_CTX *tmp_ctx,
					struct ctdb_node_map *nodemap)
{
	uint32_t *tval_noiptakeover;
	uint32_t *tval_noiphostonalldisabled;
	struct ctdb_ipflags *ipflags;
	enum ctdb_runstate *runstate;


	tval_noiptakeover = get_tunable_from_nodes(ctdb, tmp_ctx, nodemap,
						   "NoIPTakeover", 0);
	if (tval_noiptakeover == NULL) {
		return NULL;
	}

	tval_noiphostonalldisabled =
		get_tunable_from_nodes(ctdb, tmp_ctx, nodemap,
				       "NoIPHostOnAllDisabled", 0);
	if (tval_noiphostonalldisabled == NULL) {
		/* Caller frees tmp_ctx */
		return NULL;
	}

	/* Any nodes where CTDB_CONTROL_GET_RUNSTATE is not supported
	 * will default to CTDB_RUNSTATE_RUNNING.  This ensures
	 * reasonable behaviour on a mixed cluster during upgrade.
	 */
	runstate = get_runstate_from_nodes(ctdb, tmp_ctx, nodemap,
					   CTDB_RUNSTATE_RUNNING);
	if (runstate == NULL) {
		/* Caller frees tmp_ctx */
		return NULL;
	}

	ipflags = set_ipflags_internal(ctdb, tmp_ctx, nodemap,
				       tval_noiptakeover,
				       tval_noiphostonalldisabled,
				       runstate);

	talloc_free(tval_noiptakeover);
	talloc_free(tval_noiphostonalldisabled);
	talloc_free(runstate);

	return ipflags;
}

struct iprealloc_callback_data {
	bool *retry_nodes;
	int retry_count;
	client_async_callback fail_callback;
	void *fail_callback_data;
	struct ctdb_node_map *nodemap;
};

static void iprealloc_fail_callback(struct ctdb_context *ctdb, uint32_t pnn,
					int32_t res, TDB_DATA outdata,
					void *callback)
{
	int numnodes;
	struct iprealloc_callback_data *cd =
		(struct iprealloc_callback_data *)callback;

	numnodes = talloc_array_length(cd->retry_nodes);
	if (pnn > numnodes) {
		DEBUG(DEBUG_ERR,
		      ("ipreallocated failure from node %d, "
		       "but only %d nodes in nodemap\n",
		       pnn, numnodes));
		return;
	}

	/* Can't run the "ipreallocated" event on a INACTIVE node */
	if (cd->nodemap->nodes[pnn].flags & NODE_FLAGS_INACTIVE) {
		DEBUG(DEBUG_WARNING,
		      ("ipreallocated failed on inactive node %d, ignoring\n",
		       pnn));
		return;
	}

	switch (res) {
	case -ETIME:
		/* If the control timed out then that's a real error,
		 * so call the real fail callback
		 */
		if (cd->fail_callback) {
			cd->fail_callback(ctdb, pnn, res, outdata,
					  cd->fail_callback_data);
		} else {
			DEBUG(DEBUG_WARNING,
			      ("iprealloc timed out but no callback registered\n"));
		}
		break;
	default:
		/* If not a timeout then either the ipreallocated
		 * eventscript (or some setup) failed.  This might
		 * have failed because the IPREALLOCATED control isn't
		 * implemented - right now there is no way of knowing
		 * because the error codes are all folded down to -1.
		 * Consider retrying using EVENTSCRIPT control...
		 */
		DEBUG(DEBUG_WARNING,
		      ("ipreallocated failure from node %d, flagging retry\n",
		       pnn));
		cd->retry_nodes[pnn] = true;
		cd->retry_count++;
	}
}

struct takeover_callback_data {
	bool *node_failed;
	client_async_callback fail_callback;
	void *fail_callback_data;
	struct ctdb_node_map *nodemap;
};

static void takeover_run_fail_callback(struct ctdb_context *ctdb,
				       uint32_t node_pnn, int32_t res,
				       TDB_DATA outdata, void *callback_data)
{
	struct takeover_callback_data *cd =
		talloc_get_type_abort(callback_data,
				      struct takeover_callback_data);
	int i;

	for (i = 0; i < cd->nodemap->num; i++) {
		if (node_pnn == cd->nodemap->nodes[i].pnn) {
			break;
		}
	}

	if (i == cd->nodemap->num) {
		DEBUG(DEBUG_ERR, (__location__ " invalid PNN %u\n", node_pnn));
		return;
	}

	if (!cd->node_failed[i]) {
		cd->node_failed[i] = true;
		cd->fail_callback(ctdb, node_pnn, res, outdata,
				  cd->fail_callback_data);
	}
}

/*
  make any IP alias changes for public addresses that are necessary 
 */
int ctdb_takeover_run(struct ctdb_context *ctdb, struct ctdb_node_map *nodemap,
		      uint32_t *force_rebalance_nodes,
		      client_async_callback fail_callback, void *callback_data)
{
	int i, j, ret;
	struct ctdb_public_ip ip;
	struct ctdb_public_ipv4 ipv4;
	uint32_t *nodes;
	struct ctdb_public_ip_list *all_ips, *tmp_ip;
	TDB_DATA data;
	struct timeval timeout;
	struct client_async_data *async_data;
	struct ctdb_client_control_state *state;
	TALLOC_CTX *tmp_ctx = talloc_new(ctdb);
	struct ctdb_ipflags *ipflags;
	struct takeover_callback_data *takeover_data;
	struct iprealloc_callback_data iprealloc_data;
	bool *retry_data;

	/*
	 * ip failover is completely disabled, just send out the 
	 * ipreallocated event.
	 */
	if (ctdb->tunable.disable_ip_failover != 0) {
		goto ipreallocated;
	}

	ipflags = set_ipflags(ctdb, tmp_ctx, nodemap);
	if (ipflags == NULL) {
		DEBUG(DEBUG_ERR,("Failed to set IP flags - aborting takeover run\n"));
		talloc_free(tmp_ctx);
		return -1;
	}

	/* Do the IP reassignment calculations */
	ctdb_takeover_run_core(ctdb, ipflags, &all_ips, force_rebalance_nodes);

	/* Now tell all nodes to release any public IPs should not
	 * host.  This will be a NOOP on nodes that don't currently
	 * hold the given IP.
	 */
	takeover_data = talloc_zero(tmp_ctx, struct takeover_callback_data);
	CTDB_NO_MEMORY_FATAL(ctdb, takeover_data);

	takeover_data->node_failed = talloc_zero_array(tmp_ctx,
						       bool, nodemap->num);
	CTDB_NO_MEMORY_FATAL(ctdb, takeover_data->node_failed);
	takeover_data->fail_callback = fail_callback;
	takeover_data->fail_callback_data = callback_data;
	takeover_data->nodemap = nodemap;

	async_data = talloc_zero(tmp_ctx, struct client_async_data);
	CTDB_NO_MEMORY_FATAL(ctdb, async_data);

	async_data->fail_callback = takeover_run_fail_callback;
	async_data->callback_data = takeover_data;

	ZERO_STRUCT(ip); /* Avoid valgrind warnings for union */

	/* Send a RELEASE_IP to all nodes that should not be hosting
	 * each IP.  For each IP, all but one of these will be
	 * redundant.  However, the redundant ones are used to tell
	 * nodes which node should be hosting the IP so that commands
	 * like "ctdb ip" can display a particular nodes idea of who
	 * is hosting what. */
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
			if (tmp_ip->addr.sa.sa_family == AF_INET) {
				ipv4.pnn = tmp_ip->pnn;
				ipv4.sin = tmp_ip->addr.ip;

				timeout = TAKEOVER_TIMEOUT();
				data.dsize = sizeof(ipv4);
				data.dptr  = (uint8_t *)&ipv4;
				state = ctdb_control_send(ctdb, nodemap->nodes[i].pnn,
						0, CTDB_CONTROL_RELEASE_IPv4, 0,
						data, async_data,
						&timeout, NULL);
			} else {
				ip.pnn  = tmp_ip->pnn;
				ip.addr = tmp_ip->addr;

				timeout = TAKEOVER_TIMEOUT();
				data.dsize = sizeof(ip);
				data.dptr  = (uint8_t *)&ip;
				state = ctdb_control_send(ctdb, nodemap->nodes[i].pnn,
						0, CTDB_CONTROL_RELEASE_IP, 0,
						data, async_data,
						&timeout, NULL);
			}

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


	/* For each IP, send a TAKOVER_IP to the node that should be
	 * hosting it.  Many of these will often be redundant (since
	 * the allocation won't have changed) but they can be useful
	 * to recover from inconsistencies. */
	async_data = talloc_zero(tmp_ctx, struct client_async_data);
	CTDB_NO_MEMORY_FATAL(ctdb, async_data);

	async_data->fail_callback = fail_callback;
	async_data->callback_data = callback_data;

	for (tmp_ip=all_ips;tmp_ip;tmp_ip=tmp_ip->next) {
		if (tmp_ip->pnn == -1) {
			/* this IP won't be taken over */
			continue;
		}

		if (tmp_ip->addr.sa.sa_family == AF_INET) {
			ipv4.pnn = tmp_ip->pnn;
			ipv4.sin = tmp_ip->addr.ip;

			timeout = TAKEOVER_TIMEOUT();
			data.dsize = sizeof(ipv4);
			data.dptr  = (uint8_t *)&ipv4;
			state = ctdb_control_send(ctdb, tmp_ip->pnn,
					0, CTDB_CONTROL_TAKEOVER_IPv4, 0,
					data, async_data,
					&timeout, NULL);
		} else {
			ip.pnn  = tmp_ip->pnn;
			ip.addr = tmp_ip->addr;

			timeout = TAKEOVER_TIMEOUT();
			data.dsize = sizeof(ip);
			data.dptr  = (uint8_t *)&ip;
			state = ctdb_control_send(ctdb, tmp_ip->pnn,
					0, CTDB_CONTROL_TAKEOVER_IP, 0,
					data, async_data,
					&timeout, NULL);
		}
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

ipreallocated:
	/* 
	 * Tell all nodes to run eventscripts to process the
	 * "ipreallocated" event.  This can do a lot of things,
	 * including restarting services to reconfigure them if public
	 * IPs have moved.  Once upon a time this event only used to
	 * update natwg.
	 */
	retry_data = talloc_zero_array(tmp_ctx, bool, nodemap->num);
	CTDB_NO_MEMORY_FATAL(ctdb, retry_data);
	iprealloc_data.retry_nodes = retry_data;
	iprealloc_data.retry_count = 0;
	iprealloc_data.fail_callback = fail_callback;
	iprealloc_data.fail_callback_data = callback_data;
	iprealloc_data.nodemap = nodemap;

	nodes = list_of_connected_nodes(ctdb, nodemap, tmp_ctx, true);
	ret = ctdb_client_async_control(ctdb, CTDB_CONTROL_IPREALLOCATED,
					nodes, 0, TAKEOVER_TIMEOUT(),
					false, tdb_null,
					NULL, iprealloc_fail_callback,
					&iprealloc_data);
	if (ret != 0) {
		/* If the control failed then we should retry to any
		 * nodes flagged by iprealloc_fail_callback using the
		 * EVENTSCRIPT control.  This is a best-effort at
		 * backward compatiblity when running a mixed cluster
		 * where some nodes have not yet been upgraded to
		 * support the IPREALLOCATED control.
		 */
		DEBUG(DEBUG_WARNING,
		      ("Retry ipreallocated to some nodes using eventscript control\n"));

		nodes = talloc_array(tmp_ctx, uint32_t,
				     iprealloc_data.retry_count);
		CTDB_NO_MEMORY_FATAL(ctdb, nodes);

		j = 0;
		for (i=0; i<nodemap->num; i++) {
			if (iprealloc_data.retry_nodes[i]) {
				nodes[j] = i;
				j++;
			}
		}

		data.dptr  = discard_const("ipreallocated");
		data.dsize = strlen((char *)data.dptr) + 1; 
		ret = ctdb_client_async_control(ctdb,
						CTDB_CONTROL_RUN_EVENTSCRIPTS,
						nodes, 0, TAKEOVER_TIMEOUT(),
						false, data,
						NULL, fail_callback,
						callback_data);
		if (ret != 0) {
			DEBUG(DEBUG_ERR, (__location__ " failed to send control to run eventscripts with \"ipreallocated\"\n"));
		}
	}

	talloc_free(tmp_ctx);
	return ret;
}


/*
  destroy a ctdb_client_ip structure
 */
static int ctdb_client_ip_destructor(struct ctdb_client_ip *ip)
{
	DEBUG(DEBUG_DEBUG,("destroying client tcp for %s:%u (client_id %u)\n",
		ctdb_addr_to_str(&ip->addr),
		ntohs(ip->addr.ip.sin_port),
		ip->client_id));

	DLIST_REMOVE(ip->ctdb->client_ip_list, ip);
	return 0;
}

/*
  called by a client to inform us of a TCP connection that it is managing
  that should tickled with an ACK when IP takeover is done
  we handle both the old ipv4 style of packets as well as the new ipv4/6
  pdus.
 */
int32_t ctdb_control_tcp_client(struct ctdb_context *ctdb, uint32_t client_id,
				TDB_DATA indata)
{
	struct ctdb_client *client = ctdb_reqid_find(ctdb, client_id, struct ctdb_client);
	struct ctdb_control_tcp *old_addr = NULL;
	struct ctdb_control_tcp_addr new_addr;
	struct ctdb_control_tcp_addr *tcp_sock = NULL;
	struct ctdb_tcp_list *tcp;
	struct ctdb_tcp_connection t;
	int ret;
	TDB_DATA data;
	struct ctdb_client_ip *ip;
	struct ctdb_vnn *vnn;
	ctdb_sock_addr addr;

	/* If we don't have public IPs, tickles are useless */
	if (ctdb->vnn == NULL) {
		return 0;
	}

	switch (indata.dsize) {
	case sizeof(struct ctdb_control_tcp):
		old_addr = (struct ctdb_control_tcp *)indata.dptr;
		ZERO_STRUCT(new_addr);
		tcp_sock = &new_addr;
		tcp_sock->src.ip  = old_addr->src;
		tcp_sock->dest.ip = old_addr->dest;
		break;
	case sizeof(struct ctdb_control_tcp_addr):
		tcp_sock = (struct ctdb_control_tcp_addr *)indata.dptr;
		break;
	default:
		DEBUG(DEBUG_ERR,(__location__ " Invalid data structure passed "
				 "to ctdb_control_tcp_client. size was %d but "
				 "only allowed sizes are %lu and %lu\n",
				 (int)indata.dsize,
				 (long unsigned)sizeof(struct ctdb_control_tcp),
				 (long unsigned)sizeof(struct ctdb_control_tcp_addr)));
		return -1;
	}

	addr = tcp_sock->src;
	ctdb_canonicalize_ip(&addr,  &tcp_sock->src);
	addr = tcp_sock->dest;
	ctdb_canonicalize_ip(&addr, &tcp_sock->dest);

	ZERO_STRUCT(addr);
	memcpy(&addr, &tcp_sock->dest, sizeof(addr));
	vnn = find_public_ip_vnn(ctdb, &addr);
	if (vnn == NULL) {
		switch (addr.sa.sa_family) {
		case AF_INET:
			if (ntohl(addr.ip.sin_addr.s_addr) != INADDR_LOOPBACK) {
				DEBUG(DEBUG_ERR,("Could not add client IP %s. This is not a public address.\n", 
					ctdb_addr_to_str(&addr)));
			}
			break;
		case AF_INET6:
			DEBUG(DEBUG_ERR,("Could not add client IP %s. This is not a public ipv6 address.\n", 
				ctdb_addr_to_str(&addr)));
			break;
		default:
			DEBUG(DEBUG_ERR,(__location__ " Unknown family type %d\n", addr.sa.sa_family));
		}

		return 0;
	}

	if (vnn->pnn != ctdb->pnn) {
		DEBUG(DEBUG_ERR,("Attempt to register tcp client for IP %s we don't hold - failing (client_id %u pid %u)\n",
			ctdb_addr_to_str(&addr),
			client_id, client->pid));
		/* failing this call will tell smbd to die */
		return -1;
	}

	ip = talloc(client, struct ctdb_client_ip);
	CTDB_NO_MEMORY(ctdb, ip);

	ip->ctdb      = ctdb;
	ip->addr      = addr;
	ip->client_id = client_id;
	talloc_set_destructor(ip, ctdb_client_ip_destructor);
	DLIST_ADD(ctdb->client_ip_list, ip);

	tcp = talloc(client, struct ctdb_tcp_list);
	CTDB_NO_MEMORY(ctdb, tcp);

	tcp->connection.src_addr = tcp_sock->src;
	tcp->connection.dst_addr = tcp_sock->dest;

	DLIST_ADD(client->tcp_list, tcp);

	t.src_addr = tcp_sock->src;
	t.dst_addr = tcp_sock->dest;

	data.dptr = (uint8_t *)&t;
	data.dsize = sizeof(t);

	switch (addr.sa.sa_family) {
	case AF_INET:
		DEBUG(DEBUG_INFO,("registered tcp client for %u->%s:%u (client_id %u pid %u)\n",
			(unsigned)ntohs(tcp_sock->dest.ip.sin_port), 
			ctdb_addr_to_str(&tcp_sock->src),
			(unsigned)ntohs(tcp_sock->src.ip.sin_port), client_id, client->pid));
		break;
	case AF_INET6:
		DEBUG(DEBUG_INFO,("registered tcp client for %u->%s:%u (client_id %u pid %u)\n",
			(unsigned)ntohs(tcp_sock->dest.ip6.sin6_port), 
			ctdb_addr_to_str(&tcp_sock->src),
			(unsigned)ntohs(tcp_sock->src.ip6.sin6_port), client_id, client->pid));
		break;
	default:
		DEBUG(DEBUG_ERR,(__location__ " Unknown family %d\n", addr.sa.sa_family));
	}


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
		if (ctdb_same_sockaddr(&array->connections[i].src_addr, &tcp->src_addr) &&
		    ctdb_same_sockaddr(&array->connections[i].dst_addr, &tcp->dst_addr)) {
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
int32_t ctdb_control_tcp_add(struct ctdb_context *ctdb, TDB_DATA indata, bool tcp_update_needed)
{
	struct ctdb_tcp_connection *p = (struct ctdb_tcp_connection *)indata.dptr;
	struct ctdb_tcp_array *tcparray;
	struct ctdb_tcp_connection tcp;
	struct ctdb_vnn *vnn;

	/* If we don't have public IPs, tickles are useless */
	if (ctdb->vnn == NULL) {
		return 0;
	}

	vnn = find_public_ip_vnn(ctdb, &p->dst_addr);
	if (vnn == NULL) {
		DEBUG(DEBUG_INFO,(__location__ " got TCP_ADD control for an address which is not a public address '%s'\n",
			ctdb_addr_to_str(&p->dst_addr)));

		return -1;
	}


	tcparray = vnn->tcp_array;

	/* If this is the first tickle */
	if (tcparray == NULL) {
		tcparray = talloc(vnn, struct ctdb_tcp_array);
		CTDB_NO_MEMORY(ctdb, tcparray);
		vnn->tcp_array = tcparray;

		tcparray->num = 0;
		tcparray->connections = talloc_size(tcparray, sizeof(struct ctdb_tcp_connection));
		CTDB_NO_MEMORY(ctdb, tcparray->connections);

		tcparray->connections[tcparray->num].src_addr = p->src_addr;
		tcparray->connections[tcparray->num].dst_addr = p->dst_addr;
		tcparray->num++;

		if (tcp_update_needed) {
			vnn->tcp_update_needed = true;
		}
		return 0;
	}


	/* Do we already have this tickle ?*/
	tcp.src_addr = p->src_addr;
	tcp.dst_addr = p->dst_addr;
	if (ctdb_tcp_find(tcparray, &tcp) != NULL) {
		DEBUG(DEBUG_DEBUG,("Already had tickle info for %s:%u for vnn:%u\n",
			ctdb_addr_to_str(&tcp.dst_addr),
			ntohs(tcp.dst_addr.ip.sin_port),
			vnn->pnn));
		return 0;
	}

	/* A new tickle, we must add it to the array */
	tcparray->connections = talloc_realloc(tcparray, tcparray->connections,
					struct ctdb_tcp_connection,
					tcparray->num+1);
	CTDB_NO_MEMORY(ctdb, tcparray->connections);

	tcparray->connections[tcparray->num].src_addr = p->src_addr;
	tcparray->connections[tcparray->num].dst_addr = p->dst_addr;
	tcparray->num++;

	DEBUG(DEBUG_INFO,("Added tickle info for %s:%u from vnn %u\n",
		ctdb_addr_to_str(&tcp.dst_addr),
		ntohs(tcp.dst_addr.ip.sin_port),
		vnn->pnn));

	if (tcp_update_needed) {
		vnn->tcp_update_needed = true;
	}

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
	struct ctdb_vnn *vnn = find_public_ip_vnn(ctdb, &conn->dst_addr);

	if (vnn == NULL) {
		DEBUG(DEBUG_ERR,(__location__ " unable to find public address %s\n",
			ctdb_addr_to_str(&conn->dst_addr)));
		return;
	}

	/* if the array is empty we cant remove it
	   and we dont need to do anything
	 */
	if (vnn->tcp_array == NULL) {
		DEBUG(DEBUG_INFO,("Trying to remove tickle that doesnt exist (array is empty) %s:%u\n",
			ctdb_addr_to_str(&conn->dst_addr),
			ntohs(conn->dst_addr.ip.sin_port)));
		return;
	}


	/* See if we know this connection
	   if we dont know this connection  then we dont need to do anything
	 */
	tcpp = ctdb_tcp_find(vnn->tcp_array, conn);
	if (tcpp == NULL) {
		DEBUG(DEBUG_INFO,("Trying to remove tickle that doesnt exist %s:%u\n",
			ctdb_addr_to_str(&conn->dst_addr),
			ntohs(conn->dst_addr.ip.sin_port)));
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
		ctdb_addr_to_str(&conn->src_addr),
		ntohs(conn->src_addr.ip.sin_port)));
}


/*
  called by a daemon to inform us of a TCP connection that one of its
  clients used are no longer needed in the tickle database
 */
int32_t ctdb_control_tcp_remove(struct ctdb_context *ctdb, TDB_DATA indata)
{
	struct ctdb_tcp_connection *conn = (struct ctdb_tcp_connection *)indata.dptr;

	/* If we don't have public IPs, tickles are useless */
	if (ctdb->vnn == NULL) {
		return 0;
	}

	ctdb_remove_tcp_connection(ctdb, conn);

	return 0;
}


/*
  Called when another daemon starts - causes all tickles for all
  public addresses we are serving to be sent to the new node on the
  next check.  This actually causes the next scheduled call to
  tdb_update_tcp_tickles() to update all nodes.  This is simple and
  doesn't require careful error handling.
 */
int32_t ctdb_control_startup(struct ctdb_context *ctdb, uint32_t pnn)
{
	struct ctdb_vnn *vnn;

	DEBUG(DEBUG_INFO, ("Received startup control from node %lu\n",
			   (unsigned long) pnn));

	for (vnn = ctdb->vnn; vnn != NULL; vnn = vnn->next) {
		vnn->tcp_update_needed = true;
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
	int count = 0;

	for (vnn=ctdb->vnn;vnn;vnn=vnn->next) {
		if (!ctdb_sys_have_ip(&vnn->public_address)) {
			ctdb_vnn_unassign_iface(ctdb, vnn);
			continue;
		}
		if (!vnn->iface) {
			continue;
		}

		DEBUG(DEBUG_INFO,("Release of IP %s/%u on interface %s node:-1\n",
				    ctdb_addr_to_str(&vnn->public_address),
				    vnn->public_netmask_bits,
				    ctdb_vnn_iface_string(vnn)));

		ctdb_event_script_args(ctdb, CTDB_EVENT_RELEASE_IP, "%s %s %u",
				  ctdb_vnn_iface_string(vnn),
				  ctdb_addr_to_str(&vnn->public_address),
				  vnn->public_netmask_bits);
		release_kill_clients(ctdb, &vnn->public_address);
		ctdb_vnn_unassign_iface(ctdb, vnn);
		count++;
	}

	DEBUG(DEBUG_NOTICE,(__location__ " Released %d public IPs\n", count));
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
	bool only_available = false;

	if (c->flags & CTDB_PUBLIC_IP_FLAGS_ONLY_AVAILABLE) {
		only_available = true;
	}

	/* count how many public ip structures we have */
	num = 0;
	for (vnn=ctdb->vnn;vnn;vnn=vnn->next) {
		num++;
	}

	len = offsetof(struct ctdb_all_public_ips, ips) + 
		num*sizeof(struct ctdb_public_ip);
	ips = talloc_zero_size(outdata, len);
	CTDB_NO_MEMORY(ctdb, ips);

	i = 0;
	for (vnn=ctdb->vnn;vnn;vnn=vnn->next) {
		if (only_available && !ctdb_vnn_available(ctdb, vnn)) {
			continue;
		}
		ips->ips[i].pnn  = vnn->pnn;
		ips->ips[i].addr = vnn->public_address;
		i++;
	}
	ips->num = i;
	len = offsetof(struct ctdb_all_public_ips, ips) +
		i*sizeof(struct ctdb_public_ip);

	outdata->dsize = len;
	outdata->dptr  = (uint8_t *)ips;

	return 0;
}


/*
  get list of public IPs, old ipv4 style.  only returns ipv4 addresses
 */
int32_t ctdb_control_get_public_ipsv4(struct ctdb_context *ctdb, 
				    struct ctdb_req_control *c, TDB_DATA *outdata)
{
	int i, num, len;
	struct ctdb_all_public_ipsv4 *ips;
	struct ctdb_vnn *vnn;

	/* count how many public ip structures we have */
	num = 0;
	for (vnn=ctdb->vnn;vnn;vnn=vnn->next) {
		if (vnn->public_address.sa.sa_family != AF_INET) {
			continue;
		}
		num++;
	}

	len = offsetof(struct ctdb_all_public_ipsv4, ips) + 
		num*sizeof(struct ctdb_public_ipv4);
	ips = talloc_zero_size(outdata, len);
	CTDB_NO_MEMORY(ctdb, ips);

	outdata->dsize = len;
	outdata->dptr  = (uint8_t *)ips;

	ips->num = num;
	i = 0;
	for (vnn=ctdb->vnn;vnn;vnn=vnn->next) {
		if (vnn->public_address.sa.sa_family != AF_INET) {
			continue;
		}
		ips->ips[i].pnn = vnn->pnn;
		ips->ips[i].sin = vnn->public_address.ip;
		i++;
	}

	return 0;
}

int32_t ctdb_control_get_public_ip_info(struct ctdb_context *ctdb,
					struct ctdb_req_control *c,
					TDB_DATA indata,
					TDB_DATA *outdata)
{
	int i, num, len;
	ctdb_sock_addr *addr;
	struct ctdb_control_public_ip_info *info;
	struct ctdb_vnn *vnn;

	addr = (ctdb_sock_addr *)indata.dptr;

	vnn = find_public_ip_vnn(ctdb, addr);
	if (vnn == NULL) {
		/* if it is not a public ip   it could be our 'single ip' */
		if (ctdb->single_ip_vnn) {
			if (ctdb_same_ip(&ctdb->single_ip_vnn->public_address, addr)) {
				vnn = ctdb->single_ip_vnn;
			}
		}
	}
	if (vnn == NULL) {
		DEBUG(DEBUG_ERR,(__location__ " Could not get public ip info, "
				 "'%s'not a public address\n",
				 ctdb_addr_to_str(addr)));
		return -1;
	}

	/* count how many public ip structures we have */
	num = 0;
	for (;vnn->ifaces[num];) {
		num++;
	}

	len = offsetof(struct ctdb_control_public_ip_info, ifaces) +
		num*sizeof(struct ctdb_control_iface_info);
	info = talloc_zero_size(outdata, len);
	CTDB_NO_MEMORY(ctdb, info);

	info->ip.addr = vnn->public_address;
	info->ip.pnn = vnn->pnn;
	info->active_idx = 0xFFFFFFFF;

	for (i=0; vnn->ifaces[i]; i++) {
		struct ctdb_iface *cur;

		cur = ctdb_find_iface(ctdb, vnn->ifaces[i]);
		if (cur == NULL) {
			DEBUG(DEBUG_CRIT, (__location__ " internal error iface[%s] unknown\n",
					   vnn->ifaces[i]));
			return -1;
		}
		if (vnn->iface == cur) {
			info->active_idx = i;
		}
		strncpy(info->ifaces[i].name, cur->name, sizeof(info->ifaces[i].name)-1);
		info->ifaces[i].link_state = cur->link_up;
		info->ifaces[i].references = cur->references;
	}
	info->num = i;
	len = offsetof(struct ctdb_control_public_ip_info, ifaces) +
		i*sizeof(struct ctdb_control_iface_info);

	outdata->dsize = len;
	outdata->dptr  = (uint8_t *)info;

	return 0;
}

int32_t ctdb_control_get_ifaces(struct ctdb_context *ctdb,
				struct ctdb_req_control *c,
				TDB_DATA *outdata)
{
	int i, num, len;
	struct ctdb_control_get_ifaces *ifaces;
	struct ctdb_iface *cur;

	/* count how many public ip structures we have */
	num = 0;
	for (cur=ctdb->ifaces;cur;cur=cur->next) {
		num++;
	}

	len = offsetof(struct ctdb_control_get_ifaces, ifaces) +
		num*sizeof(struct ctdb_control_iface_info);
	ifaces = talloc_zero_size(outdata, len);
	CTDB_NO_MEMORY(ctdb, ifaces);

	i = 0;
	for (cur=ctdb->ifaces;cur;cur=cur->next) {
		strcpy(ifaces->ifaces[i].name, cur->name);
		ifaces->ifaces[i].link_state = cur->link_up;
		ifaces->ifaces[i].references = cur->references;
		i++;
	}
	ifaces->num = i;
	len = offsetof(struct ctdb_control_get_ifaces, ifaces) +
		i*sizeof(struct ctdb_control_iface_info);

	outdata->dsize = len;
	outdata->dptr  = (uint8_t *)ifaces;

	return 0;
}

int32_t ctdb_control_set_iface_link(struct ctdb_context *ctdb,
				    struct ctdb_req_control *c,
				    TDB_DATA indata)
{
	struct ctdb_control_iface_info *info;
	struct ctdb_iface *iface;
	bool link_up = false;

	info = (struct ctdb_control_iface_info *)indata.dptr;

	if (info->name[CTDB_IFACE_SIZE] != '\0') {
		int len = strnlen(info->name, CTDB_IFACE_SIZE);
		DEBUG(DEBUG_ERR, (__location__ " name[%*.*s] not terminated\n",
				  len, len, info->name));
		return -1;
	}

	switch (info->link_state) {
	case 0:
		link_up = false;
		break;
	case 1:
		link_up = true;
		break;
	default:
		DEBUG(DEBUG_ERR, (__location__ " link_state[%u] invalid\n",
				  (unsigned int)info->link_state));
		return -1;
	}

	if (info->references != 0) {
		DEBUG(DEBUG_ERR, (__location__ " references[%u] should be 0\n",
				  (unsigned int)info->references));
		return -1;
	}

	iface = ctdb_find_iface(ctdb, info->name);
	if (iface == NULL) {
		return -1;
	}

	if (link_up == iface->link_up) {
		return 0;
	}

	DEBUG(iface->link_up?DEBUG_ERR:DEBUG_NOTICE,
	      ("iface[%s] has changed it's link status %s => %s\n",
	       iface->name,
	       iface->link_up?"up":"down",
	       link_up?"up":"down"));

	iface->link_up = link_up;
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
	struct fd_event *fde;
	trbt_tree_t *connections;
	void *private_data;
};

/*
  a tcp connection that is to be killed
 */
struct ctdb_killtcp_con {
	ctdb_sock_addr src_addr;
	ctdb_sock_addr dst_addr;
	int count;
	struct ctdb_kill_tcp *killtcp;
};

/* this function is used to create a key to represent this socketpair
   in the killtcp tree.
   this key is used to insert and lookup matching socketpairs that are
   to be tickled and RST
*/
#define KILLTCP_KEYLEN	10
static uint32_t *killtcp_key(ctdb_sock_addr *src, ctdb_sock_addr *dst)
{
	static uint32_t key[KILLTCP_KEYLEN];

	bzero(key, sizeof(key));

	if (src->sa.sa_family != dst->sa.sa_family) {
		DEBUG(DEBUG_ERR, (__location__ " ERROR, different families passed :%u vs %u\n", src->sa.sa_family, dst->sa.sa_family));
		return key;
	}
	
	switch (src->sa.sa_family) {
	case AF_INET:
		key[0]	= dst->ip.sin_addr.s_addr;
		key[1]	= src->ip.sin_addr.s_addr;
		key[2]	= dst->ip.sin_port;
		key[3]	= src->ip.sin_port;
		break;
	case AF_INET6: {
		uint32_t *dst6_addr32 =
			(uint32_t *)&(dst->ip6.sin6_addr.s6_addr);
		uint32_t *src6_addr32 =
			(uint32_t *)&(src->ip6.sin6_addr.s6_addr);
		key[0]	= dst6_addr32[3];
		key[1]	= src6_addr32[3];
		key[2]	= dst6_addr32[2];
		key[3]	= src6_addr32[2];
		key[4]	= dst6_addr32[1];
		key[5]	= src6_addr32[1];
		key[6]	= dst6_addr32[0];
		key[7]	= src6_addr32[0];
		key[8]	= dst->ip6.sin6_port;
		key[9]	= src->ip6.sin6_port;
		break;
	}
	default:
		DEBUG(DEBUG_ERR, (__location__ " ERROR, unknown family passed :%u\n", src->sa.sa_family));
		return key;
	}

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
	ctdb_sock_addr src, dst;
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
	DEBUG(DEBUG_INFO, ("sending a tcp reset to kill connection :%d -> %s:%d\n",
		ntohs(con->dst_addr.ip.sin_port),
		ctdb_addr_to_str(&con->src_addr),
		ntohs(con->src_addr.ip.sin_port)));

	ctdb_sys_send_tcp(&con->dst_addr, &con->src_addr, ack_seq, seq, 1);
	talloc_free(con);
}


/* when traversing the list of all tcp connections to send tickle acks to
   (so that we can capture the ack coming back and kill the connection
    by a RST)
   this callback is called for each connection we are currently trying to kill
*/
static int tickle_connection_traverse(void *param, void *data)
{
	struct ctdb_killtcp_con *con = talloc_get_type(data, struct ctdb_killtcp_con);

	/* have tried too many times, just give up */
	if (con->count >= 5) {
		/* can't delete in traverse: reparent to delete_cons */
		talloc_steal(param, con);
		return 0;
	}

	/* othervise, try tickling it again */
	con->count++;
	ctdb_sys_send_tcp(
		(ctdb_sock_addr *)&con->dst_addr,
		(ctdb_sock_addr *)&con->src_addr,
		0, 0, 0);
	return 0;
}


/* 
   called every second until all sentenced connections have been reset
 */
static void ctdb_tickle_sentenced_connections(struct event_context *ev, struct timed_event *te, 
					      struct timeval t, void *private_data)
{
	struct ctdb_kill_tcp *killtcp = talloc_get_type(private_data, struct ctdb_kill_tcp);
	void *delete_cons = talloc_new(NULL);

	/* loop over all connections sending tickle ACKs */
	trbt_traversearray32(killtcp->connections, KILLTCP_KEYLEN, tickle_connection_traverse, delete_cons);

	/* now we've finished traverse, it's safe to do deletion. */
	talloc_free(delete_cons);

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
	struct ctdb_vnn *tmpvnn;

	/* verify that this vnn is still active */
	for (tmpvnn = killtcp->ctdb->vnn; tmpvnn; tmpvnn = tmpvnn->next) {
		if (tmpvnn == killtcp->vnn) {
			break;
		}
	}

	if (tmpvnn == NULL) {
		return 0;
	}

	if (killtcp->vnn->killtcp != killtcp) {
		return 0;
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
				       ctdb_sock_addr *s,
				       ctdb_sock_addr *d)
{
	ctdb_sock_addr src, dst;
	struct ctdb_kill_tcp *killtcp;
	struct ctdb_killtcp_con *con;
	struct ctdb_vnn *vnn;

	ctdb_canonicalize_ip(s, &src);
	ctdb_canonicalize_ip(d, &dst);

	vnn = find_public_ip_vnn(ctdb, &dst);
	if (vnn == NULL) {
		vnn = find_public_ip_vnn(ctdb, &src);
	}
	if (vnn == NULL) {
		/* if it is not a public ip   it could be our 'single ip' */
		if (ctdb->single_ip_vnn) {
			if (ctdb_same_ip(&ctdb->single_ip_vnn->public_address, &dst)) {
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
		killtcp = talloc_zero(vnn, struct ctdb_kill_tcp);
		CTDB_NO_MEMORY(ctdb, killtcp);

		killtcp->vnn         = vnn;
		killtcp->ctdb        = ctdb;
		killtcp->capture_fd  = -1;
		killtcp->connections = trbt_create(killtcp, 0);

		vnn->killtcp         = killtcp;
		talloc_set_destructor(killtcp, ctdb_killtcp_destructor);
	}



	/* create a structure that describes this connection we want to
	   RST and store it in killtcp->connections
	*/
	con = talloc(killtcp, struct ctdb_killtcp_con);
	CTDB_NO_MEMORY(ctdb, con);
	con->src_addr = src;
	con->dst_addr = dst;
	con->count    = 0;
	con->killtcp  = killtcp;


	trbt_insertarray32_callback(killtcp->connections,
			KILLTCP_KEYLEN, killtcp_key(&con->dst_addr, &con->src_addr),
			add_killtcp_callback, con);

	/* 
	   If we dont have a socket to listen on yet we must create it
	 */
	if (killtcp->capture_fd == -1) {
		const char *iface = ctdb_vnn_iface_string(vnn);
		killtcp->capture_fd = ctdb_sys_open_capture_socket(iface, &killtcp->private_data);
		if (killtcp->capture_fd == -1) {
			DEBUG(DEBUG_CRIT,(__location__ " Failed to open capturing "
					  "socket on iface '%s' for killtcp (%s)\n",
					  iface, strerror(errno)));
			goto failed;
		}
	}


	if (killtcp->fde == NULL) {
		killtcp->fde = event_add_fd(ctdb->ev, killtcp, killtcp->capture_fd, 
					    EVENT_FD_READ,
					    capture_tcp_handler, killtcp);
		tevent_fd_set_auto_close(killtcp->fde);

		/* We also need to set up some events to tickle all these connections
		   until they are all reset
		*/
		event_add_timed(ctdb->ev, killtcp, timeval_current_ofs(1, 0), 
				ctdb_tickle_sentenced_connections, killtcp);
	}

	/* tickle him once now */
	ctdb_sys_send_tcp(
		&con->dst_addr,
		&con->src_addr,
		0, 0, 0);

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

	return ctdb_killtcp_add_connection(ctdb, &killtcp->src_addr, &killtcp->dst_addr);
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

	DEBUG(DEBUG_INFO, ("Received tickle update for public address %s\n",
			   ctdb_addr_to_str(&list->addr)));

	vnn = find_public_ip_vnn(ctdb, &list->addr);
	if (vnn == NULL) {
		DEBUG(DEBUG_INFO,(__location__ " Could not set tcp tickle list, '%s' is not a public address\n",
			ctdb_addr_to_str(&list->addr)));

		return 1;
	}

	/* remove any old ticklelist we might have */
	talloc_free(vnn->tcp_array);
	vnn->tcp_array = NULL;

	tcparray = talloc(vnn, struct ctdb_tcp_array);
	CTDB_NO_MEMORY(ctdb, tcparray);

	tcparray->num = list->tickles.num;

	tcparray->connections = talloc_array(tcparray, struct ctdb_tcp_connection, tcparray->num);
	CTDB_NO_MEMORY(ctdb, tcparray->connections);

	memcpy(tcparray->connections, &list->tickles.connections[0],
	       sizeof(struct ctdb_tcp_connection)*tcparray->num);

	/* We now have a new fresh tickle list array for this vnn */
	vnn->tcp_array = tcparray;

	return 0;
}

/*
  called to return the full list of tickles for the puclic address associated 
  with the provided vnn
 */
int32_t ctdb_control_get_tcp_tickle_list(struct ctdb_context *ctdb, TDB_DATA indata, TDB_DATA *outdata)
{
	ctdb_sock_addr *addr = (ctdb_sock_addr *)indata.dptr;
	struct ctdb_control_tcp_tickle_list *list;
	struct ctdb_tcp_array *tcparray;
	int num;
	struct ctdb_vnn *vnn;

	vnn = find_public_ip_vnn(ctdb, addr);
	if (vnn == NULL) {
		DEBUG(DEBUG_ERR,(__location__ " Could not get tcp tickle list, '%s' is not a public address\n", 
			ctdb_addr_to_str(addr)));

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

	list->addr = *addr;
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
static int ctdb_send_set_tcp_tickles_for_ip(struct ctdb_context *ctdb,
					    ctdb_sock_addr *addr,
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
	list->addr = *addr;
	list->tickles.num = num;
	if (tcparray) {
		memcpy(&list->tickles.connections[0], tcparray->connections, sizeof(struct ctdb_tcp_connection) * num);
	}

	ret = ctdb_daemon_send_control(ctdb, CTDB_BROADCAST_ALL, 0,
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
		ret = ctdb_send_set_tcp_tickles_for_ip(ctdb,
						       &vnn->public_address,
						       vnn->tcp_array);
		if (ret != 0) {
			DEBUG(DEBUG_ERR,("Failed to send the tickle update for public address %s\n",
				ctdb_addr_to_str(&vnn->public_address)));
		} else {
			DEBUG(DEBUG_INFO,
			      ("Sent tickle update for public address %s\n",
			       ctdb_addr_to_str(&vnn->public_address)));
			vnn->tcp_update_needed = false;
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
	ctdb_sock_addr addr;
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

	ret = ctdb_sys_send_arp(&arp->addr, arp->iface);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,(__location__ " sending of gratious arp on iface '%s' failed (%s)\n",
				 arp->iface, strerror(errno)));
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
		DEBUG(DEBUG_ERR,(__location__ " Too small indata to hold a ctdb_control_gratious_arp structure. Got %u require %u bytes\n", 
				 (unsigned)indata.dsize, 
				 (unsigned)offsetof(struct ctdb_control_gratious_arp, iface)));
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
	arp->addr   = gratious_arp->addr;
	arp->iface = talloc_strdup(arp, gratious_arp->iface);
	CTDB_NO_MEMORY(ctdb, arp->iface);
	arp->count = 0;
	
	event_add_timed(arp->ctdb->ev, arp, 
			timeval_zero(), send_gratious_arp, arp);

	return 0;
}

int32_t ctdb_control_add_public_address(struct ctdb_context *ctdb, TDB_DATA indata)
{
	struct ctdb_control_ip_iface *pub = (struct ctdb_control_ip_iface *)indata.dptr;
	int ret;

	/* verify the size of indata */
	if (indata.dsize < offsetof(struct ctdb_control_ip_iface, iface)) {
		DEBUG(DEBUG_ERR,(__location__ " Too small indata to hold a ctdb_control_ip_iface structure\n"));
		return -1;
	}
	if (indata.dsize != 
		( offsetof(struct ctdb_control_ip_iface, iface)
		+ pub->len ) ){

		DEBUG(DEBUG_ERR,(__location__ " Wrong size of indata. Was %u bytes "
			"but should be %u bytes\n", 
			 (unsigned)indata.dsize, 
			 (unsigned)(offsetof(struct ctdb_control_ip_iface, iface)+pub->len)));
		return -1;
	}

	DEBUG(DEBUG_NOTICE,("Add IP %s\n", ctdb_addr_to_str(&pub->addr)));

	ret = ctdb_add_public_address(ctdb, &pub->addr, pub->mask, &pub->iface[0], true);

	if (ret != 0) {
		DEBUG(DEBUG_ERR,(__location__ " Failed to add public address\n"));
		return -1;
	}

	return 0;
}

struct delete_ip_callback_state {
	struct ctdb_req_control *c;
};

/*
  called when releaseip event finishes for del_public_address
 */
static void delete_ip_callback(struct ctdb_context *ctdb,
			       int32_t status, TDB_DATA data,
			       const char *errormsg,
			       void *private_data)
{
	struct delete_ip_callback_state *state =
		talloc_get_type(private_data, struct delete_ip_callback_state);

	/* If release failed then fail. */
	ctdb_request_control_reply(ctdb, state->c, NULL, status, errormsg);
	talloc_free(private_data);
}

int32_t ctdb_control_del_public_address(struct ctdb_context *ctdb,
					struct ctdb_req_control *c,
					TDB_DATA indata, bool *async_reply)
{
	struct ctdb_control_ip_iface *pub = (struct ctdb_control_ip_iface *)indata.dptr;
	struct ctdb_vnn *vnn;

	/* verify the size of indata */
	if (indata.dsize < offsetof(struct ctdb_control_ip_iface, iface)) {
		DEBUG(DEBUG_ERR,(__location__ " Too small indata to hold a ctdb_control_ip_iface structure\n"));
		return -1;
	}
	if (indata.dsize != 
		( offsetof(struct ctdb_control_ip_iface, iface)
		+ pub->len ) ){

		DEBUG(DEBUG_ERR,(__location__ " Wrong size of indata. Was %u bytes "
			"but should be %u bytes\n", 
			 (unsigned)indata.dsize, 
			 (unsigned)(offsetof(struct ctdb_control_ip_iface, iface)+pub->len)));
		return -1;
	}

	DEBUG(DEBUG_NOTICE,("Delete IP %s\n", ctdb_addr_to_str(&pub->addr)));

	/* walk over all public addresses until we find a match */
	for (vnn=ctdb->vnn;vnn;vnn=vnn->next) {
		if (ctdb_same_ip(&vnn->public_address, &pub->addr)) {
			if (vnn->pnn == ctdb->pnn) {
				struct delete_ip_callback_state *state;
				struct ctdb_public_ip *ip;
				TDB_DATA data;
				int ret;

				vnn->delete_pending = true;

				state = talloc(ctdb,
					       struct delete_ip_callback_state);
				CTDB_NO_MEMORY(ctdb, state);
				state->c = c;

				ip = talloc(state, struct ctdb_public_ip);
				if (ip == NULL) {
					DEBUG(DEBUG_ERR,
					      (__location__ " Out of memory\n"));
					talloc_free(state);
					return -1;
				}
				ip->pnn = -1;
				ip->addr = pub->addr;

				data.dsize = sizeof(struct ctdb_public_ip);
				data.dptr = (unsigned char *)ip;

				ret = ctdb_daemon_send_control(ctdb,
							       ctdb_get_pnn(ctdb),
							       0,
							       CTDB_CONTROL_RELEASE_IP,
							       0, 0,
							       data,
							       delete_ip_callback,
							       state);
				if (ret == -1) {
					DEBUG(DEBUG_ERR,
					      (__location__ "Unable to send "
					       "CTDB_CONTROL_RELEASE_IP\n"));
					talloc_free(state);
					return -1;
				}

				state->c = talloc_steal(state, c);
				*async_reply = true;
			} else {
				/* This IP is not hosted on the
				 * current node so just delete it
				 * now. */
				do_delete_ip(ctdb, vnn);
			}

			return 0;
		}
	}

	DEBUG(DEBUG_ERR,("Delete IP of unknown public IP address %s\n",
			 ctdb_addr_to_str(&pub->addr)));
	return -1;
}


struct ipreallocated_callback_state {
	struct ctdb_req_control *c;
};

static void ctdb_ipreallocated_callback(struct ctdb_context *ctdb,
					int status, void *p)
{
	struct ipreallocated_callback_state *state =
		talloc_get_type(p, struct ipreallocated_callback_state);

	if (status != 0) {
		DEBUG(DEBUG_ERR,
		      (" \"ipreallocated\" event script failed (status %d)\n",
		       status));
		if (status == -ETIME) {
			ctdb_ban_self(ctdb);
		}
	}

	ctdb_request_control_reply(ctdb, state->c, NULL, status, NULL);
	talloc_free(state);
}

/* A control to run the ipreallocated event */
int32_t ctdb_control_ipreallocated(struct ctdb_context *ctdb,
				   struct ctdb_req_control *c,
				   bool *async_reply)
{
	int ret;
	struct ipreallocated_callback_state *state;

	state = talloc(ctdb, struct ipreallocated_callback_state);
	CTDB_NO_MEMORY(ctdb, state);

	DEBUG(DEBUG_INFO,(__location__ " Running \"ipreallocated\" event\n"));

	ret = ctdb_event_script_callback(ctdb, state,
					 ctdb_ipreallocated_callback, state,
					 CTDB_EVENT_IPREALLOCATED,
					 "%s", "");

	if (ret != 0) {
		DEBUG(DEBUG_ERR,("Failed to run \"ipreallocated\" event \n"));
		talloc_free(state);
		return -1;
	}

	/* tell the control that we will be reply asynchronously */
	state->c    = talloc_steal(state, c);
	*async_reply = true;

	return 0;
}


/* This function is called from the recovery daemon to verify that a remote
   node has the expected ip allocation.
   This is verified against ctdb->ip_tree
*/
int verify_remote_ip_allocation(struct ctdb_context *ctdb,
				struct ctdb_all_public_ips *ips,
				uint32_t pnn)
{
	struct ctdb_public_ip_list *tmp_ip; 
	int i;

	if (ctdb->ip_tree == NULL) {
		/* dont know the expected allocation yet, assume remote node
		   is correct. */
		return 0;
	}

	if (ips == NULL) {
		return 0;
	}

	for (i=0; i<ips->num; i++) {
		tmp_ip = trbt_lookuparray32(ctdb->ip_tree, IP_KEYLEN, ip_key(&ips->ips[i].addr));
		if (tmp_ip == NULL) {
			DEBUG(DEBUG_ERR,("Node %u has new or unknown public IP %s\n", pnn, ctdb_addr_to_str(&ips->ips[i].addr)));
			return -1;
		}

		if (tmp_ip->pnn == -1 || ips->ips[i].pnn == -1) {
			continue;
		}

		if (tmp_ip->pnn != ips->ips[i].pnn) {
			DEBUG(DEBUG_ERR,
			      ("Inconsistent IP allocation - node %u thinks %s is held by node %u while it is assigned to node %u\n",
			       pnn,
			       ctdb_addr_to_str(&ips->ips[i].addr),
			       ips->ips[i].pnn, tmp_ip->pnn));
			return -1;
		}
	}

	return 0;
}

int update_ip_assignment_tree(struct ctdb_context *ctdb, struct ctdb_public_ip *ip)
{
	struct ctdb_public_ip_list *tmp_ip; 

	if (ctdb->ip_tree == NULL) {
		DEBUG(DEBUG_ERR,("No ctdb->ip_tree yet. Failed to update ip assignment\n"));
		return -1;
	}

	tmp_ip = trbt_lookuparray32(ctdb->ip_tree, IP_KEYLEN, ip_key(&ip->addr));
	if (tmp_ip == NULL) {
		DEBUG(DEBUG_ERR,(__location__ " Could not find record for address %s, update ip\n", ctdb_addr_to_str(&ip->addr)));
		return -1;
	}

	DEBUG(DEBUG_NOTICE,("Updated ip assignment tree for ip : %s from node %u to node %u\n", ctdb_addr_to_str(&ip->addr), tmp_ip->pnn, ip->pnn));
	tmp_ip->pnn = ip->pnn;

	return 0;
}


struct ctdb_reloadips_handle {
	struct ctdb_context *ctdb;
	struct ctdb_req_control *c;
	int status;
	int fd[2];
	pid_t child;
	struct fd_event *fde;
};

static int ctdb_reloadips_destructor(struct ctdb_reloadips_handle *h)
{
	if (h == h->ctdb->reload_ips) {
		h->ctdb->reload_ips = NULL;
	}
	if (h->c != NULL) {
		ctdb_request_control_reply(h->ctdb, h->c, NULL, h->status, NULL);
		h->c = NULL;
	}
	ctdb_kill(h->ctdb, h->child, SIGKILL);
	return 0;
}

static void ctdb_reloadips_timeout_event(struct event_context *ev,
				struct timed_event *te,
				struct timeval t, void *private_data)
{
	struct ctdb_reloadips_handle *h = talloc_get_type(private_data, struct ctdb_reloadips_handle);

	talloc_free(h);
}	

static void ctdb_reloadips_child_handler(struct event_context *ev, struct fd_event *fde, 
			     uint16_t flags, void *private_data)
{
	struct ctdb_reloadips_handle *h = talloc_get_type(private_data, struct ctdb_reloadips_handle);

	char res;
	int ret;

	ret = sys_read(h->fd[0], &res, 1);
	if (ret < 1 || res != 0) {
		DEBUG(DEBUG_ERR, (__location__ " Reloadips child process returned error\n"));
		res = 1;
	}
	h->status = res;

	talloc_free(h);
}

static int ctdb_reloadips_child(struct ctdb_context *ctdb)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	struct ctdb_all_public_ips *ips;
	struct ctdb_vnn *vnn;
	struct client_async_data *async_data;
	struct timeval timeout;
	TDB_DATA data;
	struct ctdb_client_control_state *state;
	bool first_add;
	int i, ret;

	CTDB_NO_MEMORY(ctdb, mem_ctx);

	/* Read IPs from local node */
	ret = ctdb_ctrl_get_public_ips(ctdb, TAKEOVER_TIMEOUT(),
				       CTDB_CURRENT_NODE, mem_ctx, &ips);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,
		      ("Unable to fetch public IPs from local node\n"));
		talloc_free(mem_ctx);
		return -1;
	}

	/* Read IPs file - this is safe since this is a child process */
	ctdb->vnn = NULL;
	if (ctdb_set_public_addresses(ctdb, false) != 0) {
		DEBUG(DEBUG_ERR,("Failed to re-read public addresses file\n"));
		talloc_free(mem_ctx);
		return -1;
	}

	async_data = talloc_zero(mem_ctx, struct client_async_data);
	CTDB_NO_MEMORY(ctdb, async_data);

	/* Compare IPs between node and file for IPs to be deleted */
	for (i = 0; i < ips->num; i++) {
		/* */
		for (vnn = ctdb->vnn; vnn; vnn = vnn->next) {
			if (ctdb_same_ip(&vnn->public_address,
					 &ips->ips[i].addr)) {
				/* IP is still in file */
				break;
			}
		}

		if (vnn == NULL) {
			/* Delete IP ips->ips[i] */
			struct ctdb_control_ip_iface *pub;

			DEBUG(DEBUG_NOTICE,
			      ("IP %s no longer configured, deleting it\n",
			       ctdb_addr_to_str(&ips->ips[i].addr)));

			pub = talloc_zero(mem_ctx,
					  struct ctdb_control_ip_iface);
			CTDB_NO_MEMORY(ctdb, pub);

			pub->addr  = ips->ips[i].addr;
			pub->mask  = 0;
			pub->len   = 0;

			timeout = TAKEOVER_TIMEOUT();

			data.dsize = offsetof(struct ctdb_control_ip_iface,
					      iface) + pub->len;
			data.dptr = (uint8_t *)pub;

			state = ctdb_control_send(ctdb, CTDB_CURRENT_NODE, 0,
						  CTDB_CONTROL_DEL_PUBLIC_IP,
						  0, data, async_data,
						  &timeout, NULL);
			if (state == NULL) {
				DEBUG(DEBUG_ERR,
				      (__location__
				       " failed sending CTDB_CONTROL_DEL_PUBLIC_IP\n"));
				goto failed;
			}

			ctdb_client_async_add(async_data, state);
		}
	}

	/* Compare IPs between node and file for IPs to be added */
	first_add = true;
	for (vnn = ctdb->vnn; vnn; vnn = vnn->next) {
		for (i = 0; i < ips->num; i++) {
			if (ctdb_same_ip(&vnn->public_address,
					 &ips->ips[i].addr)) {
				/* IP already on node */
				break;
			}
		}
		if (i == ips->num) {
			/* Add IP ips->ips[i] */
			struct ctdb_control_ip_iface *pub;
			const char *ifaces = NULL;
			uint32_t len;
			int iface = 0;

			DEBUG(DEBUG_NOTICE,
			      ("New IP %s configured, adding it\n",
			       ctdb_addr_to_str(&vnn->public_address)));
			if (first_add) {
				uint32_t pnn = ctdb_get_pnn(ctdb);

				data.dsize = sizeof(pnn);
				data.dptr  = (uint8_t *)&pnn;

				ret = ctdb_client_send_message(
					ctdb,
					CTDB_BROADCAST_CONNECTED,
					CTDB_SRVID_REBALANCE_NODE,
					data);
				if (ret != 0) {
					DEBUG(DEBUG_WARNING,
					      ("Failed to send message to force node reallocation - IPs may be unbalanced\n"));
				}

				first_add = false;
			}

			ifaces = vnn->ifaces[0];
			iface = 1;
			while (vnn->ifaces[iface] != NULL) {
				ifaces = talloc_asprintf(vnn, "%s,%s", ifaces,
							 vnn->ifaces[iface]);
				iface++;
			}

			len   = strlen(ifaces) + 1;
			pub = talloc_zero_size(mem_ctx,
					       offsetof(struct ctdb_control_ip_iface, iface) + len);
			CTDB_NO_MEMORY(ctdb, pub);

			pub->addr  = vnn->public_address;
			pub->mask  = vnn->public_netmask_bits;
			pub->len   = len;
			memcpy(&pub->iface[0], ifaces, pub->len);

			timeout = TAKEOVER_TIMEOUT();

			data.dsize = offsetof(struct ctdb_control_ip_iface,
					      iface) + pub->len;
			data.dptr = (uint8_t *)pub;

			state = ctdb_control_send(ctdb, CTDB_CURRENT_NODE, 0,
						  CTDB_CONTROL_ADD_PUBLIC_IP,
						  0, data, async_data,
						  &timeout, NULL);
			if (state == NULL) {
				DEBUG(DEBUG_ERR,
				      (__location__
				       " failed sending CTDB_CONTROL_ADD_PUBLIC_IP\n"));
				goto failed;
			}

			ctdb_client_async_add(async_data, state);
		}
	}

	if (ctdb_client_async_wait(ctdb, async_data) != 0) {
		DEBUG(DEBUG_ERR,(__location__ " Add/delete IPs failed\n"));
		goto failed;
	}

	talloc_free(mem_ctx);
	return 0;

failed:
	talloc_free(mem_ctx);
	return -1;
}

/* This control is sent to force the node to re-read the public addresses file
   and drop any addresses we should nnot longer host, and add new addresses
   that we are now able to host
*/
int32_t ctdb_control_reload_public_ips(struct ctdb_context *ctdb, struct ctdb_req_control *c, bool *async_reply)
{
	struct ctdb_reloadips_handle *h;
	pid_t parent = getpid();

	if (ctdb->reload_ips != NULL) {
		talloc_free(ctdb->reload_ips);
		ctdb->reload_ips = NULL;
	}

	h = talloc(ctdb, struct ctdb_reloadips_handle);
	CTDB_NO_MEMORY(ctdb, h);
	h->ctdb     = ctdb;
	h->c        = NULL;
	h->status   = -1;
	
	if (pipe(h->fd) == -1) {
		DEBUG(DEBUG_ERR,("Failed to create pipe for ctdb_freeze_lock\n"));
		talloc_free(h);
		return -1;
	}

	h->child = ctdb_fork(ctdb);
	if (h->child == (pid_t)-1) {
		DEBUG(DEBUG_ERR, ("Failed to fork a child for reloadips\n"));
		close(h->fd[0]);
		close(h->fd[1]);
		talloc_free(h);
		return -1;
	}

	/* child process */
	if (h->child == 0) {
		signed char res = 0;

		close(h->fd[0]);
		debug_extra = talloc_asprintf(NULL, "reloadips:");

		ctdb_set_process_name("ctdb_reloadips");
		if (switch_from_server_to_client(ctdb, "reloadips-child") != 0) {
			DEBUG(DEBUG_CRIT,("ERROR: Failed to switch reloadips child into client mode\n"));
			res = -1;
		} else {
			res = ctdb_reloadips_child(ctdb);
			if (res != 0) {
				DEBUG(DEBUG_ERR,("Failed to reload ips on local node\n"));
			}
		}

		sys_write(h->fd[1], &res, 1);
		/* make sure we die when our parent dies */
		while (ctdb_kill(ctdb, parent, 0) == 0 || errno != ESRCH) {
			sleep(5);
		}
		_exit(0);
	}

	h->c             = talloc_steal(h, c);

	close(h->fd[1]);
	set_close_on_exec(h->fd[0]);

	talloc_set_destructor(h, ctdb_reloadips_destructor);


	h->fde = event_add_fd(ctdb->ev, h, h->fd[0],
			EVENT_FD_READ, ctdb_reloadips_child_handler,
			(void *)h);
	tevent_fd_set_auto_close(h->fde);

	event_add_timed(ctdb->ev, h,
			timeval_current_ofs(120, 0),
			ctdb_reloadips_timeout_event, h);

	/* we reply later */
	*async_reply = true;
	return 0;
}
