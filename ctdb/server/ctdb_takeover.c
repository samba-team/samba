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
#include "replace.h"
#include "system/network.h"
#include "system/filesys.h"
#include "system/time.h"
#include "system/wait.h"

#include <talloc.h>
#include <tevent.h>

#include "lib/util/dlinklist.h"
#include "lib/util/debug.h"
#include "lib/util/samba_util.h"
#include "lib/util/sys_rw.h"
#include "lib/util/util_process.h"

#include "protocol/protocol_util.h"

#include "ctdb_private.h"
#include "ctdb_client.h"

#include "common/rb_tree.h"
#include "common/reqid.h"
#include "common/system.h"
#include "common/system_socket.h"
#include "common/common.h"
#include "common/logging.h"

#include "server/ctdb_config.h"

#include "server/ipalloc.h"

#define TAKEOVER_TIMEOUT() timeval_current_ofs(ctdb->tunable.takeover_timeout,0)

#define CTDB_ARP_INTERVAL 1
#define CTDB_ARP_REPEAT   3

struct ctdb_interface {
	struct ctdb_interface *prev, *next;
	const char *name;
	bool link_up;
	uint32_t references;
};

struct vnn_interface {
	struct vnn_interface *prev, *next;
	struct ctdb_interface *iface;
};

/* state associated with a public ip address */
struct ctdb_vnn {
	struct ctdb_vnn *prev, *next;

	struct ctdb_interface *iface;
	struct vnn_interface *ifaces;
	ctdb_sock_addr public_address;
	uint8_t public_netmask_bits;

	/*
	 * The node number that is serving this public address - set
	 * to CTDB_UNKNOWN_PNN if node is serving it
	 */
	uint32_t pnn;

	/* List of clients to tickle for this public address */
	struct ctdb_tcp_array *tcp_array;

	/* whether we need to update the other nodes with changes to our list
	   of connected clients */
	bool tcp_update_needed;

	/* a context to hang sending gratious arp events off */
	TALLOC_CTX *takeover_ctx;

	/* Set to true any time an update to this VNN is in flight.
	   This helps to avoid races. */
	bool update_in_flight;

	/* If CTDB_CONTROL_DEL_PUBLIC_IP is received for this IP
	 * address then this flag is set.  It will be deleted in the
	 * release IP callback. */
	bool delete_pending;
};

static const char *iface_string(const struct ctdb_interface *iface)
{
	return (iface != NULL ? iface->name : "__none__");
}

static const char *ctdb_vnn_iface_string(const struct ctdb_vnn *vnn)
{
	return iface_string(vnn->iface);
}

static struct ctdb_interface *ctdb_find_iface(struct ctdb_context *ctdb,
					      const char *iface);

static struct ctdb_interface *
ctdb_add_local_iface(struct ctdb_context *ctdb, const char *iface)
{
	struct ctdb_interface *i;

	if (strlen(iface) > CTDB_IFACE_SIZE) {
		DEBUG(DEBUG_ERR, ("Interface name too long \"%s\"\n", iface));
		return NULL;
	}

	/* Verify that we don't have an entry for this ip yet */
	i = ctdb_find_iface(ctdb, iface);
	if (i != NULL) {
		return i;
	}

	/* create a new structure for this interface */
	i = talloc_zero(ctdb, struct ctdb_interface);
	if (i == NULL) {
		DEBUG(DEBUG_ERR, (__location__ " out of memory\n"));
		return NULL;
	}
	i->name = talloc_strdup(i, iface);
	if (i->name == NULL) {
		DEBUG(DEBUG_ERR, (__location__ " out of memory\n"));
		talloc_free(i);
		return NULL;
	}

	i->link_up = true;

	DLIST_ADD(ctdb->ifaces, i);

	return i;
}

static bool vnn_has_interface(struct ctdb_vnn *vnn,
			      const struct ctdb_interface *iface)
{
	struct vnn_interface *i;

	for (i = vnn->ifaces; i != NULL; i = i->next) {
		if (iface == i->iface) {
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
 * can have addresses (by walking ctdb->vnn once) and then walking
 * ctdb->ifaces once and deleting those not in the tree.  Let's go to
 * one of those if the naive implementation causes problems...  :-)
 */
static void ctdb_remove_orphaned_ifaces(struct ctdb_context *ctdb,
					struct ctdb_vnn *vnn)
{
	struct ctdb_interface *i, *next;

	/* For each interface, check if there's an IP using it. */
	for (i = ctdb->ifaces; i != NULL; i = next) {
		struct ctdb_vnn *tv;
		bool found;
		next = i->next;

		/* Only consider interfaces named in the given VNN. */
		if (!vnn_has_interface(vnn, i)) {
			continue;
		}

		/* Search for a vnn with this interface. */
		found = false;
		for (tv=ctdb->vnn; tv; tv=tv->next) {
			if (vnn_has_interface(tv, i)) {
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


static struct ctdb_interface *ctdb_find_iface(struct ctdb_context *ctdb,
					      const char *iface)
{
	struct ctdb_interface *i;

	for (i=ctdb->ifaces;i;i=i->next) {
		if (strcmp(i->name, iface) == 0) {
			return i;
		}
	}

	return NULL;
}

static struct ctdb_interface *ctdb_vnn_best_iface(struct ctdb_context *ctdb,
						  struct ctdb_vnn *vnn)
{
	struct vnn_interface *i;
	struct ctdb_interface *cur = NULL;
	struct ctdb_interface *best = NULL;

	for (i = vnn->ifaces; i != NULL; i = i->next) {

		cur = i->iface;

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
	struct ctdb_interface *best = NULL;

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
		vnn->pnn = CTDB_UNKNOWN_PNN;
	}
}

static bool ctdb_vnn_available(struct ctdb_context *ctdb,
			       struct ctdb_vnn *vnn)
{
	uint32_t flags;
	struct vnn_interface *i;

	/* Nodes that are not RUNNING can not host IPs */
	if (ctdb->runstate != CTDB_RUNSTATE_RUNNING) {
		return false;
	}

	flags = ctdb->nodes[ctdb->pnn]->flags;
	if ((flags & (NODE_FLAGS_INACTIVE|NODE_FLAGS_DISABLED)) != 0) {
		return false;
	}

	if (vnn->delete_pending) {
		return false;
	}

	if (vnn->iface && vnn->iface->link_up) {
		return true;
	}

	for (i = vnn->ifaces; i != NULL; i = i->next) {
		if (i->iface->link_up) {
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
	struct ctdb_connection connection;
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
static void ctdb_control_send_arp(struct tevent_context *ev,
				  struct tevent_timer *te,
				  struct timeval t, void *private_data)
{
	struct ctdb_takeover_arp *arp = talloc_get_type(private_data, 
							struct ctdb_takeover_arp);
	int ret;
	struct ctdb_tcp_array *tcparray;
	const char *iface = ctdb_vnn_iface_string(arp->vnn);

	ret = ctdb_sys_send_arp(&arp->addr, iface);
	if (ret != 0) {
		DBG_ERR("Failed to send ARP on interface %s: %s\n",
			iface, strerror(ret));
	}

	tcparray = arp->tcparray;
	if (tcparray) {
		unsigned int i;

		for (i=0;i<tcparray->num;i++) {
			struct ctdb_connection *tcon;

			tcon = &tcparray->connections[i];
			DEBUG(DEBUG_INFO,("sending tcp tickle ack for %u->%s:%u\n",
				(unsigned)ntohs(tcon->dst.ip.sin_port),
				ctdb_addr_to_str(&tcon->src),
				(unsigned)ntohs(tcon->src.ip.sin_port)));
			ret = ctdb_sys_send_tcp(
				&tcon->src,
				&tcon->dst,
				0, 0, 0);
			if (ret != 0) {
				DEBUG(DEBUG_CRIT,(__location__ " Failed to send tcp tickle ack for %s\n",
					ctdb_addr_to_str(&tcon->src)));
			}
		}
	}

	arp->count++;

	if (arp->count == CTDB_ARP_REPEAT) {
		talloc_free(arp);
		return;
	}

	tevent_add_timer(arp->ctdb->ev, arp->vnn->takeover_ctx,
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

	tevent_add_timer(arp->ctdb->ev, vnn->takeover_ctx,
			 timeval_zero(), ctdb_control_send_arp, arp);

	return 0;
}

struct ctdb_do_takeip_state {
	struct ctdb_req_control_old *c;
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
		if (status == -ETIMEDOUT) {
			ctdb_ban_self(ctdb);
		}
		DEBUG(DEBUG_ERR,(__location__ " Failed to takeover IP %s on interface %s\n",
				 ctdb_addr_to_str(&state->vnn->public_address),
				 ctdb_vnn_iface_string(state->vnn)));
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
			      struct ctdb_req_control_old *c,
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

	state->c = NULL;
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

	state->c = talloc_steal(ctdb, c);
	return 0;
}

struct ctdb_do_updateip_state {
	struct ctdb_req_control_old *c;
	struct ctdb_interface *old;
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

	if (status != 0) {
		if (status == -ETIMEDOUT) {
			ctdb_ban_self(ctdb);
		}
		DEBUG(DEBUG_ERR,
		      ("Failed update of IP %s from interface %s to %s\n",
		       ctdb_addr_to_str(&state->vnn->public_address),
		       iface_string(state->old),
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
				struct ctdb_req_control_old *c,
				struct ctdb_vnn *vnn)
{
	int ret;
	struct ctdb_do_updateip_state *state;
	struct ctdb_interface *old = vnn->iface;
	const char *old_name = iface_string(old);
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
		DEBUG(DEBUG_ERR,("Update of IP %s/%u failed to "
				 "assign a usable interface (old iface '%s')\n",
				 ctdb_addr_to_str(&vnn->public_address),
				 vnn->public_netmask_bits,
				 old_name));
		return -1;
	}

	if (old == vnn->iface) {
		/* A benign update from one interface onto itself.
		 * no need to run the eventscripts in this case, just return
		 * success.
		 */
		ctdb_request_control_reply(ctdb, c, NULL, 0, NULL);
		return 0;
	}

	state = talloc(vnn, struct ctdb_do_updateip_state);
	CTDB_NO_MEMORY(ctdb, state);

	state->c = NULL;
	state->old = old;
	state->vnn = vnn;

	vnn->update_in_flight = true;
	talloc_set_destructor(state, ctdb_updateip_destructor);

	new_name = ctdb_vnn_iface_string(vnn);
	DEBUG(DEBUG_NOTICE,("Update of IP %s/%u from "
			    "interface %s to %s\n",
			    ctdb_addr_to_str(&vnn->public_address),
			    vnn->public_netmask_bits,
			    old_name,
			    new_name));

	ret = ctdb_event_script_callback(ctdb,
					 state,
					 ctdb_do_updateip_callback,
					 state,
					 CTDB_EVENT_UPDATE_IP,
					 "%s %s %s %u",
					 old_name,
					 new_name,
					 ctdb_addr_to_str(&vnn->public_address),
					 vnn->public_netmask_bits);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,
		      ("Failed update IP %s from interface %s to %s\n",
		       ctdb_addr_to_str(&vnn->public_address),
		       old_name, new_name));
		talloc_free(state);
		return -1;
	}

	state->c = talloc_steal(ctdb, c);
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
				 struct ctdb_req_control_old *c,
				 TDB_DATA indata,
				 bool *async_reply)
{
	int ret;
	struct ctdb_public_ip *pip = (struct ctdb_public_ip *)indata.dptr;
	struct ctdb_vnn *vnn;
	bool have_ip = false;
	bool do_updateip = false;
	bool do_takeip = false;
	struct ctdb_interface *best_iface = NULL;

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

	if (ctdb_config.failover_disabled == 0 && ctdb->do_checkpublicip) {
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

	if (vnn->pnn != ctdb->pnn && have_ip && vnn->pnn != CTDB_UNKNOWN_PNN) {
		DEBUG(DEBUG_CRIT,(__location__ " takeoverip of IP %s is known to the kernel, "
				  "and we have it on iface[%s], but it was assigned to node %d"
				  "and we are node %d, banning ourself\n",
				 ctdb_addr_to_str(&vnn->public_address),
				 ctdb_vnn_iface_string(vnn), vnn->pnn, ctdb->pnn));
		ctdb_ban_self(ctdb);
		return -1;
	}

	if (vnn->pnn == CTDB_UNKNOWN_PNN && have_ip) {
		/* This will cause connections to be reset and
		 * reestablished.  However, this is a very unusual
		 * situation and doing this will completely repair the
		 * inconsistency in the VNN.
		 */
		DEBUG(DEBUG_WARNING,
		      (__location__
		       " Doing updateip for IP %s already on an interface\n",
		       ctdb_addr_to_str(&vnn->public_address)));
		do_updateip = true;
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

static void do_delete_ip(struct ctdb_context *ctdb, struct ctdb_vnn *vnn)
{
	DLIST_REMOVE(ctdb->vnn, vnn);
	ctdb_vnn_unassign_iface(ctdb, vnn);
	ctdb_remove_orphaned_ifaces(ctdb, vnn);
	talloc_free(vnn);
}

static struct ctdb_vnn *release_ip_post(struct ctdb_context *ctdb,
					struct ctdb_vnn *vnn,
					ctdb_sock_addr *addr)
{
	TDB_DATA data;

	/* Send a message to all clients of this node telling them
	 * that the cluster has been reconfigured and they should
	 * close any connections on this IP address
	 */
	data.dptr = (uint8_t *)ctdb_addr_to_str(addr);
	data.dsize = strlen((char *)data.dptr)+1;
	DEBUG(DEBUG_INFO, ("Sending RELEASE_IP message for %s\n", data.dptr));
	ctdb_daemon_send_message(ctdb, ctdb->pnn, CTDB_SRVID_RELEASE_IP, data);

	ctdb_vnn_unassign_iface(ctdb, vnn);

	/* Process the IP if it has been marked for deletion */
	if (vnn->delete_pending) {
		do_delete_ip(ctdb, vnn);
		return NULL;
	}

	return vnn;
}

struct release_ip_callback_state {
	struct ctdb_req_control_old *c;
	ctdb_sock_addr *addr;
	struct ctdb_vnn *vnn;
	uint32_t target_pnn;
};

/*
  called when releaseip event finishes
 */
static void release_ip_callback(struct ctdb_context *ctdb, int status,
				void *private_data)
{
	struct release_ip_callback_state *state =
		talloc_get_type(private_data, struct release_ip_callback_state);

	if (status == -ETIMEDOUT) {
		ctdb_ban_self(ctdb);
	}

	if (ctdb_config.failover_disabled == 0 && ctdb->do_checkpublicip) {
		if  (ctdb_sys_have_ip(state->addr)) {
			DEBUG(DEBUG_ERR,
			      ("IP %s still hosted during release IP callback, failing\n",
			       ctdb_addr_to_str(state->addr)));
			ctdb_request_control_reply(ctdb, state->c,
						   NULL, -1, NULL);
			talloc_free(state);
			return;
		}
	}

	state->vnn->pnn = state->target_pnn;
	state->vnn = release_ip_post(ctdb, state->vnn, state->addr);

	/* the control succeeded */
	ctdb_request_control_reply(ctdb, state->c, NULL, 0, NULL);
	talloc_free(state);
}

static int ctdb_releaseip_destructor(struct release_ip_callback_state *state)
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
				struct ctdb_req_control_old *c,
				TDB_DATA indata, 
				bool *async_reply)
{
	int ret;
	struct release_ip_callback_state *state;
	struct ctdb_public_ip *pip = (struct ctdb_public_ip *)indata.dptr;
	struct ctdb_vnn *vnn;
	const char *iface;

	/* update our vnn list */
	vnn = find_public_ip_vnn(ctdb, &pip->addr);
	if (vnn == NULL) {
		DEBUG(DEBUG_INFO,("releaseip called for an ip '%s' that is not a public address\n",
			ctdb_addr_to_str(&pip->addr)));
		return 0;
	}

	/* stop any previous arps */
	talloc_free(vnn->takeover_ctx);
	vnn->takeover_ctx = NULL;

	/* RELEASE_IP controls are sent to all nodes that should not
	 * be hosting a particular IP.  This serves 2 purposes.  The
	 * first is to help resolve any inconsistencies.  If a node
	 * does unexpectly host an IP then it will be released.  The
	 * 2nd is to use a "redundant release" to tell non-takeover
	 * nodes where an IP is moving to.  This is how "ctdb ip" can
	 * report the (likely) location of an IP by only asking the
	 * local node.  Redundant releases need to update the PNN but
	 * are otherwise ignored.
	 */
	if (ctdb_config.failover_disabled == 0 && ctdb->do_checkpublicip) {
		if (!ctdb_sys_have_ip(&pip->addr)) {
			DEBUG(DEBUG_DEBUG,("Redundant release of IP %s/%u on interface %s (ip not held)\n",
				ctdb_addr_to_str(&pip->addr),
				vnn->public_netmask_bits,
				ctdb_vnn_iface_string(vnn)));
			vnn->pnn = pip->pnn;
			ctdb_vnn_unassign_iface(ctdb, vnn);
			return 0;
		}
	} else {
		if (vnn->iface == NULL) {
			DEBUG(DEBUG_DEBUG,("Redundant release of IP %s/%u (ip not held)\n",
					   ctdb_addr_to_str(&pip->addr),
					   vnn->public_netmask_bits));
			vnn->pnn = pip->pnn;
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

	iface = ctdb_vnn_iface_string(vnn);

	DEBUG(DEBUG_NOTICE,("Release of IP %s/%u on interface %s  node:%d\n",
		ctdb_addr_to_str(&pip->addr),
		vnn->public_netmask_bits,
		iface,
		pip->pnn));

	state = talloc(ctdb, struct release_ip_callback_state);
	if (state == NULL) {
		ctdb_set_error(ctdb, "Out of memory at %s:%d",
			       __FILE__, __LINE__);
		return -1;
	}

	state->c = NULL;
	state->addr = talloc(state, ctdb_sock_addr);
	if (state->addr == NULL) {
		ctdb_set_error(ctdb, "Out of memory at %s:%d",
			       __FILE__, __LINE__);
		talloc_free(state);
		return -1;
	}
	*state->addr = pip->addr;
	state->target_pnn = pip->pnn;
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
	if (ret != 0) {
		DEBUG(DEBUG_ERR,(__location__ " Failed to release IP %s on interface %s\n",
			ctdb_addr_to_str(&pip->addr),
			ctdb_vnn_iface_string(vnn)));
		talloc_free(state);
		return -1;
	}

	/* tell the control that we will be reply asynchronously */
	*async_reply = true;
	state->c = talloc_steal(state, c);
	return 0;
}

static int ctdb_add_public_address(struct ctdb_context *ctdb,
				   ctdb_sock_addr *addr,
				   unsigned mask, const char *ifaces,
				   bool check_address)
{
	struct ctdb_vnn      *vnn;
	char *tmp;
	const char *iface;

	/* Verify that we don't have an entry for this IP yet */
	for (vnn = ctdb->vnn; vnn != NULL; vnn = vnn->next) {
		if (ctdb_same_sockaddr(addr, &vnn->public_address)) {
			DEBUG(DEBUG_ERR,
			      ("Duplicate public IP address '%s'\n",
			       ctdb_addr_to_str(addr)));
			return -1;
		}
	}

	/* Create a new VNN structure for this IP address */
	vnn = talloc_zero(ctdb, struct ctdb_vnn);
	if (vnn == NULL) {
		DEBUG(DEBUG_ERR, (__location__ " out of memory\n"));
		return -1;
	}
	tmp = talloc_strdup(vnn, ifaces);
	if (tmp == NULL) {
		DEBUG(DEBUG_ERR, (__location__ " out of memory\n"));
		talloc_free(vnn);
		return -1;
	}
	for (iface = strtok(tmp, ","); iface; iface = strtok(NULL, ",")) {
		struct vnn_interface *vnn_iface;
		struct ctdb_interface *i;
		if (!ctdb_sys_check_iface_exists(iface)) {
			DEBUG(DEBUG_ERR,
			      ("Unknown interface %s for public address %s\n",
			       iface, ctdb_addr_to_str(addr)));
			talloc_free(vnn);
			return -1;
		}

		i = ctdb_add_local_iface(ctdb, iface);
		if (i == NULL) {
			DEBUG(DEBUG_ERR,
			      ("Failed to add interface '%s' "
			       "for public address %s\n",
			       iface, ctdb_addr_to_str(addr)));
			talloc_free(vnn);
			return -1;
		}

		vnn_iface = talloc_zero(vnn, struct vnn_interface);
		if (vnn_iface == NULL) {
			DEBUG(DEBUG_ERR, (__location__ " out of memory\n"));
			talloc_free(vnn);
			return -1;
		}

		vnn_iface->iface = i;
		DLIST_ADD_END(vnn->ifaces, vnn_iface);
	}
	talloc_free(tmp);
	vnn->public_address      = *addr;
	vnn->public_netmask_bits = mask;
	vnn->pnn                 = -1;

	DLIST_ADD(ctdb->vnn, vnn);

	return 0;
}

/*
  setup the public address lists from a file
*/
int ctdb_set_public_addresses(struct ctdb_context *ctdb, bool check_addresses)
{
	bool ok;
	char **lines;
	int nlines;
	int i;

	/* If no public addresses file given then try the default */
	if (ctdb->public_addresses_file == NULL) {
		const char *b = getenv("CTDB_BASE");
		if (b == NULL) {
			DBG_ERR("CTDB_BASE not set\n");
			return -1;
		}
		ctdb->public_addresses_file = talloc_asprintf(
					ctdb, "%s/%s", b, "public_addresses");
		if (ctdb->public_addresses_file == NULL) {
			DBG_ERR("Out of memory\n");
			return -1;
		}
	}

	/* If the file doesn't exist then warn and do nothing */
	ok = file_exist(ctdb->public_addresses_file);
	if (!ok) {
		D_WARNING("Not loading public addresses, no file %s\n",
			  ctdb->public_addresses_file);
		return 0;
	}

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
		int ret;

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
			D_ERR("No interface specified at line %u "
			      "of public addresses file\n", i+1);
			talloc_free(lines);
			return -1;
		}
		ifaces = tok;

		if (addrstr == NULL) {
			D_ERR("Badly formed line %u in public address list\n",
			      i+1);
			talloc_free(lines);
			return -1;
		}

		ret = ctdb_sock_addr_mask_from_string(addrstr, &addr, &mask);
		if (ret != 0) {
			D_ERR("Badly formed line %u in public address list\n",
			      i+1);
			talloc_free(lines);
			return -1;
		}

		if (ctdb_add_public_address(ctdb, &addr, mask, ifaces, check_addresses)) {
			DEBUG(DEBUG_CRIT,("Failed to add line %u to the public address list\n", i+1));
			talloc_free(lines);
			return -1;
		}
	}


	D_NOTICE("Loaded public addresses from %s\n",
		 ctdb->public_addresses_file);

	talloc_free(lines);
	return 0;
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
 */
int32_t ctdb_control_tcp_client(struct ctdb_context *ctdb, uint32_t client_id,
				TDB_DATA indata)
{
	struct ctdb_client *client = reqid_find(ctdb->idr, client_id, struct ctdb_client);
	struct ctdb_connection *tcp_sock = NULL;
	struct ctdb_tcp_list *tcp;
	struct ctdb_connection t;
	int ret;
	TDB_DATA data;
	struct ctdb_client_ip *ip;
	struct ctdb_vnn *vnn;
	ctdb_sock_addr src_addr;
	ctdb_sock_addr dst_addr;

	/* If we don't have public IPs, tickles are useless */
	if (ctdb->vnn == NULL) {
		return 0;
	}

	tcp_sock = (struct ctdb_connection *)indata.dptr;

	src_addr = tcp_sock->src;
	ctdb_canonicalize_ip(&src_addr,  &tcp_sock->src);
	ZERO_STRUCT(src_addr);
	memcpy(&src_addr, &tcp_sock->src, sizeof(src_addr));

	dst_addr = tcp_sock->dst;
	ctdb_canonicalize_ip(&dst_addr, &tcp_sock->dst);
	ZERO_STRUCT(dst_addr);
	memcpy(&dst_addr, &tcp_sock->dst, sizeof(dst_addr));

	vnn = find_public_ip_vnn(ctdb, &dst_addr);
	if (vnn == NULL) {
		char *src_addr_str = NULL;
		char *dst_addr_str = NULL;

		switch (dst_addr.sa.sa_family) {
		case AF_INET:
			if (ntohl(dst_addr.ip.sin_addr.s_addr) == INADDR_LOOPBACK) {
				/* ignore ... */
				return 0;
			}
			break;
		case AF_INET6:
			break;
		default:
			DEBUG(DEBUG_ERR,(__location__ " Unknown family type %d\n",
			      dst_addr.sa.sa_family));
			return 0;
		}

		src_addr_str = ctdb_sock_addr_to_string(client, &src_addr, false);
		dst_addr_str = ctdb_sock_addr_to_string(client, &dst_addr, false);
		DEBUG(DEBUG_ERR,(
		      "Could not register TCP connection from "
		      "%s to %s (not a public address) (port %u) "
		      "(client_id %u pid %u).\n",
		      src_addr_str,
		      dst_addr_str,
		      ctdb_sock_addr_port(&dst_addr),
		      client_id, client->pid));
		TALLOC_FREE(src_addr_str);
		TALLOC_FREE(dst_addr_str);
		return 0;
	}

	if (vnn->pnn != ctdb->pnn) {
		DEBUG(DEBUG_ERR,("Attempt to register tcp client for IP %s we don't hold - failing (client_id %u pid %u)\n",
			ctdb_addr_to_str(&dst_addr),
			client_id, client->pid));
		/* failing this call will tell smbd to die */
		return -1;
	}

	ip = talloc(client, struct ctdb_client_ip);
	CTDB_NO_MEMORY(ctdb, ip);

	ip->ctdb      = ctdb;
	ip->addr      = dst_addr;
	ip->client_id = client_id;
	talloc_set_destructor(ip, ctdb_client_ip_destructor);
	DLIST_ADD(ctdb->client_ip_list, ip);

	tcp = talloc(client, struct ctdb_tcp_list);
	CTDB_NO_MEMORY(ctdb, tcp);

	tcp->connection.src = tcp_sock->src;
	tcp->connection.dst = tcp_sock->dst;

	DLIST_ADD(client->tcp_list, tcp);

	t.src = tcp_sock->src;
	t.dst = tcp_sock->dst;

	data.dptr = (uint8_t *)&t;
	data.dsize = sizeof(t);

	switch (dst_addr.sa.sa_family) {
	case AF_INET:
		DEBUG(DEBUG_INFO,("registered tcp client for %u->%s:%u (client_id %u pid %u)\n",
			(unsigned)ntohs(tcp_sock->dst.ip.sin_port),
			ctdb_addr_to_str(&tcp_sock->src),
			(unsigned)ntohs(tcp_sock->src.ip.sin_port), client_id, client->pid));
		break;
	case AF_INET6:
		DEBUG(DEBUG_INFO,("registered tcp client for %u->%s:%u (client_id %u pid %u)\n",
			(unsigned)ntohs(tcp_sock->dst.ip6.sin6_port),
			ctdb_addr_to_str(&tcp_sock->src),
			(unsigned)ntohs(tcp_sock->src.ip6.sin6_port), client_id, client->pid));
		break;
	default:
		DEBUG(DEBUG_ERR,(__location__ " Unknown family %d\n",
		      dst_addr.sa.sa_family));
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
static struct ctdb_connection *ctdb_tcp_find(struct ctdb_tcp_array *array,
					   struct ctdb_connection *tcp)
{
	unsigned int i;

	if (array == NULL) {
		return NULL;
	}

	for (i=0;i<array->num;i++) {
		if (ctdb_same_sockaddr(&array->connections[i].src, &tcp->src) &&
		    ctdb_same_sockaddr(&array->connections[i].dst, &tcp->dst)) {
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
	struct ctdb_connection *p = (struct ctdb_connection *)indata.dptr;
	struct ctdb_tcp_array *tcparray;
	struct ctdb_connection tcp;
	struct ctdb_vnn *vnn;

	/* If we don't have public IPs, tickles are useless */
	if (ctdb->vnn == NULL) {
		return 0;
	}

	vnn = find_public_ip_vnn(ctdb, &p->dst);
	if (vnn == NULL) {
		DEBUG(DEBUG_INFO,(__location__ " got TCP_ADD control for an address which is not a public address '%s'\n",
			ctdb_addr_to_str(&p->dst)));

		return -1;
	}


	tcparray = vnn->tcp_array;

	/* If this is the first tickle */
	if (tcparray == NULL) {
		tcparray = talloc(vnn, struct ctdb_tcp_array);
		CTDB_NO_MEMORY(ctdb, tcparray);
		vnn->tcp_array = tcparray;

		tcparray->num = 0;
		tcparray->connections = talloc_size(tcparray, sizeof(struct ctdb_connection));
		CTDB_NO_MEMORY(ctdb, tcparray->connections);

		tcparray->connections[tcparray->num].src = p->src;
		tcparray->connections[tcparray->num].dst = p->dst;
		tcparray->num++;

		if (tcp_update_needed) {
			vnn->tcp_update_needed = true;
		}
		return 0;
	}


	/* Do we already have this tickle ?*/
	tcp.src = p->src;
	tcp.dst = p->dst;
	if (ctdb_tcp_find(tcparray, &tcp) != NULL) {
		DEBUG(DEBUG_DEBUG,("Already had tickle info for %s:%u for vnn:%u\n",
			ctdb_addr_to_str(&tcp.dst),
			ntohs(tcp.dst.ip.sin_port),
			vnn->pnn));
		return 0;
	}

	/* A new tickle, we must add it to the array */
	tcparray->connections = talloc_realloc(tcparray, tcparray->connections,
					struct ctdb_connection,
					tcparray->num+1);
	CTDB_NO_MEMORY(ctdb, tcparray->connections);

	tcparray->connections[tcparray->num].src = p->src;
	tcparray->connections[tcparray->num].dst = p->dst;
	tcparray->num++;

	DEBUG(DEBUG_INFO,("Added tickle info for %s:%u from vnn %u\n",
		ctdb_addr_to_str(&tcp.dst),
		ntohs(tcp.dst.ip.sin_port),
		vnn->pnn));

	if (tcp_update_needed) {
		vnn->tcp_update_needed = true;
	}

	return 0;
}


static void ctdb_remove_connection(struct ctdb_vnn *vnn, struct ctdb_connection *conn)
{
	struct ctdb_connection *tcpp;

	if (vnn == NULL) {
		return;
	}

	/* if the array is empty we cant remove it
	   and we don't need to do anything
	 */
	if (vnn->tcp_array == NULL) {
		DEBUG(DEBUG_INFO,("Trying to remove tickle that doesn't exist (array is empty) %s:%u\n",
			ctdb_addr_to_str(&conn->dst),
			ntohs(conn->dst.ip.sin_port)));
		return;
	}


	/* See if we know this connection
	   if we don't know this connection  then we don't need to do anything
	 */
	tcpp = ctdb_tcp_find(vnn->tcp_array, conn);
	if (tcpp == NULL) {
		DEBUG(DEBUG_INFO,("Trying to remove tickle that doesn't exist %s:%u\n",
			ctdb_addr_to_str(&conn->dst),
			ntohs(conn->dst.ip.sin_port)));
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
		ctdb_addr_to_str(&conn->src),
		ntohs(conn->src.ip.sin_port)));
}


/*
  called by a daemon to inform us of a TCP connection that one of its
  clients used are no longer needed in the tickle database
 */
int32_t ctdb_control_tcp_remove(struct ctdb_context *ctdb, TDB_DATA indata)
{
	struct ctdb_vnn *vnn;
	struct ctdb_connection *conn = (struct ctdb_connection *)indata.dptr;

	/* If we don't have public IPs, tickles are useless */
	if (ctdb->vnn == NULL) {
		return 0;
	}

	vnn = find_public_ip_vnn(ctdb, &conn->dst);
	if (vnn == NULL) {
		DEBUG(DEBUG_ERR,
		      (__location__ " unable to find public address %s\n",
		       ctdb_addr_to_str(&conn->dst)));
		return 0;
	}

	ctdb_remove_connection(vnn, conn);

	return 0;
}


static void ctdb_send_set_tcp_tickles_for_all(struct ctdb_context *ctdb,
					      bool force);

/*
  Called when another daemon starts - causes all tickles for all
  public addresses we are serving to be sent to the new node on the
  next check.  This actually causes the tickles to be sent to the
  other node immediately.  In case there is an error, the periodic
  timer will send the updates on timer event.  This is simple and
  doesn't require careful error handling.
 */
int32_t ctdb_control_startup(struct ctdb_context *ctdb, uint32_t pnn)
{
	DEBUG(DEBUG_INFO, ("Received startup control from node %lu\n",
			   (unsigned long) pnn));

	ctdb_send_set_tcp_tickles_for_all(ctdb, true);
	return 0;
}


/*
  called when a client structure goes away - hook to remove
  elements from the tcp_list in all daemons
 */
void ctdb_takeover_client_destructor_hook(struct ctdb_client *client)
{
	while (client->tcp_list) {
		struct ctdb_vnn *vnn;
		struct ctdb_tcp_list *tcp = client->tcp_list;
		struct ctdb_connection *conn = &tcp->connection;

		DLIST_REMOVE(client->tcp_list, tcp);

		vnn = find_public_ip_vnn(client->ctdb,
					 &conn->dst);
		if (vnn == NULL) {
			DEBUG(DEBUG_ERR,
			      (__location__ " unable to find public address %s\n",
			       ctdb_addr_to_str(&conn->dst)));
			continue;
		}

		/* If the IP address is hosted on this node then
		 * remove the connection. */
		if (vnn->pnn == client->ctdb->pnn) {
			ctdb_remove_connection(vnn, conn);
		}

		/* Otherwise this function has been called because the
		 * server IP address has been released to another node
		 * and the client has exited.  This means that we
		 * should not delete the connection information.  The
		 * takeover node processes connections too. */
	}
}


void ctdb_release_all_ips(struct ctdb_context *ctdb)
{
	struct ctdb_vnn *vnn, *next;
	int count = 0;

	if (ctdb_config.failover_disabled == 1) {
		return;
	}

	for (vnn = ctdb->vnn; vnn != NULL; vnn = next) {
		/* vnn can be freed below in release_ip_post() */
		next = vnn->next;

		if (!ctdb_sys_have_ip(&vnn->public_address)) {
			ctdb_vnn_unassign_iface(ctdb, vnn);
			continue;
		}

		/* Don't allow multiple releases at once.  Some code,
		 * particularly ctdb_tickle_sentenced_connections() is
		 * not re-entrant */
		if (vnn->update_in_flight) {
			DEBUG(DEBUG_WARNING,
			      (__location__
			       " Not releasing IP %s/%u on interface %s, an update is already in progress\n",
				    ctdb_addr_to_str(&vnn->public_address),
				    vnn->public_netmask_bits,
				    ctdb_vnn_iface_string(vnn)));
			continue;
		}
		vnn->update_in_flight = true;

		DEBUG(DEBUG_INFO,("Release of IP %s/%u on interface %s node:-1\n",
				    ctdb_addr_to_str(&vnn->public_address),
				    vnn->public_netmask_bits,
				    ctdb_vnn_iface_string(vnn)));

		ctdb_event_script_args(ctdb, CTDB_EVENT_RELEASE_IP, "%s %s %u",
				       ctdb_vnn_iface_string(vnn),
				       ctdb_addr_to_str(&vnn->public_address),
				       vnn->public_netmask_bits);
		/* releaseip timeouts are converted to success, so to
		 * detect failures just check if the IP address is
		 * still there...
		 */
		if (ctdb_sys_have_ip(&vnn->public_address)) {
			DEBUG(DEBUG_ERR,
			      (__location__
			       " IP address %s not released\n",
			       ctdb_addr_to_str(&vnn->public_address)));
			vnn->update_in_flight = false;
			continue;
		}

		vnn = release_ip_post(ctdb, vnn, &vnn->public_address);
		if (vnn != NULL) {
			vnn->update_in_flight = false;
		}
		count++;
	}

	DEBUG(DEBUG_NOTICE,(__location__ " Released %d public IPs\n", count));
}


/*
  get list of public IPs
 */
int32_t ctdb_control_get_public_ips(struct ctdb_context *ctdb, 
				    struct ctdb_req_control_old *c, TDB_DATA *outdata)
{
	int i, num, len;
	struct ctdb_public_ip_list_old *ips;
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

	len = offsetof(struct ctdb_public_ip_list_old, ips) +
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
	len = offsetof(struct ctdb_public_ip_list_old, ips) +
		i*sizeof(struct ctdb_public_ip);

	outdata->dsize = len;
	outdata->dptr  = (uint8_t *)ips;

	return 0;
}


int32_t ctdb_control_get_public_ip_info(struct ctdb_context *ctdb,
					struct ctdb_req_control_old *c,
					TDB_DATA indata,
					TDB_DATA *outdata)
{
	int i, num, len;
	ctdb_sock_addr *addr;
	struct ctdb_public_ip_info_old *info;
	struct ctdb_vnn *vnn;
	struct vnn_interface *iface;

	addr = (ctdb_sock_addr *)indata.dptr;

	vnn = find_public_ip_vnn(ctdb, addr);
	if (vnn == NULL) {
		DEBUG(DEBUG_ERR,(__location__ " Could not get public ip info, "
				 "'%s'not a public address\n",
				 ctdb_addr_to_str(addr)));
		return -1;
	}

	/* count how many public ip structures we have */
	num = 0;
	for (iface = vnn->ifaces; iface != NULL; iface = iface->next) {
		num++;
	}

	len = offsetof(struct ctdb_public_ip_info_old, ifaces) +
		num*sizeof(struct ctdb_iface);
	info = talloc_zero_size(outdata, len);
	CTDB_NO_MEMORY(ctdb, info);

	info->ip.addr = vnn->public_address;
	info->ip.pnn = vnn->pnn;
	info->active_idx = 0xFFFFFFFF;

	i = 0;
	for (iface = vnn->ifaces; iface != NULL; iface = iface->next) {
		struct ctdb_interface *cur;

		cur = iface->iface;
		if (vnn->iface == cur) {
			info->active_idx = i;
		}
		strncpy(info->ifaces[i].name, cur->name,
			sizeof(info->ifaces[i].name));
		info->ifaces[i].name[sizeof(info->ifaces[i].name)-1] = '\0';
		info->ifaces[i].link_state = cur->link_up;
		info->ifaces[i].references = cur->references;

		i++;
	}
	info->num = i;
	len = offsetof(struct ctdb_public_ip_info_old, ifaces) +
		i*sizeof(struct ctdb_iface);

	outdata->dsize = len;
	outdata->dptr  = (uint8_t *)info;

	return 0;
}

int32_t ctdb_control_get_ifaces(struct ctdb_context *ctdb,
				struct ctdb_req_control_old *c,
				TDB_DATA *outdata)
{
	int i, num, len;
	struct ctdb_iface_list_old *ifaces;
	struct ctdb_interface *cur;

	/* count how many public ip structures we have */
	num = 0;
	for (cur=ctdb->ifaces;cur;cur=cur->next) {
		num++;
	}

	len = offsetof(struct ctdb_iface_list_old, ifaces) +
		num*sizeof(struct ctdb_iface);
	ifaces = talloc_zero_size(outdata, len);
	CTDB_NO_MEMORY(ctdb, ifaces);

	i = 0;
	for (cur=ctdb->ifaces;cur;cur=cur->next) {
		strncpy(ifaces->ifaces[i].name, cur->name,
			sizeof(ifaces->ifaces[i].name));
		ifaces->ifaces[i].name[sizeof(ifaces->ifaces[i].name)-1] = '\0';
		ifaces->ifaces[i].link_state = cur->link_up;
		ifaces->ifaces[i].references = cur->references;
		i++;
	}
	ifaces->num = i;
	len = offsetof(struct ctdb_iface_list_old, ifaces) +
		i*sizeof(struct ctdb_iface);

	outdata->dsize = len;
	outdata->dptr  = (uint8_t *)ifaces;

	return 0;
}

int32_t ctdb_control_set_iface_link(struct ctdb_context *ctdb,
				    struct ctdb_req_control_old *c,
				    TDB_DATA indata)
{
	struct ctdb_iface *info;
	struct ctdb_interface *iface;
	bool link_up = false;

	info = (struct ctdb_iface *)indata.dptr;

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

	DEBUG(DEBUG_ERR,
	      ("iface[%s] has changed it's link status %s => %s\n",
	       iface->name,
	       iface->link_up?"up":"down",
	       link_up?"up":"down"));

	iface->link_up = link_up;
	return 0;
}


/*
  called by a daemon to inform us of the entire list of TCP tickles for
  a particular public address.
  this control should only be sent by the node that is currently serving
  that public address.
 */
int32_t ctdb_control_set_tcp_tickle_list(struct ctdb_context *ctdb, TDB_DATA indata)
{
	struct ctdb_tickle_list_old *list = (struct ctdb_tickle_list_old *)indata.dptr;
	struct ctdb_tcp_array *tcparray;
	struct ctdb_vnn *vnn;

	/* We must at least have tickles.num or else we cant verify the size
	   of the received data blob
	 */
	if (indata.dsize < offsetof(struct ctdb_tickle_list_old, connections)) {
		DEBUG(DEBUG_ERR,("Bad indata in ctdb_tickle_list. Not enough data for the tickle.num field\n"));
		return -1;
	}

	/* verify that the size of data matches what we expect */
	if (indata.dsize < offsetof(struct ctdb_tickle_list_old, connections)
			 + sizeof(struct ctdb_connection) * list->num) {
		DEBUG(DEBUG_ERR,("Bad indata in ctdb_tickle_list\n"));
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

	if (vnn->pnn == ctdb->pnn) {
		DEBUG(DEBUG_INFO,
		      ("Ignoring redundant set tcp tickle list, this node hosts '%s'\n",
		       ctdb_addr_to_str(&list->addr)));
		return 0;
	}

	/* remove any old ticklelist we might have */
	talloc_free(vnn->tcp_array);
	vnn->tcp_array = NULL;

	tcparray = talloc(vnn, struct ctdb_tcp_array);
	CTDB_NO_MEMORY(ctdb, tcparray);

	tcparray->num = list->num;

	tcparray->connections = talloc_array(tcparray, struct ctdb_connection, tcparray->num);
	CTDB_NO_MEMORY(ctdb, tcparray->connections);

	memcpy(tcparray->connections, &list->connections[0],
	       sizeof(struct ctdb_connection)*tcparray->num);

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
	struct ctdb_tickle_list_old *list;
	struct ctdb_tcp_array *tcparray;
	unsigned int num, i;
	struct ctdb_vnn *vnn;
	unsigned port;

	vnn = find_public_ip_vnn(ctdb, addr);
	if (vnn == NULL) {
		DEBUG(DEBUG_ERR,(__location__ " Could not get tcp tickle list, '%s' is not a public address\n",
			ctdb_addr_to_str(addr)));

		return 1;
	}

	port = ctdb_addr_to_port(addr);

	tcparray = vnn->tcp_array;
	num = 0;
	if (tcparray != NULL) {
		if (port == 0) {
			/* All connections */
			num = tcparray->num;
		} else {
			/* Count connections for port */
			for (i = 0; i < tcparray->num; i++) {
				if (port == ctdb_addr_to_port(&tcparray->connections[i].dst)) {
					num++;
				}
			}
		}
	}

	outdata->dsize = offsetof(struct ctdb_tickle_list_old, connections)
			+ sizeof(struct ctdb_connection) * num;

	outdata->dptr  = talloc_size(outdata, outdata->dsize);
	CTDB_NO_MEMORY(ctdb, outdata->dptr);
	list = (struct ctdb_tickle_list_old *)outdata->dptr;

	list->addr = *addr;
	list->num = num;

	if (num == 0) {
		return 0;
	}

	num = 0;
	for (i = 0; i < tcparray->num; i++) {
		if (port == 0 || \
		    port == ctdb_addr_to_port(&tcparray->connections[i].dst)) {
			list->connections[num] = tcparray->connections[i];
			num++;
		}
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
	struct ctdb_tickle_list_old *list;

	if (tcparray) {
		num = tcparray->num;
	} else {
		num = 0;
	}

	data.dsize = offsetof(struct ctdb_tickle_list_old, connections) +
			sizeof(struct ctdb_connection) * num;
	data.dptr = talloc_size(ctdb, data.dsize);
	CTDB_NO_MEMORY(ctdb, data.dptr);

	list = (struct ctdb_tickle_list_old *)data.dptr;
	list->addr = *addr;
	list->num = num;
	if (tcparray) {
		memcpy(&list->connections[0], tcparray->connections, sizeof(struct ctdb_connection) * num);
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

static void ctdb_send_set_tcp_tickles_for_all(struct ctdb_context *ctdb,
					      bool force)
{
	struct ctdb_vnn *vnn;
	int ret;

	for (vnn = ctdb->vnn; vnn != NULL; vnn = vnn->next) {
		/* we only send out updates for public addresses that
		   we have taken over
		 */
		if (ctdb->pnn != vnn->pnn) {
			continue;
		}

		/* We only send out the updates if we need to */
		if (!force && !vnn->tcp_update_needed) {
			continue;
		}

		ret = ctdb_send_set_tcp_tickles_for_ip(ctdb,
						       &vnn->public_address,
						       vnn->tcp_array);
		if (ret != 0) {
			D_ERR("Failed to send the tickle update for ip %s\n",
			      ctdb_addr_to_str(&vnn->public_address));
			vnn->tcp_update_needed = true;
		} else {
			D_INFO("Sent tickle update for ip %s\n",
			       ctdb_addr_to_str(&vnn->public_address));
			vnn->tcp_update_needed = false;
		}
	}

}

/*
  perform tickle updates if required
 */
static void ctdb_update_tcp_tickles(struct tevent_context *ev,
				    struct tevent_timer *te,
				    struct timeval t, void *private_data)
{
	struct ctdb_context *ctdb = talloc_get_type(
		private_data, struct ctdb_context);

	ctdb_send_set_tcp_tickles_for_all(ctdb, false);

	tevent_add_timer(ctdb->ev, ctdb->tickle_update_context,
			 timeval_current_ofs(ctdb->tunable.tickle_update_interval, 0),
			 ctdb_update_tcp_tickles, ctdb);
}

/*
  start periodic update of tcp tickles
 */
void ctdb_start_tcp_tickle_update(struct ctdb_context *ctdb)
{
	ctdb->tickle_update_context = talloc_new(ctdb);

	tevent_add_timer(ctdb->ev, ctdb->tickle_update_context,
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
static void send_gratious_arp(struct tevent_context *ev,
			      struct tevent_timer *te,
			      struct timeval t, void *private_data)
{
	int ret;
	struct control_gratious_arp *arp = talloc_get_type(private_data, 
							struct control_gratious_arp);

	ret = ctdb_sys_send_arp(&arp->addr, arp->iface);
	if (ret != 0) {
		DBG_ERR("Failed to send gratuitous ARP on iface %s: %s\n",
			arp->iface, strerror(ret));
	}


	arp->count++;
	if (arp->count == CTDB_ARP_REPEAT) {
		talloc_free(arp);
		return;
	}

	tevent_add_timer(arp->ctdb->ev, arp,
			 timeval_current_ofs(CTDB_ARP_INTERVAL, 0),
			 send_gratious_arp, arp);
}


/*
  send a gratious arp 
 */
int32_t ctdb_control_send_gratious_arp(struct ctdb_context *ctdb, TDB_DATA indata)
{
	struct ctdb_addr_info_old *gratious_arp = (struct ctdb_addr_info_old *)indata.dptr;
	struct control_gratious_arp *arp;

	/* verify the size of indata */
	if (indata.dsize < offsetof(struct ctdb_addr_info_old, iface)) {
		DEBUG(DEBUG_ERR,(__location__ " Too small indata to hold a ctdb_control_gratious_arp structure. Got %u require %u bytes\n", 
				 (unsigned)indata.dsize, 
				 (unsigned)offsetof(struct ctdb_addr_info_old, iface)));
		return -1;
	}
	if (indata.dsize != 
		( offsetof(struct ctdb_addr_info_old, iface)
		+ gratious_arp->len ) ){

		DEBUG(DEBUG_ERR,(__location__ " Wrong size of indata. Was %u bytes "
			"but should be %u bytes\n", 
			 (unsigned)indata.dsize, 
			 (unsigned)(offsetof(struct ctdb_addr_info_old, iface)+gratious_arp->len)));
		return -1;
	}


	arp = talloc(ctdb, struct control_gratious_arp);
	CTDB_NO_MEMORY(ctdb, arp);

	arp->ctdb  = ctdb;
	arp->addr   = gratious_arp->addr;
	arp->iface = talloc_strdup(arp, gratious_arp->iface);
	CTDB_NO_MEMORY(ctdb, arp->iface);
	arp->count = 0;

	tevent_add_timer(arp->ctdb->ev, arp,
			 timeval_zero(), send_gratious_arp, arp);

	return 0;
}

int32_t ctdb_control_add_public_address(struct ctdb_context *ctdb, TDB_DATA indata)
{
	struct ctdb_addr_info_old *pub = (struct ctdb_addr_info_old *)indata.dptr;
	int ret;

	/* verify the size of indata */
	if (indata.dsize < offsetof(struct ctdb_addr_info_old, iface)) {
		DEBUG(DEBUG_ERR,(__location__ " Too small indata to hold a ctdb_addr_info structure\n"));
		return -1;
	}
	if (indata.dsize != 
		( offsetof(struct ctdb_addr_info_old, iface)
		+ pub->len ) ){

		DEBUG(DEBUG_ERR,(__location__ " Wrong size of indata. Was %u bytes "
			"but should be %u bytes\n", 
			 (unsigned)indata.dsize, 
			 (unsigned)(offsetof(struct ctdb_addr_info_old, iface)+pub->len)));
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

int32_t ctdb_control_del_public_address(struct ctdb_context *ctdb, TDB_DATA indata)
{
	struct ctdb_addr_info_old *pub = (struct ctdb_addr_info_old *)indata.dptr;
	struct ctdb_vnn *vnn;

	/* verify the size of indata */
	if (indata.dsize < offsetof(struct ctdb_addr_info_old, iface)) {
		DEBUG(DEBUG_ERR,(__location__ " Too small indata to hold a ctdb_addr_info structure\n"));
		return -1;
	}
	if (indata.dsize != 
		( offsetof(struct ctdb_addr_info_old, iface)
		+ pub->len ) ){

		DEBUG(DEBUG_ERR,(__location__ " Wrong size of indata. Was %u bytes "
			"but should be %u bytes\n", 
			 (unsigned)indata.dsize, 
			 (unsigned)(offsetof(struct ctdb_addr_info_old, iface)+pub->len)));
		return -1;
	}

	DEBUG(DEBUG_NOTICE,("Delete IP %s\n", ctdb_addr_to_str(&pub->addr)));

	/* walk over all public addresses until we find a match */
	for (vnn=ctdb->vnn;vnn;vnn=vnn->next) {
		if (ctdb_same_ip(&vnn->public_address, &pub->addr)) {
			if (vnn->pnn == ctdb->pnn) {
				/* This IP is currently being hosted.
				 * Defer the deletion until the next
				 * takeover run. "ctdb reloadips" will
				 * always cause a takeover run.  "ctdb
				 * delip" will now need an explicit
				 * "ctdb ipreallocated" afterwards. */
				vnn->delete_pending = true;
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
	struct ctdb_req_control_old *c;
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
		if (status == -ETIMEDOUT) {
			ctdb_ban_self(ctdb);
		}
	}

	ctdb_request_control_reply(ctdb, state->c, NULL, status, NULL);
	talloc_free(state);
}

/* A control to run the ipreallocated event */
int32_t ctdb_control_ipreallocated(struct ctdb_context *ctdb,
				   struct ctdb_req_control_old *c,
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


struct ctdb_reloadips_handle {
	struct ctdb_context *ctdb;
	struct ctdb_req_control_old *c;
	int status;
	int fd[2];
	pid_t child;
	struct tevent_fd *fde;
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

static void ctdb_reloadips_timeout_event(struct tevent_context *ev,
					 struct tevent_timer *te,
					 struct timeval t, void *private_data)
{
	struct ctdb_reloadips_handle *h = talloc_get_type(private_data, struct ctdb_reloadips_handle);

	talloc_free(h);
}

static void ctdb_reloadips_child_handler(struct tevent_context *ev,
					 struct tevent_fd *fde,
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
	struct ctdb_public_ip_list_old *ips;
	struct ctdb_vnn *vnn;
	struct client_async_data *async_data;
	struct timeval timeout;
	TDB_DATA data;
	struct ctdb_client_control_state *state;
	bool first_add;
	unsigned int i;
	int ret;

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
			struct ctdb_addr_info_old *pub;

			DEBUG(DEBUG_NOTICE,
			      ("IP %s no longer configured, deleting it\n",
			       ctdb_addr_to_str(&ips->ips[i].addr)));

			pub = talloc_zero(mem_ctx, struct ctdb_addr_info_old);
			CTDB_NO_MEMORY(ctdb, pub);

			pub->addr  = ips->ips[i].addr;
			pub->mask  = 0;
			pub->len   = 0;

			timeout = TAKEOVER_TIMEOUT();

			data.dsize = offsetof(struct ctdb_addr_info_old,
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
			struct ctdb_addr_info_old *pub;
			const char *ifaces = NULL;
			uint32_t len;
			struct vnn_interface *iface = NULL;

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

			ifaces = vnn->ifaces->iface->name;
			iface = vnn->ifaces->next;
			while (iface != NULL) {
				ifaces = talloc_asprintf(vnn, "%s,%s", ifaces,
							 iface->iface->name);
				iface = iface->next;
			}

			len   = strlen(ifaces) + 1;
			pub = talloc_zero_size(mem_ctx,
					       offsetof(struct ctdb_addr_info_old, iface) + len);
			CTDB_NO_MEMORY(ctdb, pub);

			pub->addr  = vnn->public_address;
			pub->mask  = vnn->public_netmask_bits;
			pub->len   = len;
			memcpy(&pub->iface[0], ifaces, pub->len);

			timeout = TAKEOVER_TIMEOUT();

			data.dsize = offsetof(struct ctdb_addr_info_old,
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
int32_t ctdb_control_reload_public_ips(struct ctdb_context *ctdb, struct ctdb_req_control_old *c, bool *async_reply)
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

		prctl_set_comment("ctdb_reloadips");
		if (switch_from_server_to_client(ctdb) != 0) {
			DEBUG(DEBUG_CRIT,("ERROR: Failed to switch reloadips child into client mode\n"));
			res = -1;
		} else {
			res = ctdb_reloadips_child(ctdb);
			if (res != 0) {
				DEBUG(DEBUG_ERR,("Failed to reload ips on local node\n"));
			}
		}

		sys_write(h->fd[1], &res, 1);
		ctdb_wait_for_process_to_exit(parent);
		_exit(0);
	}

	h->c             = talloc_steal(h, c);

	close(h->fd[1]);
	set_close_on_exec(h->fd[0]);

	talloc_set_destructor(h, ctdb_reloadips_destructor);


	h->fde = tevent_add_fd(ctdb->ev, h, h->fd[0], TEVENT_FD_READ,
			       ctdb_reloadips_child_handler, (void *)h);
	tevent_fd_set_auto_close(h->fde);

	tevent_add_timer(ctdb->ev, h, timeval_current_ofs(120, 0),
			 ctdb_reloadips_timeout_event, h);

	/* we reply later */
	*async_reply = true;
	return 0;
}
