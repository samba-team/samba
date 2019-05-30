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

#include <talloc.h>

#include "lib/util/debug.h"

#include "common/logging.h"
#include "common/rb_tree.h"

#include "protocol/protocol_util.h"

#include "server/ipalloc_private.h"

/* Initialise main ipalloc state and sub-structures */
struct ipalloc_state *
ipalloc_state_init(TALLOC_CTX *mem_ctx,
		   uint32_t num_nodes,
		   enum ipalloc_algorithm algorithm,
		   bool no_ip_takeover,
		   bool no_ip_failback,
		   uint32_t *force_rebalance_nodes)
{
	struct ipalloc_state *ipalloc_state =
		talloc_zero(mem_ctx, struct ipalloc_state);
	if (ipalloc_state == NULL) {
		DEBUG(DEBUG_ERR, (__location__ " Out of memory\n"));
		return NULL;
	}

	ipalloc_state->num = num_nodes;

	ipalloc_state->algorithm = algorithm;
	ipalloc_state->no_ip_takeover = no_ip_takeover;
	ipalloc_state->no_ip_failback = no_ip_failback;
	ipalloc_state->force_rebalance_nodes = force_rebalance_nodes;

	return ipalloc_state;
}

static void *add_ip_callback(void *parm, void *data)
{
	struct public_ip_list *this_ip = parm;
	struct public_ip_list *prev_ip = data;

	if (prev_ip == NULL) {
		return parm;
	}
	if (this_ip->pnn == CTDB_UNKNOWN_PNN) {
		this_ip->pnn = prev_ip->pnn;
	}

	return parm;
}

static int getips_count_callback(void *param, void *data)
{
	struct public_ip_list **ip_list = (struct public_ip_list **)param;
	struct public_ip_list *new_ip = (struct public_ip_list *)data;

	new_ip->next = *ip_list;
	*ip_list     = new_ip;
	return 0;
}

/* Nodes only know about those public addresses that they are
 * configured to serve and no individual node has a full list of all
 * public addresses configured across the cluster.  Therefore, a
 * merged list of all public addresses needs to be built so that IP
 * allocation can be done. */
static struct public_ip_list *
create_merged_ip_list(struct ipalloc_state *ipalloc_state)
{
	unsigned int i, j;
	struct public_ip_list *ip_list;
	struct ctdb_public_ip_list *public_ips;
	struct trbt_tree *ip_tree;

	ip_tree = trbt_create(ipalloc_state, 0);

	if (ipalloc_state->known_public_ips == NULL) {
		DEBUG(DEBUG_ERR, ("Known public IPs not set\n"));
		return NULL;
	}

	for (i=0; i < ipalloc_state->num; i++) {

		public_ips = &ipalloc_state->known_public_ips[i];

		for (j=0; j < public_ips->num; j++) {
			struct public_ip_list *tmp_ip;

			/* This is returned as part of ip_list */
			tmp_ip = talloc_zero(ipalloc_state, struct public_ip_list);
			if (tmp_ip == NULL) {
				DEBUG(DEBUG_ERR,
				      (__location__ " out of memory\n"));
				talloc_free(ip_tree);
				return NULL;
			}

			/* Do not use information about IP addresses hosted
			 * on other nodes, it may not be accurate */
			if (public_ips->ip[j].pnn == i) {
				tmp_ip->pnn = public_ips->ip[j].pnn;
			} else {
				tmp_ip->pnn = CTDB_UNKNOWN_PNN;
			}
			tmp_ip->addr = public_ips->ip[j].addr;
			tmp_ip->next = NULL;

			trbt_insertarray32_callback(ip_tree,
				IP_KEYLEN, ip_key(&public_ips->ip[j].addr),
				add_ip_callback,
				tmp_ip);
		}
	}

	ip_list = NULL;
	trbt_traversearray32(ip_tree, IP_KEYLEN, getips_count_callback, &ip_list);
	talloc_free(ip_tree);

	return ip_list;
}

static bool populate_bitmap(struct ipalloc_state *ipalloc_state)
{
	struct public_ip_list *ip = NULL;
	unsigned int i, j;

	for (ip = ipalloc_state->all_ips; ip != NULL; ip = ip->next) {

		ip->known_on = bitmap_talloc(ip, ipalloc_state->num);
		if (ip->known_on == NULL) {
			return false;
		}

		ip->available_on = bitmap_talloc(ip, ipalloc_state->num);
		if (ip->available_on == NULL) {
			return false;
		}

		for (i = 0; i < ipalloc_state->num; i++) {
			struct ctdb_public_ip_list *known =
				&ipalloc_state->known_public_ips[i];
			struct ctdb_public_ip_list *avail =
				&ipalloc_state->available_public_ips[i];

			/* Check to see if "ip" is available on node "i" */
			for (j = 0; j < avail->num; j++) {
				if (ctdb_sock_addr_same_ip(
					    &ip->addr, &avail->ip[j].addr)) {
					bitmap_set(ip->available_on, i);
					break;
				}
			}

			/* Optimisation: available => known */
			if (bitmap_query(ip->available_on, i)) {
				bitmap_set(ip->known_on, i);
				continue;
			}

			/* Check to see if "ip" is known on node "i" */
			for (j = 0; j < known->num; j++) {
				if (ctdb_sock_addr_same_ip(
					    &ip->addr, &known->ip[j].addr)) {
					bitmap_set(ip->known_on, i);
					break;
				}
			}
		}
	}

	return true;
}

void ipalloc_set_public_ips(struct ipalloc_state *ipalloc_state,
			    struct ctdb_public_ip_list *known_ips,
			    struct ctdb_public_ip_list *available_ips)
{
	ipalloc_state->available_public_ips = available_ips;
	ipalloc_state->known_public_ips = known_ips;
}

/* This can only return false if there are no available IPs *and*
 * there are no IP addresses currently allocated.  If the latter is
 * true then the cluster can clearly host IPs... just not necessarily
 * right now... */
bool ipalloc_can_host_ips(struct ipalloc_state *ipalloc_state)
{
	unsigned int i;
	bool have_ips = false;

	for (i=0; i < ipalloc_state->num; i++) {
		struct ctdb_public_ip_list *ips =
			ipalloc_state->known_public_ips;
		if (ips[i].num != 0) {
			unsigned int j;
			have_ips = true;
			/* Succeed if an address is hosted on node i */
			for (j=0; j < ips[i].num; j++) {
				if (ips[i].ip[j].pnn == i) {
					return true;
				}
			}
		}
	}

	if (! have_ips) {
		return false;
	}

	/* At this point there are known addresses but none are
	 * hosted.  Need to check if cluster can now host some
	 * addresses.
	 */
	for (i=0; i < ipalloc_state->num; i++) {
		if (ipalloc_state->available_public_ips[i].num != 0) {
			return true;
		}
	}

	return false;
}

/* The calculation part of the IP allocation algorithm. */
struct public_ip_list *ipalloc(struct ipalloc_state *ipalloc_state)
{
	bool ret = false;

	ipalloc_state->all_ips = create_merged_ip_list(ipalloc_state);
	if (ipalloc_state->all_ips == NULL) {
		return NULL;
	}

	if (!populate_bitmap(ipalloc_state)) {
		return NULL;
	}

	switch (ipalloc_state->algorithm) {
	case IPALLOC_LCP2:
		ret = ipalloc_lcp2(ipalloc_state);
		break;
	case IPALLOC_DETERMINISTIC:
		ret = ipalloc_deterministic(ipalloc_state);
		break;
	case IPALLOC_NONDETERMINISTIC:
		ret = ipalloc_nondeterministic(ipalloc_state);
               break;
	}

	/* at this point ->pnn is the node which will own each IP
	   or CTDB_UNKNOWN_PNN if there is no node that can cover this ip
	*/

	return (ret ? ipalloc_state->all_ips : NULL);
}
