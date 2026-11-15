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
#include "lib/util/rbtree.h"

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

/*
 * Order IP addresses by ip_key(), comparing 32-bit words from the
 * start of the key
 */
static int ip_key_cmp(ctdb_sock_addr *ip1, ctdb_sock_addr *ip2)
{
	uint32_t k1[IP_KEYLEN];
	uint32_t *k2 = NULL;
	unsigned int i;

	/* ip_key() returns a static buffer */
	memcpy(k1, ip_key(ip1), sizeof(k1));
	k2 = ip_key(ip2);

	for (i = 0; i < IP_KEYLEN; i++) {
		if (k1[i] < k2[i]) {
			return -1;
		}
		if (k1[i] > k2[i]) {
			return 1;
		}
	}

	return 0;
}

struct merged_ip {
	struct rb_node rb;
	struct public_ip_list *ip;
};

static struct merged_ip *merged_ip_from_rb(struct rb_node *rb)
{
	void *p = (char *)rb - offsetof(struct merged_ip, rb);

	return (struct merged_ip *)p;
}

/*
 * Return the entry for addr in tree, adding a new one if the address
 * has not been seen before
 */
static struct public_ip_list *merged_ip_lookup_add(TALLOC_CTX *mem_ctx,
						   TALLOC_CTX *tree_ctx,
						   struct rb_root *tree,
						   ctdb_sock_addr *addr)
{
	struct rb_node **p = &tree->rb_node;
	struct rb_node *parent = NULL;
	struct merged_ip *m = NULL;

	while (*p != NULL) {
		int cmp;

		parent = *p;
		m = merged_ip_from_rb(parent);

		cmp = ip_key_cmp(addr, &m->ip->addr);
		if (cmp < 0) {
			p = &parent->rb_left;
		} else if (cmp > 0) {
			p = &parent->rb_right;
		} else {
			return m->ip;
		}
	}

	m = talloc_zero(tree_ctx, struct merged_ip);
	if (m == NULL) {
		return NULL;
	}

	/* This is returned as part of ip_list */
	m->ip = talloc_zero(mem_ctx, struct public_ip_list);
	if (m->ip == NULL) {
		return NULL;
	}

	m->ip->addr = *addr;
	m->ip->pnn = CTDB_UNKNOWN_PNN;

	rb_link_node(&m->rb, parent, p);
	rb_insert_color(&m->rb, tree);

	return m->ip;
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
	struct public_ip_list *ip_list = NULL;
	struct ctdb_public_ip_list *public_ips;
	TALLOC_CTX *tree_ctx = NULL;
	struct rb_root tree = RB_ROOT;
	struct rb_node *rb = NULL;

	if (ipalloc_state->known_public_ips == NULL) {
		D_ERR("Known public IPs not set\n");
		return NULL;
	}

	tree_ctx = talloc_new(ipalloc_state);
	if (tree_ctx == NULL) {
		DBG_ERR("Out of memory\n");
		return NULL;
	}

	for (i=0; i < ipalloc_state->num; i++) {

		public_ips = &ipalloc_state->known_public_ips[i];

		for (j=0; j < public_ips->num; j++) {
			struct ctdb_public_ip *pip = &public_ips->ip[j];
			struct public_ip_list *ip = NULL;

			ip = merged_ip_lookup_add(ipalloc_state,
						  tree_ctx,
						  &tree,
						  &pip->addr);
			if (ip == NULL) {
				DBG_ERR("Out of memory\n");
				talloc_free(tree_ctx);
				return NULL;
			}

			/* Do not use information about IP addresses hosted
			 * on other nodes, it may not be accurate */
			if (pip->pnn == i) {
				if (ip->pnn != CTDB_UNKNOWN_PNN) {
					/* An earlier node also hosts it */
					ip->multiple_claims = true;
				}
				ip->pnn = pip->pnn;
			}
		}
	}

	/*
	 * Prepending reverses the order.  This matters because the
	 * result of deterministic IP allocation depends on it.
	 */
	for (rb = rb_first(&tree); rb != NULL; rb = rb_next(rb)) {
		struct public_ip_list *ip = merged_ip_from_rb(rb)->ip;

		ip->next = ip_list;
		ip_list = ip;
	}

	talloc_free(tree_ctx);

	return ip_list;
}

static uint32_t *setup_prev(struct ipalloc_state *ipalloc_state)
{
	uint32_t *prev = NULL;
	struct public_ip_list *ip = NULL;
	unsigned int i = 0;

	for (ip = ipalloc_state->all_ips; ip != NULL; ip = ip->next) {
		i++;
	}

	prev = talloc_array(ipalloc_state, uint32_t, i);
	if (prev == NULL) {
		return NULL;
	}

	i = 0;
	for (ip = ipalloc_state->all_ips; ip != NULL; ip = ip->next) {
		prev[i] = ip->pnn;
		i++;
	}

	return prev;
}

static unsigned int compare_with_prev(struct ipalloc_state *ipalloc_state,
				      uint32_t *prev)
{
	struct public_ip_list *ip = NULL;
	unsigned int i = 0;
	unsigned int num_changed = 0;

	for (ip = ipalloc_state->all_ips; ip != NULL; ip = ip->next) {
		/*
		 * An IP hosted by multiple nodes will be released from
		 * at least one of them
		 */
		if (ip->multiple_claims || prev[i] != ip->pnn) {
			num_changed++;
		}
		i++;
	}

	return num_changed;
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
struct public_ip_list *ipalloc(struct ipalloc_state *ipalloc_state,
			       unsigned int *num_changed)
{
	bool status = false;
	struct public_ip_list *ret = NULL;
	uint32_t *prev = NULL;

	ipalloc_state->all_ips = create_merged_ip_list(ipalloc_state);
	if (ipalloc_state->all_ips == NULL) {
		goto done;
	}

	if (num_changed != NULL) {
		prev = setup_prev(ipalloc_state);
		if (prev == NULL) {
			goto done;
		}
	}

	if (!populate_bitmap(ipalloc_state)) {
		goto done;
	}

	switch (ipalloc_state->algorithm) {
	case IPALLOC_LCP2:
		status = ipalloc_lcp2(ipalloc_state);
		break;
	case IPALLOC_DETERMINISTIC:
		status = ipalloc_deterministic(ipalloc_state);
		break;
	case IPALLOC_NONDETERMINISTIC:
		status = ipalloc_nondeterministic(ipalloc_state);
		break;
	}

	if (!status) {
		goto done;
	}

	/*
	 * At this point ->pnn is the node to which an IP is allocated or
	 * CTDB_UNKNOWN_PNN if there is no node that can cover an ip
	 */
	ret = ipalloc_state->all_ips;

	if (num_changed != NULL) {
		*num_changed = compare_with_prev(ipalloc_state, prev);
	}

done:
	talloc_free(prev);
	return ret;
}
