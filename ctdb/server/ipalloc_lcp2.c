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

#include "lib/util/debug.h"
#include "common/logging.h"

#include "protocol/protocol_util.h"

#include "server/ipalloc_private.h"

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
			while ((x & ((uint32_t)1 << 31)) == 0) {
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
				  struct public_ip_list *ips,
				  unsigned int pnn)
{
	struct public_ip_list *t;
	uint32_t d;

	uint32_t sum = 0;

	for (t = ips; t != NULL; t = t->next) {
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
static uint32_t lcp2_imbalance(struct public_ip_list * all_ips,
			       unsigned int pnn)
{
	struct public_ip_list *t;

	uint32_t imbalance = 0;

	for (t = all_ips; t != NULL; t = t->next) {
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

static bool lcp2_init(struct ipalloc_state *ipalloc_state,
		      uint32_t **lcp2_imbalances,
		      bool **rebalance_candidates)
{
	unsigned int i, numnodes;
	struct public_ip_list *t;

	numnodes = ipalloc_state->num;

	*rebalance_candidates = talloc_array(ipalloc_state, bool, numnodes);
	if (*rebalance_candidates == NULL) {
		DEBUG(DEBUG_ERR, (__location__ " out of memory\n"));
		return false;
	}
	*lcp2_imbalances = talloc_array(ipalloc_state, uint32_t, numnodes);
	if (*lcp2_imbalances == NULL) {
		DEBUG(DEBUG_ERR, (__location__ " out of memory\n"));
		return false;
	}

	for (i=0; i<numnodes; i++) {
		(*lcp2_imbalances)[i] =
			lcp2_imbalance(ipalloc_state->all_ips, i);
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
	for (t = ipalloc_state->all_ips; t != NULL; t = t->next) {
		if (t->pnn != CTDB_UNKNOWN_PNN) {
			(*rebalance_candidates)[t->pnn] = false;
		}
	}

	/* 3rd step: if a node is forced to re-balance then
	   we allow failback onto the node */
	if (ipalloc_state->force_rebalance_nodes == NULL) {
		return true;
	}
	for (i = 0;
	     i < talloc_array_length(ipalloc_state->force_rebalance_nodes);
	     i++) {
		uint32_t pnn = ipalloc_state->force_rebalance_nodes[i];
		if (pnn >= numnodes) {
			DEBUG(DEBUG_ERR,
			      (__location__ "unknown node %u\n", pnn));
			continue;
		}

		DEBUG(DEBUG_NOTICE,
		      ("Forcing rebalancing of IPs to node %u\n", pnn));
		(*rebalance_candidates)[pnn] = true;
	}

	return true;
}

/* Allocate any unassigned addresses using the LCP2 algorithm to find
 * the IP/node combination that will cost the least.
 */
static void lcp2_allocate_unassigned(struct ipalloc_state *ipalloc_state,
				     uint32_t *lcp2_imbalances)
{
	struct public_ip_list *t;
	unsigned int dstnode, numnodes;

	unsigned int minnode;
	uint32_t mindsum, dstdsum, dstimbl;
	uint32_t minimbl = 0;
	struct public_ip_list *minip;

	bool should_loop = true;
	bool have_unassigned = true;

	numnodes = ipalloc_state->num;

	while (have_unassigned && should_loop) {
		should_loop = false;

		DEBUG(DEBUG_DEBUG,(" ----------------------------------------\n"));
		DEBUG(DEBUG_DEBUG,(" CONSIDERING MOVES (UNASSIGNED)\n"));

		minnode = CTDB_UNKNOWN_PNN;
		mindsum = 0;
		minip = NULL;

		/* loop over each unassigned ip. */
		for (t = ipalloc_state->all_ips; t != NULL ; t = t->next) {
			if (t->pnn != CTDB_UNKNOWN_PNN) {
				continue;
			}

			for (dstnode = 0; dstnode < numnodes; dstnode++) {
				/* only check nodes that can actually takeover this ip */
				if (!can_node_takeover_ip(ipalloc_state,
							  dstnode,
							  t)) {
					/* no it couldnt   so skip to the next node */
					continue;
				}

				dstdsum = ip_distance_2_sum(&(t->addr),
							    ipalloc_state->all_ips,
							    dstnode);
				dstimbl = lcp2_imbalances[dstnode] + dstdsum;
				DEBUG(DEBUG_DEBUG,
				      (" %s -> %d [+%d]\n",
				       ctdb_sock_addr_to_string(ipalloc_state,
								&(t->addr),
								false),
				       dstnode,
				       dstimbl - lcp2_imbalances[dstnode]));


				if (minnode == CTDB_UNKNOWN_PNN ||
				    dstdsum < mindsum) {
					minnode = dstnode;
					minimbl = dstimbl;
					mindsum = dstdsum;
					minip = t;
					should_loop = true;
				}
			}
		}

		DEBUG(DEBUG_DEBUG,(" ----------------------------------------\n"));

		/* If we found one then assign it to the given node. */
		if (minnode != CTDB_UNKNOWN_PNN) {
			minip->pnn = minnode;
			lcp2_imbalances[minnode] = minimbl;
			DEBUG(DEBUG_INFO,(" %s -> %d [+%d]\n",
					  ctdb_sock_addr_to_string(
						  ipalloc_state,
						  &(minip->addr), false),
					  minnode,
					  mindsum));
		}

		/* There might be a better way but at least this is clear. */
		have_unassigned = false;
		for (t = ipalloc_state->all_ips; t != NULL; t = t->next) {
			if (t->pnn == CTDB_UNKNOWN_PNN) {
				have_unassigned = true;
			}
		}
	}

	/* We know if we have an unassigned addresses so we might as
	 * well optimise.
	 */
	if (have_unassigned) {
		for (t = ipalloc_state->all_ips; t != NULL; t = t->next) {
			if (t->pnn == CTDB_UNKNOWN_PNN) {
				DEBUG(DEBUG_WARNING,
				      ("Failed to find node to cover ip %s\n",
				       ctdb_sock_addr_to_string(ipalloc_state,
								&t->addr,
								false)));
			}
		}
	}
}

/* LCP2 algorithm for rebalancing the cluster.  Given a candidate node
 * to move IPs from, determines the best IP/destination node
 * combination to move from the source node.
 */
static bool lcp2_failback_candidate(struct ipalloc_state *ipalloc_state,
				    unsigned int srcnode,
				    uint32_t *lcp2_imbalances,
				    bool *rebalance_candidates)
{
	unsigned int dstnode, mindstnode, numnodes;
	uint32_t srcdsum, dstimbl, dstdsum;
	uint32_t minsrcimbl, mindstimbl;
	struct public_ip_list *minip;
	struct public_ip_list *t;

	/* Find an IP and destination node that best reduces imbalance. */
	minip = NULL;
	minsrcimbl = 0;
	mindstnode = CTDB_UNKNOWN_PNN;
	mindstimbl = 0;

	numnodes = ipalloc_state->num;

	DEBUG(DEBUG_DEBUG,(" ----------------------------------------\n"));
	DEBUG(DEBUG_DEBUG,(" CONSIDERING MOVES FROM %d [%d]\n",
			   srcnode, lcp2_imbalances[srcnode]));

	for (t = ipalloc_state->all_ips; t != NULL; t = t->next) {
		uint32_t srcimbl;

		/* Only consider addresses on srcnode. */
		if (t->pnn != srcnode) {
			continue;
		}

		/* What is this IP address costing the source node? */
		srcdsum = ip_distance_2_sum(&(t->addr),
					    ipalloc_state->all_ips,
					    srcnode);
		srcimbl = lcp2_imbalances[srcnode] - srcdsum;

		/* Consider this IP address would cost each potential
		 * destination node.  Destination nodes are limited to
		 * those that are newly healthy, since we don't want
		 * to do gratuitous failover of IPs just to make minor
		 * balance improvements.
		 */
		for (dstnode = 0; dstnode < numnodes; dstnode++) {
			if (!rebalance_candidates[dstnode]) {
				continue;
			}

			/* only check nodes that can actually takeover this ip */
			if (!can_node_takeover_ip(ipalloc_state, dstnode,
						  t)) {
				/* no it couldnt   so skip to the next node */
				continue;
			}

			dstdsum = ip_distance_2_sum(&(t->addr),
						    ipalloc_state->all_ips,
						    dstnode);
			dstimbl = lcp2_imbalances[dstnode] + dstdsum;
			DEBUG(DEBUG_DEBUG,(" %d [%d] -> %s -> %d [+%d]\n",
					   srcnode, -srcdsum,
					   ctdb_sock_addr_to_string(
						   ipalloc_state,
						   &(t->addr), false),
					   dstnode, dstdsum));

			if ((dstimbl < lcp2_imbalances[srcnode]) &&
			    (dstdsum < srcdsum) &&			\
			    ((mindstnode == CTDB_UNKNOWN_PNN) ||				\
			     ((srcimbl + dstimbl) < (minsrcimbl + mindstimbl)))) {

				minip = t;
				minsrcimbl = srcimbl;
				mindstnode = dstnode;
				mindstimbl = dstimbl;
			}
		}
	}
	DEBUG(DEBUG_DEBUG,(" ----------------------------------------\n"));

        if (mindstnode != CTDB_UNKNOWN_PNN) {
		/* We found a move that makes things better... */
		DEBUG(DEBUG_INFO,
		      ("%d [%d] -> %s -> %d [+%d]\n",
		       srcnode, minsrcimbl - lcp2_imbalances[srcnode],
		       ctdb_sock_addr_to_string(ipalloc_state,
						&(minip->addr), false),
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
	unsigned int pnn;
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
static void lcp2_failback(struct ipalloc_state *ipalloc_state,
			  uint32_t *lcp2_imbalances,
			  bool *rebalance_candidates)
{
	int i, numnodes;
	struct lcp2_imbalance_pnn * lips;
	bool again;

	numnodes = ipalloc_state->num;

try_again:
	/* Put the imbalances and nodes into an array, sort them and
	 * iterate through candidates.  Usually the 1st one will be
	 * used, so this doesn't cost much...
	 */
	DEBUG(DEBUG_DEBUG,("+++++++++++++++++++++++++++++++++++++++++\n"));
	DEBUG(DEBUG_DEBUG,("Selecting most imbalanced node from:\n"));
	lips = talloc_array(ipalloc_state, struct lcp2_imbalance_pnn, numnodes);
	for (i = 0; i < numnodes; i++) {
		lips[i].imbalance = lcp2_imbalances[i];
		lips[i].pnn = i;
		DEBUG(DEBUG_DEBUG,(" %d [%d]\n", i, lcp2_imbalances[i]));
	}
	qsort(lips, numnodes, sizeof(struct lcp2_imbalance_pnn),
	      lcp2_cmp_imbalance_pnn);

	again = false;
	for (i = 0; i < numnodes; i++) {
		/* This means that all nodes had 0 or 1 addresses, so
		 * can't be imbalanced.
		 */
		if (lips[i].imbalance == 0) {
			break;
		}

		if (lcp2_failback_candidate(ipalloc_state,
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

bool ipalloc_lcp2(struct ipalloc_state *ipalloc_state)
{
	uint32_t *lcp2_imbalances;
	bool *rebalance_candidates;
	int numnodes, i;
	bool have_rebalance_candidates;
	bool ret = true;

	unassign_unsuitable_ips(ipalloc_state);

	if (!lcp2_init(ipalloc_state,
		       &lcp2_imbalances, &rebalance_candidates)) {
		ret = false;
		goto finished;
	}

	lcp2_allocate_unassigned(ipalloc_state, lcp2_imbalances);

	/* If we don't want IPs to fail back then don't rebalance IPs. */
	if (ipalloc_state->no_ip_failback) {
		goto finished;
	}

	/* It is only worth continuing if we have suitable target
	 * nodes to transfer IPs to.  This check is much cheaper than
	 * continuing on...
	 */
	numnodes = ipalloc_state->num;
	have_rebalance_candidates = false;
	for (i=0; i<numnodes; i++) {
		if (rebalance_candidates[i]) {
			have_rebalance_candidates = true;
			break;
		}
	}
	if (!have_rebalance_candidates) {
		goto finished;
	}

	/* Now, try to make sure the ip adresses are evenly distributed
	   across the nodes.
	*/
	lcp2_failback(ipalloc_state, lcp2_imbalances, rebalance_candidates);

finished:
	return ret;
}
