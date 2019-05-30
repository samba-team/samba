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

#include "ctdb_private.h"

#include "lib/util/debug.h"
#include "common/logging.h"
#include "common/common.h"

#include "protocol/protocol_util.h"

#include "server/ipalloc_private.h"

/* Basic non-deterministic rebalancing algorithm.
 */
static void basic_failback(struct ipalloc_state *ipalloc_state,
			   int num_ips)
{
	unsigned int i, numnodes, maxnode, minnode;
	int maxnum, minnum, num, retries;
	struct public_ip_list *t;

	numnodes = ipalloc_state->num;
	retries = 0;

try_again:
	maxnum=0;
	minnum=0;

	/* for each ip address, loop over all nodes that can serve
	   this ip and make sure that the difference between the node
	   serving the most and the node serving the least ip's are
	   not greater than 1.
	*/
	for (t = ipalloc_state->all_ips; t != NULL; t = t->next) {
		if (t->pnn == CTDB_UNKNOWN_PNN) {
			continue;
		}

		/* Get the highest and lowest number of ips's served by any 
		   valid node which can serve this ip.
		*/
		maxnode = CTDB_UNKNOWN_PNN;
		minnode = CTDB_UNKNOWN_PNN;
		for (i=0; i<numnodes; i++) {
			/* only check nodes that can actually serve this ip */
			if (!can_node_takeover_ip(ipalloc_state, i,
						  t)) {
				/* no it couldnt   so skip to the next node */
				continue;
			}

			num = node_ip_coverage(i, ipalloc_state->all_ips);
			if (maxnode == CTDB_UNKNOWN_PNN) {
				maxnode = i;
				maxnum  = num;
			} else {
				if (num > maxnum) {
					maxnode = i;
					maxnum  = num;
				}
			}
			if (minnode == CTDB_UNKNOWN_PNN) {
				minnode = i;
				minnum  = num;
			} else {
				if (num < minnum) {
					minnode = i;
					minnum  = num;
				}
			}
		}
		if (maxnode == CTDB_UNKNOWN_PNN) {
			DEBUG(DEBUG_WARNING,
			      (__location__ " Could not find maxnode. May not be able to serve ip '%s'\n",
			       ctdb_sock_addr_to_string(ipalloc_state,
							&t->addr, false)));

			continue;
		}

		/* if the spread between the smallest and largest coverage by
		   a node is >=2 we steal one of the ips from the node with
		   most coverage to even things out a bit.
		   try to do this a limited number of times since we dont
		   want to spend too much time balancing the ip coverage.
		*/
		if ((maxnum > minnum+1) &&
		    (retries < (num_ips + 5))){
			struct public_ip_list *tt;

			/* Reassign one of maxnode's VNNs */
			for (tt = ipalloc_state->all_ips; tt != NULL; tt = tt->next) {
				if (tt->pnn == maxnode) {
					(void)find_takeover_node(ipalloc_state,
								 tt);
					retries++;
					goto try_again;;
				}
			}
		}
	}
}

bool ipalloc_nondeterministic(struct ipalloc_state *ipalloc_state)
{
	/* This should be pushed down into basic_failback. */
	struct public_ip_list *t;
	int num_ips = 0;
	for (t = ipalloc_state->all_ips; t != NULL; t = t->next) {
		num_ips++;
	}

	unassign_unsuitable_ips(ipalloc_state);

	basic_allocate_unassigned(ipalloc_state);

	/* If we don't want IPs to fail back then don't rebalance IPs. */
	if (ipalloc_state->no_ip_failback) {
		return true;
	}

	/* Now, try to make sure the ip adresses are evenly distributed
	   across the nodes.
	*/
	basic_failback(ipalloc_state, num_ips);

	return true;
}
