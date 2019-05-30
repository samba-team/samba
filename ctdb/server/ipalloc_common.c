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

#include "lib/util/time.h"

#include "lib/util/debug.h"
#include "common/logging.h"

#include "common/common.h"
#include "common/rb_tree.h"

#include "protocol/protocol_util.h"

#include "server/ipalloc_private.h"

#define TAKEOVER_TIMEOUT() timeval_current_ofs(ctdb->tunable.takeover_timeout,0)

/* Given a physical node, return the number of
   public addresses that is currently assigned to this node.
*/
int node_ip_coverage(uint32_t pnn, struct public_ip_list *ips)
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
static bool can_node_host_ip(struct ipalloc_state *ipalloc_state,
			     int32_t pnn,
			     struct public_ip_list *ip)
{
	return bitmap_query(ip->available_on, pnn);
}

bool can_node_takeover_ip(struct ipalloc_state *ipalloc_state,
			  int32_t pnn,
			  struct public_ip_list *ip)
{
	if (ipalloc_state->no_ip_takeover) {
		return false;
	}

	return can_node_host_ip(ipalloc_state, pnn, ip);
}

/* search the node lists list for a node to takeover this ip.
   pick the node that currently are serving the least number of ips
   so that the ips get spread out evenly.
*/
int find_takeover_node(struct ipalloc_state *ipalloc_state,
		       struct public_ip_list *ip)
{
	unsigned int pnn;
	int min=0, num;
	unsigned int i, numnodes;

	numnodes = ipalloc_state->num;
	pnn = CTDB_UNKNOWN_PNN;
	for (i=0; i<numnodes; i++) {
		/* verify that this node can serve this ip */
		if (!can_node_takeover_ip(ipalloc_state, i, ip)) {
			/* no it couldnt   so skip to the next node */
			continue;
		}

		num = node_ip_coverage(i, ipalloc_state->all_ips);
		/* was this the first node we checked ? */
		if (pnn == CTDB_UNKNOWN_PNN) {
			pnn = i;
			min  = num;
		} else {
			if (num < min) {
				pnn = i;
				min  = num;
			}
		}
	}
	if (pnn == CTDB_UNKNOWN_PNN) {
		DEBUG(DEBUG_WARNING,(__location__ " Could not find node to take over public address '%s'\n",
				     ctdb_sock_addr_to_string(ipalloc_state,
							      &ip->addr,
							      false)));

		return -1;
	}

	ip->pnn = pnn;
	return 0;
}

uint32_t *ip_key(ctdb_sock_addr *ip)
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

/* Allocate any unassigned IPs just by looping through the IPs and
 * finding the best node for each.
 */
void basic_allocate_unassigned(struct ipalloc_state *ipalloc_state)
{
	struct public_ip_list *t;

	/* loop over all ip's and find a physical node to cover for
	   each unassigned ip.
	*/
	for (t = ipalloc_state->all_ips; t != NULL; t = t->next) {
		if (t->pnn == CTDB_UNKNOWN_PNN) {
			if (find_takeover_node(ipalloc_state, t)) {
				DEBUG(DEBUG_WARNING,
				      ("Failed to find node to cover ip %s\n",
				       ctdb_sock_addr_to_string(ipalloc_state,
								&t->addr,
								false)));
			}
		}
	}
}

void unassign_unsuitable_ips(struct ipalloc_state *ipalloc_state)
{
	struct public_ip_list *t;

	/* verify that the assigned nodes can serve that public ip
	   and set it to CTDB_UNKNOWN_PNN if not
	*/
	for (t = ipalloc_state->all_ips; t != NULL; t = t->next) {
		if (t->pnn == CTDB_UNKNOWN_PNN) {
			continue;
		}
		if (!can_node_host_ip(ipalloc_state, t->pnn, t) != 0) {
			/* this node can not serve this ip. */
			DEBUG(DEBUG_DEBUG,("Unassign IP: %s from %d\n",
					   ctdb_sock_addr_to_string(
						   ipalloc_state,
						   &t->addr, false),
					   t->pnn));
			t->pnn = CTDB_UNKNOWN_PNN;
		}
	}
}
