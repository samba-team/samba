/*
   CTDB IP takeover code

   Copyright (C) Ronnie Sahlberg  2007
   Copyright (C) Andrew Tridgell  2007
   Copyright (C) Martin Schwenke  2015

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

#ifndef __CTDB_IPALLOC_PRIVATE_H__
#define __CTDB_IPALLOC_PRIVATE_H__

#include "protocol/protocol.h"

#include "server/ipalloc.h"

struct ipalloc_state {
	uint32_t num;

	/* Arrays with data for each node */
	struct ctdb_public_ip_list *available_public_ips;
	struct ctdb_public_ip_list *known_public_ips;

	struct public_ip_list *all_ips;
	enum ipalloc_algorithm algorithm;
	bool no_ip_failback;
	bool no_ip_takeover;
	uint32_t *force_rebalance_nodes;
};

bool can_node_takeover_ip(struct ipalloc_state *ipalloc_state,
			  int32_t pnn,
			  struct public_ip_list *ip);
int node_ip_coverage(uint32_t pnn, struct public_ip_list *ips);
int find_takeover_node(struct ipalloc_state *ipalloc_state,
		       struct public_ip_list *ip);

void unassign_unsuitable_ips(struct ipalloc_state *ipalloc_state);
void basic_allocate_unassigned(struct ipalloc_state *ipalloc_state);

bool ipalloc_nondeterministic(struct ipalloc_state *ipalloc_state);
bool ipalloc_deterministic(struct ipalloc_state *ipalloc_state);
bool ipalloc_lcp2(struct ipalloc_state *ipalloc_state);

#endif /* __CTDB_IPALLOC_PRIVATE_H__ */
