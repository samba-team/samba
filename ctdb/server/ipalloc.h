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

#ifndef __CTDB_IPALLOC_H__
#define __CTDB_IPALLOC_H__

#include <talloc.h>

#include "replace.h"
#include "system/network.h"

#include "lib/util/bitmap.h"

struct public_ip_list {
	struct public_ip_list *next;
	uint32_t pnn;
	ctdb_sock_addr addr;
	struct bitmap *known_on;
	struct bitmap *available_on;
};

#define IP_KEYLEN	4
uint32_t *ip_key(ctdb_sock_addr *ip);

/* Flags used in IP allocation algorithms. */
enum ipalloc_algorithm {
	IPALLOC_DETERMINISTIC,
	IPALLOC_NONDETERMINISTIC,
	IPALLOC_LCP2,
};

struct ipalloc_state;

struct ipalloc_state * ipalloc_state_init(TALLOC_CTX *mem_ctx,
					  uint32_t num_nodes,
					  enum ipalloc_algorithm algorithm,
					  bool no_ip_takeover,
					  bool no_ip_failback,
					  uint32_t *force_rebalance_nodes);

void ipalloc_set_public_ips(struct ipalloc_state *ipalloc_state,
			    struct ctdb_public_ip_list *known_ips,
			    struct ctdb_public_ip_list *available_ips);

bool ipalloc_can_host_ips(struct ipalloc_state *ipalloc_state);

struct public_ip_list *ipalloc(struct ipalloc_state *ipalloc_state);

#endif /* __CTDB_IPALLOC_H__ */
