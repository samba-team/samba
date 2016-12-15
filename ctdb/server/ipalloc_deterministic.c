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

#include "server/ipalloc_private.h"

bool ipalloc_deterministic(struct ipalloc_state *ipalloc_state)
{
	struct public_ip_list *t;
	int i, numnodes;

	numnodes = ipalloc_state->num;

	DEBUG(DEBUG_NOTICE,("Deterministic IPs enabled. Resetting all ip allocations\n"));
       /* Allocate IPs to nodes in a modulo fashion so that IPs will
        *  always be allocated the same way for a specific set of
        *  available/unavailable nodes.
	*/

	for (i = 0, t = ipalloc_state->all_ips; t!= NULL; t = t->next, i++) {
		t->pnn = i % numnodes;
	}

	/* IP failback doesn't make sense with deterministic
	 * IPs, since the modulo step above implicitly fails
	 * back IPs to their "home" node.
	 */
	if (ipalloc_state->no_ip_failback) {
		D_WARNING("WARNING: 'NoIPFailback' set but ignored - "
			  "incompatible with 'Deterministic IPs\n");
	}

	unassign_unsuitable_ips(ipalloc_state);

	basic_allocate_unassigned(ipalloc_state);

	/* No failback here! */

	return true;
}
