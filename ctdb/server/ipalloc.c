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

/* The calculation part of the IP allocation algorithm. */
bool ipalloc(struct ipalloc_state *ipalloc_state)
{
	bool ret = false;

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
	   or -1 if there is no node that can cover this ip
	*/

	return ret;
}
