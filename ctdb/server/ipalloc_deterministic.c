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
#include "common/path.h"

#include "protocol/protocol_util.h"
#include "lib/util/smb_strtox.h"
#include "lib/util/memory.h"

#include "server/ipalloc_private.h"

struct home_node {
	ctdb_sock_addr addr;
	uint32_t pnn;
};

static struct home_node *ipalloc_get_home_nodes(TALLOC_CTX *mem_ctx)
{
	char *line = NULL;
	size_t len = 0;
	char *fname = NULL;
	FILE *fp = NULL;
	struct home_node *result = NULL;

	fname = path_etcdir_append(mem_ctx, "home_nodes");
	if (fname == NULL) {
		goto fail;
	}

	fp = fopen(fname, "r");
	if (fp == NULL) {
		goto fail;
	}
	TALLOC_FREE(fname);

	while (true) {
		size_t num_nodes = talloc_array_length(result);
		char *saveptr = NULL, *addrstr = NULL, *nodestr = NULL;
		struct home_node hn = {
			.pnn = CTDB_UNKNOWN_PNN,
		};
		struct home_node *tmp = NULL;
		ssize_t n = 0;
		int ret;

		n = getline(&line, &len, fp);
		if (n < 0) {
			if (!feof(fp)) {
				/* real error */
				goto fail;
			}
			break;
		}
		if ((n > 0) && (line[n - 1] == '\n')) {
			line[n - 1] = '\0';
		}

		addrstr = strtok_r(line, " \t", &saveptr);
		if (addrstr == NULL) {
			continue;
		}
		nodestr = strtok_r(NULL, " \t", &saveptr);
		if (nodestr == NULL) {
			continue;
		}

		ret = ctdb_sock_addr_from_string(addrstr, &hn.addr, false);
		if (ret != 0) {
			DBG_WARNING("Could not parse %s: %s\n",
				    addrstr,
				    strerror(ret));
			goto fail;
		}

		hn.pnn = smb_strtoul(nodestr,
				     NULL,
				     10,
				     &ret,
				     SMB_STR_FULL_STR_CONV);
		if (ret != 0) {
			DBG_WARNING("Could not parse \"%s\"\n", nodestr);
			goto fail;
		}

		tmp = talloc_realloc(mem_ctx,
				     result,
				     struct home_node,
				     num_nodes + 1);
		if (tmp == NULL) {
			goto fail;
		}
		result = tmp;
		result[num_nodes] = hn;
	}

	fclose(fp);
	fp = NULL;
	return result;

fail:
	if (fp != NULL) {
		fclose(fp);
		fp = NULL;
	}
	SAFE_FREE(line);
	TALLOC_FREE(fname);
	TALLOC_FREE(result);
	return NULL;
}

bool ipalloc_deterministic(struct ipalloc_state *ipalloc_state)
{
	struct home_node *home_nodes = ipalloc_get_home_nodes(ipalloc_state);
	size_t num_home_nodes = talloc_array_length(home_nodes);
	struct public_ip_list *t;
	int i;
	uint32_t numnodes;

	numnodes = ipalloc_state->num;

	DEBUG(DEBUG_NOTICE,("Deterministic IPs enabled. Resetting all ip allocations\n"));
       /* Allocate IPs to nodes in a modulo fashion so that IPs will
        *  always be allocated the same way for a specific set of
        *  available/unavailable nodes.
	*/

	for (i = 0, t = ipalloc_state->all_ips; t!= NULL; t = t->next, i++) {
		size_t j;

		t->pnn = i % numnodes;

		for (j = 0; j < num_home_nodes; j++) {
			struct home_node *hn = &home_nodes[j];

			if (ctdb_sock_addr_same_ip(&t->addr, &hn->addr)) {

				if (hn->pnn >= numnodes) {
					DBG_WARNING("pnn %" PRIu32
						    " too large\n",
						    hn->pnn);
					break;
				}

				t->pnn = hn->pnn;
				break;
			}
		}
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

	TALLOC_FREE(home_nodes);

	return true;
}
