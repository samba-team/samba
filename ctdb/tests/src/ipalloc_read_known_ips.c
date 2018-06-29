/*
   Tests support for CTDB IP allocation

   Copyright (C) Martin Schwenke 2011

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

#include "protocol/protocol.h"
#include "protocol/protocol_util.h"
#include "common/logging.h"

#include "ipalloc_read_known_ips.h"

static bool add_ip(TALLOC_CTX *mem_ctx,
		   struct ctdb_public_ip_list *l,
		   ctdb_sock_addr *addr,
		   uint32_t pnn)
{

	l->ip = talloc_realloc(mem_ctx, l->ip,
			       struct ctdb_public_ip, l->num + 1);
	if (l->ip == NULL) {
		D_ERR(__location__ " out of memory\n");
		return false;
	}

	l->ip[l->num].addr = *addr;
	l->ip[l->num].pnn  = pnn;
	l->num++;

	return true;
}

/* Format of each line is "IP CURRENT_PNN [ALLOWED_PNN,...]".
 * If multi is true then ALLOWED_PNNs are not allowed.  */
static bool read_ctdb_public_ip_info_node(bool multi,
					  int numnodes,
					  struct ctdb_public_ip_list **k,
					  struct ctdb_public_ip_list *known)
{
	char line[1024];
	ctdb_sock_addr addr;
	char *t, *tok;
	int pnn, n;

	/* Known public IPs */
	*k = talloc_zero(known, struct ctdb_public_ip_list);
	if (*k == NULL) {
		goto fail;
	}

	while (fgets(line, sizeof(line), stdin) != NULL) {
		int ret;

		/* Get rid of pesky newline */
		if ((t = strchr(line, '\n')) != NULL) {
			*t = '\0';
		}

		/* Exit on an empty line */
		if (line[0] == '\0') {
			break;
		}

		/* Get the IP address */
		tok = strtok(line, " \t");
		if (tok == NULL) {
			D_WARNING("WARNING, bad line ignored :%s\n", line);
			continue;
		}

		ret = ctdb_sock_addr_from_string(tok, &addr, false);
		if (ret != 0) {
			D_ERR("ERROR, bad address :%s\n", tok);
			continue;
		}

		/* Get the PNN */
		pnn = -1;
		tok = strtok(NULL, " \t");
		if (tok != NULL) {
			pnn = (int) strtol(tok, (char **) NULL, 10);
		}

		if (! add_ip(*k, *k, &addr, pnn)) {
			goto fail;
		}

		tok = strtok(NULL, " \t#");
		if (tok == NULL) {
			if (! multi) {
				for (n = 0; n < numnodes; n++) {
					if (! add_ip(known, &known[n],
						     &addr, pnn)) {
						goto fail;
					}
				}
			}
			continue;
		}

		/* Handle allowed nodes for addr */
		if (multi) {
			D_ERR("ERROR, bad token\n");
			goto fail;
		}
		t = strtok(tok, ",");
		while (t != NULL) {
			n = (int) strtol(t, (char **) NULL, 10);
			if (! add_ip(known, &known[n], &addr, pnn)) {
				goto fail;
			}
			t = strtok(NULL, ",");
		}
	}

	return true;

fail:
	TALLOC_FREE(*k);
	return false;
}

struct ctdb_public_ip_list * ipalloc_read_known_ips(TALLOC_CTX *ctx,
						    int numnodes,
						    bool multi)
{
	int n;
	struct ctdb_public_ip_list *k;
	struct ctdb_public_ip_list *known;

	known = talloc_zero_array(ctx, struct ctdb_public_ip_list,
				  numnodes);
	if (known == NULL) {
		D_ERR(__location__ " out of memory\n");
		goto fail;
	}

	if (multi) {
		for (n = 0; n < numnodes; n++) {
			if (! read_ctdb_public_ip_info_node(multi, numnodes,
							    &k, known)) {
				goto fail;
			}

			known[n] = *k;
		}
	} else {
		if (! read_ctdb_public_ip_info_node(multi, numnodes,
						    &k, known)) {
			goto fail;
		}
	}

	return known;

fail:
	talloc_free(known);
	return NULL;
}
