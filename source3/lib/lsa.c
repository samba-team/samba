/*
 * Helper functions related to the LSA server
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

/***************************************************************************
 init_lsa_ref_domain_list - adds a domain if it's not already in, returns index.
***************************************************************************/

#include "replace.h"
#include "lib/util/data_blob.h"
#include "lib/util/time.h"
#include "libcli/security/dom_sid.h"
#include "librpc/gen_ndr/lsa.h"
#include "lsa.h"

int init_lsa_ref_domain_list(TALLOC_CTX *mem_ctx,
			     struct lsa_RefDomainList *ref,
			     const char *dom_name,
			     struct dom_sid *dom_sid)
{
	int num = 0;

	if (dom_name != NULL) {
		for (num = 0; num < ref->count; num++) {
			if (dom_sid_equal(dom_sid, ref->domains[num].sid)) {
				return num;
			}
		}
	} else {
		num = ref->count;
	}

	if (num >= LSA_REF_DOMAIN_LIST_MULTIPLIER) {
		/* index not found, already at maximum domain limit */
		return -1;
	}

	ref->count = num + 1;
	ref->max_size = LSA_REF_DOMAIN_LIST_MULTIPLIER;

	ref->domains = talloc_realloc(mem_ctx, ref->domains,
					    struct lsa_DomainInfo, ref->count);
	if (!ref->domains) {
		return -1;
	}

	ZERO_STRUCT(ref->domains[num]);

	ref->domains[num].name.string = talloc_strdup(mem_ctx, dom_name);
	if (!ref->domains[num].name.string) {
		return -1;
	}

	ref->domains[num].sid = dom_sid_dup(mem_ctx, dom_sid);
	if (!ref->domains[num].sid) {
		return -1;
	}

	return num;
}
