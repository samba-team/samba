/* 
   Unix SMB/CIFS implementation.
   ID Mapping
   Copyright (C) Simo Sorce 2003
   Copyright (C) Jeremy Allison 2006
   Copyright (C) Michael Adam 2010

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.*/

#include "includes.h"
#include "winbindd.h"
#include "winbindd_proto.h"
#include "idmap.h"
#include "idmap_cache.h"
#include "../libcli/security/security.h"
#include "secrets.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_IDMAP

/**
 * check whether a given unix id is inside the filter range of an idmap domain
 */
bool idmap_unix_id_is_in_range(uint32_t id, struct idmap_domain *dom)
{
	if ((dom->low_id && (id < dom->low_id)) ||
	    (dom->high_id && (id > dom->high_id)))
	{
		return false;
	}

	return true;
}

/**
 * Helper for unixids_to_sids: find entry by id in mapping array,
 * search up to IDMAP_AD_MAX_IDS entries
 */
struct id_map *idmap_find_map_by_id(struct id_map **maps, enum id_type type,
				    uint32_t id)
{
	int i;

	for (i = 0; maps[i] != NULL; i++) {
		if ((maps[i]->xid.type == type) && (maps[i]->xid.id == id)) {
			return maps[i];
		}
	}

	return NULL;
}

/**
 * Helper for sids_to_unix_ids: find entry by SID in mapping array,
 * search up to IDMAP_AD_MAX_IDS entries
 */
struct id_map *idmap_find_map_by_sid(struct id_map **maps, struct dom_sid *sid)
{
	int i;

	for (i = 0; i < IDMAP_LDAP_MAX_IDS; i++) {
		if (maps[i] == NULL) { /* end of the run */
			return NULL;
		}
		if (dom_sid_equal(maps[i]->sid, sid)) {
			return maps[i];
		}
	}

	return NULL;
}

char *idmap_fetch_secret(const char *backend, const char *domain,
			 const char *identity)
{
	char *tmp, *ret;
	int r;

	r = asprintf(&tmp, "IDMAP_%s_%s", backend, domain);

	if (r < 0)
		return NULL;

	/* make sure the key is case insensitive */
	if (!strupper_m(tmp)) {
		SAFE_FREE(tmp);
		return NULL;
	}

	ret = secrets_fetch_generic(tmp, identity);

	SAFE_FREE(tmp);

	return ret;
}

struct id_map **id_map_ptrs_init(TALLOC_CTX *mem_ctx, size_t num_ids)
{
	struct id_map **ptrs;
	struct id_map *maps;
	struct dom_sid *sids;
	size_t i;

	ptrs = talloc_array(mem_ctx, struct id_map *, num_ids+1);
	if (ptrs == NULL) {
		return NULL;
	}
	maps = talloc_array(ptrs, struct id_map, num_ids);
	if (maps == NULL) {
		TALLOC_FREE(ptrs);
		return NULL;
	}
	sids = talloc_zero_array(ptrs, struct dom_sid, num_ids);
	if (sids == NULL) {
		TALLOC_FREE(ptrs);
		return NULL;
	}

	for (i=0; i<num_ids; i++) {
		maps[i] = (struct id_map) { .sid = &sids[i] };
		ptrs[i] = &maps[i];
	}
	ptrs[num_ids] = NULL;

	return ptrs;
}
