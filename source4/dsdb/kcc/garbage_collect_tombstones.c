/*
   Unix SMB/CIFS implementation.

   handle removal of deleted objects

   Copyright (C) 2009 Andrew Tridgell

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.

*/

#include "includes.h"
#include <ldb_errors.h>
#include "../lib/util/dlinklist.h"
#include "librpc/gen_ndr/ndr_misc.h"
#include "librpc/gen_ndr/ndr_drsuapi.h"
#include "librpc/gen_ndr/ndr_drsblobs.h"
#include "param/param.h"
#include "lib/util/dlinklist.h"
#include "ldb.h"
#include "dsdb/kcc/garbage_collect_tombstones.h"


NTSTATUS dsdb_garbage_collect_tombstones(TALLOC_CTX *mem_ctx, struct loadparm_context *lp_ctx,
					 struct ldb_context *samdb,
					 struct dsdb_ldb_dn_list_node *part,
					 time_t current_time,
					 bool do_fs)
{
	int ret;
	uint32_t tombstoneLifetime;

	ret = dsdb_tombstone_lifetime(samdb, &tombstoneLifetime);
	if (ret != LDB_SUCCESS) {
		DEBUG(1,(__location__ ": Failed to get tombstone lifetime\n"));
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}

	for (; part != NULL; part = part->next) {
		struct ldb_dn *do_dn;
		struct ldb_result *res;
		const char *attrs[] = { "whenChanged", NULL };
		unsigned int i;
		TALLOC_CTX *tmp_ctx = talloc_new(mem_ctx);
		if (!tmp_ctx) {
			return NT_STATUS_NO_MEMORY;
		}

		ret = dsdb_get_deleted_objects_dn(samdb, tmp_ctx, part->dn, &do_dn);
		if (ret != LDB_SUCCESS) {
			TALLOC_FREE(tmp_ctx);
			/* some partitions have no Deleted Objects
			   container */
			continue;
		}

		if (!do_fs && ldb_dn_compare(ldb_get_config_basedn(samdb), part->dn)) {
			ret = dsdb_search(samdb, tmp_ctx, &res, do_dn, LDB_SCOPE_ONELEVEL, attrs,
					DSDB_SEARCH_SHOW_RECYCLED, NULL);
		} else {
			if (do_fs) {
				DEBUG(1, ("Doing a full scan on %s and looking for deleted object\n",
						ldb_dn_get_linearized(part->dn)));
			}
			ret = dsdb_search(samdb, tmp_ctx, &res, part->dn, LDB_SCOPE_SUBTREE, attrs,
					DSDB_SEARCH_SHOW_RECYCLED, "(|(isDeleted=TRUE))");
		}

		if (ret != LDB_SUCCESS) {
			DEBUG(1,(__location__ ": Failed to search for deleted objects in %s\n",
				 ldb_dn_get_linearized(do_dn)));
			TALLOC_FREE(tmp_ctx);
			continue;
		}

		for (i=0; i<res->count; i++) {
			const char *tstring;
			time_t whenChanged = 0;

			if (ldb_dn_compare(do_dn, res->msgs[i]->dn) == 0) {
				/* Skip the Deleted Object Container */
				continue;
			}
			tstring = ldb_msg_find_attr_as_string(res->msgs[i], "whenChanged", NULL);
			if (tstring) {
				whenChanged = ldb_string_to_time(tstring);
			}
			if (current_time - whenChanged > tombstoneLifetime*60*60*24) {
				ret = dsdb_delete(samdb, res->msgs[i]->dn, DSDB_SEARCH_SHOW_RECYCLED|DSDB_MODIFY_RELAX);
				if (ret != LDB_SUCCESS) {
					DEBUG(1,(__location__ ": Failed to remove deleted object %s\n",
						 ldb_dn_get_linearized(res->msgs[i]->dn)));
				} else {
					DEBUG(4,("Removed deleted object %s\n",
						 ldb_dn_get_linearized(res->msgs[i]->dn)));
				}
			}
		}

		TALLOC_FREE(tmp_ctx);
	}

	return NT_STATUS_OK;
}
