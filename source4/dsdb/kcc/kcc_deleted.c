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
#include "lib/events/events.h"
#include "dsdb/samdb/samdb.h"
#include "auth/auth.h"
#include "smbd/service.h"
#include "lib/messaging/irpc.h"
#include "dsdb/kcc/kcc_connection.h"
#include "dsdb/kcc/kcc_service.h"
#include <ldb_errors.h>
#include "../lib/util/dlinklist.h"
#include "librpc/gen_ndr/ndr_misc.h"
#include "librpc/gen_ndr/ndr_drsuapi.h"
#include "librpc/gen_ndr/ndr_drsblobs.h"
#include "param/param.h"
#include "dsdb/common/util.h"

/*
  check to see if any deleted objects need scavenging
 */
NTSTATUS kccsrv_check_deleted(struct kccsrv_service *s, TALLOC_CTX *mem_ctx)
{
	struct kccsrv_partition *part;
	int ret;
	uint32_t tombstoneLifetime;
	bool do_fs = false;

	time_t interval = lpcfg_parm_int(s->task->lp_ctx, NULL, "kccsrv",
						    "check_deleted_full_scan_interval", 86400);
	time_t t = time(NULL);

	if (t - s->last_deleted_check < lpcfg_parm_int(s->task->lp_ctx, NULL, "kccsrv",
						    "check_deleted_interval", 600)) {
		return NT_STATUS_OK;
	}
	s->last_deleted_check = t;

	ret = dsdb_tombstone_lifetime(s->samdb, &tombstoneLifetime);
	if (ret != LDB_SUCCESS) {
		DEBUG(1,(__location__ ": Failed to get tombstone lifetime\n"));
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}
	if (s->last_full_scan_deleted_check > 0 && ((t - s->last_full_scan_deleted_check) > interval )) {
		do_fs = true;
		s->last_full_scan_deleted_check = t;
	}

	if (s->last_full_scan_deleted_check == 0) {
		/*
		 * If we never made a full scan set the last full scan event to be in the past
		 * and that 9/10 of the full scan interval has already passed.
		 * This is done to avoid the full scan to fire just at the begining of samba
		 * or a couple of minutes after the start.
		 * With this "setup" and default values of interval, the full scan will fire
		 * 2.4 hours after the start of samba
		 */
		s->last_full_scan_deleted_check = t - ((9 * interval) / 10);
	}

	for (part=s->partitions; part; part=part->next) {
		struct ldb_dn *do_dn;
		struct ldb_result *res;
		const char *attrs[] = { "whenChanged", NULL };
		unsigned int i;
		TALLOC_CTX *tmp_ctx = talloc_new(mem_ctx);
		if (!tmp_ctx) {
			return NT_STATUS_NO_MEMORY;
		}

		ret = dsdb_get_deleted_objects_dn(s->samdb, tmp_ctx, part->dn, &do_dn);
		if (ret != LDB_SUCCESS) {
			TALLOC_FREE(tmp_ctx);
			/* some partitions have no Deleted Objects
			   container */
			continue;
		}

		if (!do_fs && ldb_dn_compare(ldb_get_config_basedn(s->samdb), part->dn)) {
			ret = dsdb_search(s->samdb, tmp_ctx, &res, do_dn, LDB_SCOPE_ONELEVEL, attrs,
					DSDB_SEARCH_SHOW_RECYCLED, NULL);
		} else {
			if (do_fs) {
				DEBUG(1, ("Doing a full scan on %s and looking for deleted object\n",
						ldb_dn_get_linearized(part->dn)));
			}
			ret = dsdb_search(s->samdb, tmp_ctx, &res, part->dn, LDB_SCOPE_SUBTREE, attrs,
					DSDB_SEARCH_SHOW_RECYCLED, "(isDeleted=TRUE)");
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
			if (t - whenChanged > tombstoneLifetime*60*60*24) {
				ret = dsdb_delete(s->samdb, res->msgs[i]->dn, DSDB_SEARCH_SHOW_RECYCLED|DSDB_MODIFY_RELAX);
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
