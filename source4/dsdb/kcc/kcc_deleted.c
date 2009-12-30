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
#include "lib/ldb/include/ldb_errors.h"
#include "../lib/util/dlinklist.h"
#include "librpc/gen_ndr/ndr_misc.h"
#include "librpc/gen_ndr/ndr_drsuapi.h"
#include "librpc/gen_ndr/ndr_drsblobs.h"
#include "param/param.h"


/*
  check to see if any deleted objects need scavenging
 */
NTSTATUS kccsrv_check_deleted(struct kccsrv_service *s, TALLOC_CTX *mem_ctx)
{
	struct kccsrv_partition *part;
	int ret;

	time_t t = time(NULL);
	if (t - s->last_deleted_check < lp_parm_int(task->lp_ctx, NULL, "kccsrv",
						    "check_deleted_interval", 600)) {
		return NT_STATUS_OK;
	}
	s->last_deleted_check = t;

	for (part=s->partitions; part; part=part->next) {
		struct ldb_dn *do_dn;
		struct ldb_result *res;

		ret = dsdb_get_deleted_objects_dn(s->samdb, mem_ctx, part->dn, &do_dn);
		ret = ldb_search(s->samdb, mem_ctx, &res, do_dn, LDB_SCOPE_SUBTREE,
				 attrs, "isDeleted=TRUE");
	}


}
