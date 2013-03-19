/*
   Unix SMB/CIFS implementation.
   Database interface wrapper

   Copyright (C) Volker Lendecke 2005-2007

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
#include "dbwrap/dbwrap.h"
#include "dbwrap/dbwrap_private.h"
#include "dbwrap/dbwrap_open.h"
#include "dbwrap/dbwrap_tdb.h"
#include "dbwrap/dbwrap_ctdb.h"
#include "lib/param/param.h"
#include "util_tdb.h"
#include "ctdbd_conn.h"

bool db_is_local(const char *name)
{
	const char *sockname = lp_ctdbd_socket();

	if (lp_clustering() && socket_exist(sockname)) {
		const char *partname;
		/* ctdb only wants the file part of the name */
		partname = strrchr(name, '/');
		if (partname) {
			partname++;
		} else {
			partname = name;
		}
		/* allow ctdb for individual databases to be disabled */
		if (lp_parm_bool(-1, "ctdb", partname, True)) {
			return false;
		}
	}

	return true;
}

/**
 * open a database
 */
struct db_context *db_open(TALLOC_CTX *mem_ctx,
			   const char *name,
			   int hash_size, int tdb_flags,
			   int open_flags, mode_t mode,
			   enum dbwrap_lock_order lock_order,
			   uint64_t dbwrap_flags)
{
	struct db_context *result = NULL;
	const char *sockname;

	if (!DBWRAP_LOCK_ORDER_VALID(lock_order)) {
		errno = EINVAL;
		return NULL;
	}

	if (tdb_flags & TDB_CLEAR_IF_FIRST) {
		const char *base;
		bool try_readonly = false;

		base = strrchr_m(name, '/');
		if (base != NULL) {
			base += 1;
		} else {
			base = name;
		}

		if (dbwrap_flags & DBWRAP_FLAG_OPTIMIZE_READONLY_ACCESS) {
			try_readonly = true;
		}

		try_readonly = lp_parm_bool(-1, "dbwrap_optimize_readonly", "*", try_readonly);
		try_readonly = lp_parm_bool(-1, "dbwrap_optimize_readonly", base, try_readonly);

		if (try_readonly) {
			dbwrap_flags |= DBWRAP_FLAG_OPTIMIZE_READONLY_ACCESS;
		} else {
			dbwrap_flags &= ~DBWRAP_FLAG_OPTIMIZE_READONLY_ACCESS;
		}
	}

	if (tdb_flags & TDB_CLEAR_IF_FIRST) {
		const char *base;
		bool try_mutex = false;

		base = strrchr_m(name, '/');
		if (base != NULL) {
			base += 1;
		} else {
			base = name;
		}

		try_mutex = lp_parm_bool(-1, "dbwrap_tdb_mutexes", "*", try_mutex);
		try_mutex = lp_parm_bool(-1, "dbwrap_tdb_mutexes", base, try_mutex);

		if (try_mutex && tdb_runtime_check_for_robust_mutexes()) {
			tdb_flags |= TDB_MUTEX_LOCKING;
		}
	}

	sockname = lp_ctdbd_socket();

	if (lp_clustering()) {
		const char *partname;

		if (!socket_exist(sockname)) {
			DEBUG(1, ("ctdb socket does not exist - is ctdb not "
				  "running?\n"));
			return NULL;
		}

		/* ctdb only wants the file part of the name */
		partname = strrchr(name, '/');
		if (partname) {
			partname++;
		} else {
			partname = name;
		}
		/* allow ctdb for individual databases to be disabled */
		if (lp_parm_bool(-1, "ctdb", partname, True)) {
			result = db_open_ctdb(mem_ctx, partname, hash_size,
					      tdb_flags, open_flags, mode,
					      lock_order, dbwrap_flags);
			if (result == NULL) {
				DEBUG(0,("failed to attach to ctdb %s\n",
					 partname));
				if (errno == 0) {
					errno = EIO;
				}
				return NULL;
			}
		}
	}

	if (result == NULL) {
		struct loadparm_context *lp_ctx = loadparm_init_s3(mem_ctx, loadparm_s3_helpers());
		result = dbwrap_local_open(mem_ctx, lp_ctx, name, hash_size,
					   tdb_flags, open_flags, mode,
					   lock_order, dbwrap_flags);
		talloc_unlink(mem_ctx, lp_ctx);
	}
	return result;
}
