/*
   Unix SMB/CIFS implementation.
   Database interface wrapper: local open code.

   Copyright (C) Rusty Russell 2012

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
#include "dbwrap/dbwrap_tdb.h"
#include "tdb.h"
#ifndef DISABLE_NTDB
#include "lib/util/util_ntdb.h"
#endif
#include "lib/param/param.h"
#include "system/filesys.h"
#include "ccan/str/str.h"

struct db_context *dbwrap_local_open(TALLOC_CTX *mem_ctx,
				     struct loadparm_context *lp_ctx,
				     const char *name,
				     int hash_size, int tdb_flags,
				     int open_flags, mode_t mode,
				     enum dbwrap_lock_order lock_order)
{
	TALLOC_CTX *tmp_ctx = talloc_new(mem_ctx);
	const char *ntdbname, *tdbname;
	struct db_context *db = NULL;

	/* Get both .ntdb and .tdb variants of the name. */
	if (!name) {
		tdbname = ntdbname = "unnamed database";
	} else if (strends(name, ".tdb")) {
		tdbname = name;
		ntdbname = talloc_asprintf(tmp_ctx,
					   "%.*s.ntdb",
					   (int)strlen(name) - 4, name);
	} else if (strends(name, ".ntdb")) {
		ntdbname = name;
		tdbname = talloc_asprintf(tmp_ctx,
					  "%.*s.tdb",
					  (int)strlen(name) - 5, name);
	} else {
		ntdbname = tdbname = name;
	}

	if (ntdbname == NULL || tdbname == NULL) {
		DEBUG(0, ("talloc failed\n"));
		goto out;
	}

	/* We currently always open a tdb, not an ntdb. */
	db = db_open_tdb(mem_ctx, lp_ctx, tdbname, hash_size,
			 tdb_flags, open_flags, mode,
			 lock_order);
out:
	talloc_free(tmp_ctx);
	return db;
}
