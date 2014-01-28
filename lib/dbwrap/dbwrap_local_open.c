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
#include "dbwrap/dbwrap_ntdb.h"
#include "tdb.h"
#include "lib/util/util_ntdb.h"
#include "lib/param/param.h"
#include "system/filesys.h"
#include "ccan/str/str.h"

struct flag_map {
	int tdb_flag;
	int ntdb_flag;
};

static const struct flag_map tdb_ntdb_flags[] = {
	{ TDB_CLEAR_IF_FIRST, NTDB_CLEAR_IF_FIRST },
	{ TDB_INTERNAL, NTDB_INTERNAL },
	{ TDB_NOLOCK, NTDB_NOLOCK },
	{ TDB_NOMMAP, NTDB_NOMMAP },
	{ TDB_CONVERT, NTDB_CONVERT },
	{ TDB_NOSYNC, NTDB_NOSYNC },
	{ TDB_SEQNUM, NTDB_SEQNUM },
	{ TDB_VOLATILE, 0 },
	{ TDB_ALLOW_NESTING, NTDB_ALLOW_NESTING },
	{ TDB_DISALLOW_NESTING, 0 },
	{ TDB_INCOMPATIBLE_HASH, 0 }
};

static int tdb_flags_to_ntdb_flags(int tdb_flags)
{
	unsigned int i;
	int ntdb_flags = 0;

	/* TDB allows nesting unless told not to. */
	if (!(tdb_flags & TDB_DISALLOW_NESTING))
		ntdb_flags |= NTDB_ALLOW_NESTING;

	for (i = 0; i < sizeof(tdb_ntdb_flags)/sizeof(tdb_ntdb_flags[0]); i++) {
		if (tdb_flags & tdb_ntdb_flags[i].tdb_flag) {
			tdb_flags &= ~tdb_ntdb_flags[i].tdb_flag;
			ntdb_flags |= tdb_ntdb_flags[i].ntdb_flag;
		}
	}

	SMB_ASSERT(tdb_flags == 0);
	return ntdb_flags;
}

struct trav_data {
	struct db_context *ntdb;
	NTSTATUS status;
};

static int write_to_ntdb(struct db_record *rec, void *_tdata)
{
	struct trav_data *tdata = _tdata;
	TDB_DATA key, value;

	key = dbwrap_record_get_key(rec);
	value = dbwrap_record_get_value(rec);

	tdata->status = dbwrap_store(tdata->ntdb, key, value, TDB_INSERT);
	if (!NT_STATUS_IS_OK(tdata->status)) {
		return 1;
	}
	return 0;
}

static bool tdb_to_ntdb(TALLOC_CTX *ctx, struct loadparm_context *lp_ctx,
			const char *tdbname, const char *ntdbname)
{
	struct db_context *ntdb, *tdb;
	char *bakname;
	const char *tdbbase, *bakbase;
	struct trav_data tdata;
	struct stat st;

	/* We need permissions from the tdb file. */
	if (stat(tdbname, &st) == -1) {
		DEBUG(0, ("tdb_to_ntdb: fstat %s failed: %s\n",
			  tdbname, strerror(errno)));
		return false;
	}
	tdb = db_open_tdb(ctx, lp_ctx, tdbname, 0,
			  TDB_DEFAULT, O_RDONLY, 0, DBWRAP_LOCK_ORDER_NONE,
			  DBWRAP_FLAG_NONE);
	if (!tdb) {
		DEBUG(0, ("tdb_to_ntdb: could not open %s: %s\n",
			  tdbname, strerror(errno)));
		return false;
	}
	ntdb = db_open_ntdb(ctx, lp_ctx, ntdbname, dbwrap_hash_size(tdb),
			    TDB_DEFAULT, O_RDWR|O_CREAT|O_EXCL,
			    st.st_mode & 0777, DBWRAP_LOCK_ORDER_NONE,
			    DBWRAP_FLAG_NONE);
	if (!ntdb) {
		DEBUG(0, ("tdb_to_ntdb: could not create %s: %s\n",
			  ntdbname, strerror(errno)));
		return false;
	}
	bakname = talloc_asprintf(ctx, "%s.bak", tdbname);
	if (!bakname) {
		DEBUG(0, ("tdb_to_ntdb: could not allocate\n"));
		return false;
	}

	tdata.status = NT_STATUS_OK;
	tdata.ntdb = ntdb;
	if (!NT_STATUS_IS_OK(dbwrap_traverse_read(tdb, write_to_ntdb, &tdata,
						  NULL))) {
		return false;
	}
	if (!NT_STATUS_IS_OK(tdata.status)) {
		return false;
	}

	if (rename(tdbname, bakname) != 0) {
		DEBUG(0, ("tdb_to_ntdb: could not rename %s to %s\n",
			  tdbname, bakname));
		unlink(ntdbname);
		return false;
	}

	/* Make sure it's never accidentally used. */
	symlink("This is now in an NTDB", tdbname);

	/* Make message a bit shorter by using basenames. */
	tdbbase = strrchr(tdbname, '/');
	if (!tdbbase)
		tdbbase = tdbname;
	bakbase = strrchr(bakname, '/');
	if (!bakbase)
		bakbase = bakname;
	DEBUG(1, ("Upgraded %s from %s (which moved to %s)\n",
		  ntdbname, tdbbase, bakbase));
	return true;
}

struct db_context *dbwrap_local_open(TALLOC_CTX *mem_ctx,
				     struct loadparm_context *lp_ctx,
				     const char *name,
				     int hash_size, int tdb_flags,
				     int open_flags, mode_t mode,
				     enum dbwrap_lock_order lock_order,
				     uint64_t dbwrap_flags)
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
		DEBUG(1, ("WARNING: database '%s' does not end in .[n]tdb:"
			  " treating it as a TDB file!\n", name));
		ntdbname = talloc_strdup(tmp_ctx, name);
		tdbname = name;
	}

	if (ntdbname == NULL || tdbname == NULL) {
		DEBUG(0, ("talloc failed\n"));
		goto out;
	}

	if (name == ntdbname) {
		int ntdb_flags = tdb_flags_to_ntdb_flags(tdb_flags);

		/* For non-internal databases, we upgrade on demand. */
		if (!(tdb_flags & TDB_INTERNAL)) {
			if (!file_exist(ntdbname) && file_exist(tdbname)) {
				if (!tdb_to_ntdb(tmp_ctx, lp_ctx,
						 tdbname, ntdbname)) {
					goto out;
				}
			}
		}
		db = db_open_ntdb(mem_ctx, lp_ctx, ntdbname, hash_size,
				  ntdb_flags, open_flags, mode, lock_order,
				  dbwrap_flags);
	} else {
		if (!streq(ntdbname, tdbname) && file_exist(ntdbname)) {
			DEBUG(0, ("Refusing to open '%s' when '%s' exists\n",
				  tdbname, ntdbname));
			goto out;
		}
		db = db_open_tdb(mem_ctx, lp_ctx, tdbname, hash_size,
				 tdb_flags, open_flags, mode,
				 lock_order, dbwrap_flags);
	}
out:
	talloc_free(tmp_ctx);
	return db;
}
