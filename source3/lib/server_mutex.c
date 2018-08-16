/* 
   Unix SMB/CIFS implementation.
   Authenticate against a remote domain
   Copyright (C) Andrew Tridgell 1992-2002
   Copyright (C) Andrew Bartlett 2002
   
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
#include "system/filesys.h"
#include "lib/tdb_wrap/tdb_wrap.h"
#include "util_tdb.h"
#include "lib/param/param.h"

/* For reasons known only to MS, many of their NT/Win2k versions
   need serialised access only.  Two connections at the same time
   may (in certain situations) cause connections to be reset,
   or access to be denied.

   This locking allows smbd's multithread architecture to look
   like the single-connection that NT makes. */

struct named_mutex {
	struct tdb_wrap *tdb;
	char *name;
};

static int unlock_named_mutex(struct named_mutex *mutex)
{
	tdb_unlock_bystring(mutex->tdb->tdb, mutex->name);
	return 0;
}

struct named_mutex *grab_named_mutex(TALLOC_CTX *mem_ctx, const char *name,
				     int timeout)
{
	struct named_mutex *result;
	struct loadparm_context *lp_ctx;
	char *fname;

	result = talloc(mem_ctx, struct named_mutex);
	if (result == NULL) {
		DEBUG(0, ("talloc failed\n"));
		return NULL;
	}

	lp_ctx = loadparm_init_s3(result, loadparm_s3_helpers());
	if (lp_ctx == NULL) {
		DEBUG(0, ("loadparm_init_s3 failed\n"));
		talloc_free(result);
		return NULL;
	}

	result->name = talloc_strdup(result, name);
	if (result->name == NULL) {
		DEBUG(0, ("talloc failed\n"));
		TALLOC_FREE(result);
		return NULL;
	}

	fname = lock_path(talloc_tos(), "mutex.tdb");
	if (fname == NULL) {
		TALLOC_FREE(result);
		return NULL;
	}

	result->tdb = tdb_wrap_open(result, fname,
				    lpcfg_tdb_hash_size(lp_ctx, fname),
				    lpcfg_tdb_flags(lp_ctx,
						    TDB_DEFAULT |
						    TDB_CLEAR_IF_FIRST |
						    TDB_INCOMPATIBLE_HASH),
				    O_RDWR|O_CREAT, 0600);
	TALLOC_FREE(fname);
	talloc_unlink(result, lp_ctx);
	if (result->tdb == NULL) {
		DEBUG(1, ("Could not open mutex.tdb: %s\n",
			  strerror(errno)));
		TALLOC_FREE(result);
		return NULL;
	}

	if (tdb_lock_bystring_with_timeout(result->tdb->tdb, name,
					   timeout) != 0) {
		DEBUG(1, ("Could not get the lock for %s\n", name));
		TALLOC_FREE(result);
		return NULL;
	}

	talloc_set_destructor(result, unlock_named_mutex);
	return result;
}
