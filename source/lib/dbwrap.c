/* 
   Unix SMB/CIFS implementation.
   Database interface wrapper
   Copyright (C) Jim McDonough <jmcd@us.ibm.com> 2006

   Major code contributions from Aleksey Fedoseev (fedoseev@ru.ibm.com)
   
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
#ifdef CLUSTER_SUPPORT
#include "ctdb_private.h"
#endif
/*
 * Fall back using fetch_locked if no genuine fetch operation is provided
 */

static int dbwrap_fallback_fetch(struct db_context *db, TALLOC_CTX *mem_ctx,
				 TDB_DATA key, TDB_DATA *data)
{
	struct db_record *rec;

	if (!(rec = db->fetch_locked(db, mem_ctx, key))) {
		return -1;
	}

	data->dsize = rec->value.dsize;
	data->dptr = talloc_move(mem_ctx, &rec->value.dptr);
	TALLOC_FREE(rec);
	return 0;
}

bool db_is_local(const char *name)
{
#ifdef CLUSTER_SUPPORT
	const char *sockname = lp_ctdbd_socket();

	if(!sockname || !*sockname) {
		sockname = CTDB_PATH;
	}

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
#endif
	return true;
}

/**
 * If you need transaction support use db_open_trans()
 */
struct db_context *db_open(TALLOC_CTX *mem_ctx,
			   const char *name,
			   int hash_size, int tdb_flags,
			   int open_flags, mode_t mode)
{
	struct db_context *result = NULL;
#ifdef CLUSTER_SUPPORT
	const char *sockname = lp_ctdbd_socket();
#endif

#ifdef CLUSTER_SUPPORT
	if(!sockname || !*sockname) {
		sockname = CTDB_PATH;
	}

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
			result = db_open_ctdb(mem_ctx, partname, hash_size,
					      tdb_flags, open_flags, mode);
			if (result == NULL) {
				DEBUG(0,("failed to attach to ctdb %s\n",
					 partname));
				smb_panic("failed to attach to a ctdb "
					  "database");
			}
		}
	}

#endif

	if (result == NULL) {
		result = db_open_tdb(mem_ctx, name, hash_size,
				     tdb_flags, open_flags, mode);
	}

	if ((result != NULL) && (result->fetch == NULL)) {
		result->fetch = dbwrap_fallback_fetch;
	}

	return result;
}

/**
 * If you use this you can only modify with a transaction
 */
struct db_context *db_open_trans(TALLOC_CTX *mem_ctx,
				 const char *name,
				 int hash_size, int tdb_flags,
				 int open_flags, mode_t mode)
{
	bool use_tdb2 = lp_parm_bool(-1, "dbwrap", "use_tdb2", false);
#ifdef CLUSTER_SUPPORT
	const char *sockname = lp_ctdbd_socket();
#endif

	if (tdb_flags & TDB_CLEAR_IF_FIRST) {
		DEBUG(0,("db_open_trans: called with TDB_CLEAR_IF_FIRST: %s\n",
			 name));
		smb_panic("db_open_trans: called with TDB_CLEAR_IF_FIRST");
	}

#ifdef CLUSTER_SUPPORT
	if(!sockname || !*sockname) {
		sockname = CTDB_PATH;
	}

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
		if (lp_parm_bool(-1, "ctdb", partname, true)) {
			struct db_context *result = NULL;
			result = db_open_ctdb(mem_ctx, partname, hash_size,
					      tdb_flags, open_flags, mode);
			if (result == NULL) {
				DEBUG(0,("failed to attach to ctdb %s\n",
					 partname));
				smb_panic("failed to attach to a ctdb "
					  "database");
			}
			return result;
		}
	}
#endif

	if (use_tdb2) {
		const char *partname;
		/* tdb2 only wants the file part of the name */
		partname = strrchr(name, '/');
		if (partname) {
			partname++;
		} else {
			partname = name;
		}
		/* allow ctdb for individual databases to be disabled */
		if (lp_parm_bool(-1, "tdb2", partname, true)) {
			return db_open_tdb2(mem_ctx, partname, hash_size,
					    tdb_flags, open_flags, mode);
		}
	}

	return db_open_tdb(mem_ctx, name, hash_size,
			   tdb_flags, open_flags, mode);
}

NTSTATUS dbwrap_delete_bystring(struct db_context *db, const char *key)
{
	struct db_record *rec;
	NTSTATUS status;

	rec = db->fetch_locked(db, talloc_tos(), string_term_tdb_data(key));
	if (rec == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	status = rec->delete_rec(rec);
	TALLOC_FREE(rec);
	return status;
}

NTSTATUS dbwrap_store_bystring(struct db_context *db, const char *key,
			       TDB_DATA data, int flags)
{
	struct db_record *rec;
	NTSTATUS status;

	rec = db->fetch_locked(db, talloc_tos(), string_term_tdb_data(key));
	if (rec == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	status = rec->store(rec, data, flags);
	TALLOC_FREE(rec);
	return status;
}

TDB_DATA dbwrap_fetch_bystring(struct db_context *db, TALLOC_CTX *mem_ctx,
			       const char *key)
{
	TDB_DATA result;

	if (db->fetch(db, mem_ctx, string_term_tdb_data(key), &result) == -1) {
		return make_tdb_data(NULL, 0);
	}

	return result;
}
