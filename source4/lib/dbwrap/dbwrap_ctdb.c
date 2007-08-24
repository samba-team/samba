/* 
   Unix SMB/CIFS implementation.

   Database interface wrapper around ctdbd

   Copyright (C) Andrew Tridgell 2007
   
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
#include "lib/tdb/include/tdb.h"
#include "lib/dbwrap/dbwrap.h"
#include "cluster/cluster.h"
#include "cluster/ctdb/include/ctdb.h"

static NTSTATUS db_ctdb_store(struct db_record *rec, TDB_DATA data, int flag)
{
	struct ctdb_record_handle *h = talloc_get_type(rec->private_data, struct ctdb_record_handle);
	int ret;

	ret = ctdb_record_store(h, data);
	if (ret != 0) {
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}
	return NT_STATUS_OK;
}

static NTSTATUS db_ctdb_delete(struct db_record *rec)
{
	return rec->store(rec, tdb_null, TDB_REPLACE);
}


static struct db_record *db_ctdb_fetch_locked(struct db_context *db,
					      TALLOC_CTX *mem_ctx,
					      TDB_DATA key)
{
	struct db_record *rec;
	struct ctdb_record_handle *h;
	struct ctdb_db_context *cdb = talloc_get_type(db->private_data, struct ctdb_db_context);

	rec = talloc(mem_ctx, struct db_record);
	if (!rec) return NULL;

	h = ctdb_fetch_lock(cdb, rec, key, &rec->value);
	if (h == NULL) {
		talloc_free(rec);
		return NULL;
	}

	rec->private_data = h;
	rec->store        = db_ctdb_store;
	rec->delete_rec   = db_ctdb_delete;

	return rec;
}

/*
  fetch (unlocked, no migration) operation on ctdb
 */
static int db_ctdb_fetch(struct db_context *db, TALLOC_CTX *mem_ctx,
			 TDB_DATA key, TDB_DATA *data)
{
	struct ctdb_db_context *cdb = talloc_get_type(db->private_data, struct ctdb_db_context);

	return ctdb_fetch(cdb, mem_ctx, key, data);
}

struct traverse_state {
	struct db_context *db;
	int (*fn)(struct db_record *rec, void *private_data);
	void *private_data;
};

static int traverse_callback(struct ctdb_context *ctdb, TDB_DATA key, TDB_DATA data, void *private_data)
{
	struct traverse_state *state = (struct traverse_state *)private_data;
	struct db_record *rec;
	TALLOC_CTX *tmp_ctx = talloc_new(state->db);
	/* we have to give them a locked record to prevent races */
	rec = db_ctdb_fetch_locked(state->db, tmp_ctx, key);
	if (rec && rec->value.dsize > 0) {
		state->fn(rec, state->private_data);
	}
	talloc_free(tmp_ctx);
	return 0;
}

static int db_ctdb_traverse(struct db_context *db,
			    int (*fn)(struct db_record *rec, void *private_data),
			    void *private_data)
{
	struct ctdb_db_context *cdb = talloc_get_type(db->private_data, struct ctdb_db_context);
	struct traverse_state state;

	state.db = db;
	state.fn = fn;
	state.private_data = private_data;

	ctdb_traverse(cdb, traverse_callback, &state);
	return 0;
}

static NTSTATUS db_ctdb_store_deny(struct db_record *rec, TDB_DATA data, int flag)
{
	return NT_STATUS_MEDIA_WRITE_PROTECTED;
}

static NTSTATUS db_ctdb_delete_deny(struct db_record *rec)
{
	return NT_STATUS_MEDIA_WRITE_PROTECTED;
}

static int traverse_read_callback(struct ctdb_context *ctdb, 
				  TDB_DATA key, TDB_DATA data, void *private_data)
{
	struct traverse_state *state = (struct traverse_state *)private_data;
	struct db_record rec;
	rec.key = key;
	rec.value = data;
	rec.store = db_ctdb_store_deny;
	rec.delete_rec = db_ctdb_delete_deny;
	rec.private_data = state->db;
	state->fn(&rec, state->private_data);
	return 0;
}

static int db_ctdb_traverse_read(struct db_context *db,
				 int (*fn)(struct db_record *rec,
					   void *private_data),
				 void *private_data)
{
	struct traverse_state state;
	struct ctdb_db_context *cdb = talloc_get_type(db->private_data, struct ctdb_db_context);

	state.db = db;
	state.fn = fn;
	state.private_data = private_data;

	ctdb_traverse(cdb, traverse_read_callback, &state);
	return 0;
}

static int db_ctdb_get_seqnum(struct db_context *db)
{
	DEBUG(0,("ctdb_get_seqnum not implemented\n"));
	return -1;
}

struct db_context *db_tmp_open_ctdb(TALLOC_CTX *mem_ctx, const char *name, int tdb_flags)
{
	struct db_context *db;
	struct ctdb_context *ctdb = talloc_get_type(cluster_backend_handle(), 
						    struct ctdb_context);
	struct ctdb_db_context *cdb;

	db = talloc_zero(mem_ctx, struct db_context);
	if (db == NULL) {
		return NULL;
	}

	cdb = ctdb_attach(ctdb, name);
	if (!cdb) {
		DEBUG(0,("Failed to attach to ctdb database '%s'\n", name));
		talloc_free(db);
		return NULL;
	}

	db->private_data  = cdb;
	db->fetch_locked  = db_ctdb_fetch_locked;
	db->fetch         = db_ctdb_fetch;
	db->traverse      = db_ctdb_traverse;
	db->traverse_read = db_ctdb_traverse_read;
	db->get_seqnum    = db_ctdb_get_seqnum;

	DEBUG(3,("db_tmp_open_ctdb: opened database '%s'\n", name));

	return db;
}
