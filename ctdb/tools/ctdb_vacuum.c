/* 
   ctdb control tool - database vacuum 

   Copyright (C) Andrew Tridgell  2008

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program; if not, see <http://www.gnu.org/licenses/>.
*/

#include "includes.h"
#include "system/filesys.h"
#include "system/network.h"
#include "../include/ctdb_client.h"
#include "../include/ctdb_private.h"
#include "../common/rb_tree.h"
#include "lib/tdb_wrap/tdb_wrap.h"

/* should be tunable */
#define TIMELIMIT() timeval_current_ofs(10, 0)


struct vacuum_traverse_state {
	bool error;
	struct tdb_context *dest_db;
};

/*
  traverse function for repacking
 */
static int repack_traverse(struct tdb_context *tdb, TDB_DATA key, TDB_DATA data, void *private)
{
	struct vacuum_traverse_state *state = (struct vacuum_traverse_state *)private;
	if (tdb_store(state->dest_db, key, data, TDB_INSERT) != 0) {
		state->error = true;
		return -1;
	}
	return 0;
}

/*
  repack a tdb
 */
static int ctdb_repack_tdb(struct tdb_context *tdb)
{
	struct tdb_context *tmp_db;
	struct vacuum_traverse_state state;

	if (tdb_transaction_start(tdb) != 0) {
		DEBUG(DEBUG_ERR,(__location__ " Failed to start transaction\n"));
		return -1;
	}

	tmp_db = tdb_open("tmpdb", tdb_hash_size(tdb),
			  TDB_INTERNAL|TDB_DISALLOW_NESTING,
			  O_RDWR|O_CREAT, 0);
	if (tmp_db == NULL) {
		DEBUG(DEBUG_ERR,(__location__ " Failed to create tmp_db\n"));
		tdb_transaction_cancel(tdb);
		return -1;
	}

	state.error = false;
	state.dest_db = tmp_db;

	if (tdb_traverse_read(tdb, repack_traverse, &state) == -1) {
		DEBUG(DEBUG_ERR,(__location__ " Failed to traverse copying out\n"));
		tdb_transaction_cancel(tdb);
		tdb_close(tmp_db);
		return -1;		
	}

	if (state.error) {
		DEBUG(DEBUG_ERR,(__location__ " Error during traversal\n"));
		tdb_transaction_cancel(tdb);
		tdb_close(tmp_db);
		return -1;
	}

	if (tdb_wipe_all(tdb) != 0) {
		DEBUG(DEBUG_ERR,(__location__ " Failed to wipe database\n"));
		tdb_transaction_cancel(tdb);
		tdb_close(tmp_db);
		return -1;
	}

	state.error = false;
	state.dest_db = tdb;

	if (tdb_traverse_read(tmp_db, repack_traverse, &state) == -1) {
		DEBUG(DEBUG_ERR,(__location__ " Failed to traverse copying back\n"));
		tdb_transaction_cancel(tdb);
		tdb_close(tmp_db);
		return -1;		
	}

	if (state.error) {
		DEBUG(DEBUG_ERR,(__location__ " Error during second traversal\n"));
		tdb_transaction_cancel(tdb);
		tdb_close(tmp_db);
		return -1;
	}

	tdb_close(tmp_db);

	if (tdb_transaction_commit(tdb) != 0) {
		DEBUG(DEBUG_ERR,(__location__ " Failed to commit\n"));
		return -1;
	}

	return 0;
}


/* repack one database */
static int ctdb_repack_db(struct ctdb_context *ctdb, uint32_t db_id, 
			  bool persistent, uint32_t repack_limit)
{
	struct ctdb_db_context *ctdb_db;
	const char *name;
	int size;

	if (ctdb_ctrl_getdbname(ctdb, TIMELIMIT(), CTDB_CURRENT_NODE, db_id, ctdb, &name) != 0) {
		DEBUG(DEBUG_ERR,(__location__ " Failed to get name of db 0x%x\n", db_id));
		return -1;
	}

	ctdb_db = ctdb_attach(ctdb, TIMELIMIT(), name, persistent, 0);
	if (ctdb_db == NULL) {
		DEBUG(DEBUG_ERR,(__location__ " Failed to attach to database '%s'\n", name));
		return -1;
	}

	size = tdb_freelist_size(ctdb_db->ltdb->tdb);
	if (size == -1) {
		DEBUG(DEBUG_ERR,(__location__ " Failed to get freelist size for '%s'\n", name));
		return -1;
	}

	if (size <= repack_limit) {
		return 0;
	}

	printf("Repacking %s with %u freelist entries\n", name, size);

	if (ctdb_repack_tdb(ctdb_db->ltdb->tdb) != 0) {
		DEBUG(DEBUG_ERR,(__location__ " Failed to repack '%s'\n", name));
		return -1;
	}

	return 0;
}


/*
  repack all our databases
 */
int ctdb_repack(struct ctdb_context *ctdb, int argc, const char **argv)
{
	struct ctdb_dbid_map *dbmap=NULL;
	int ret, i;
	/* a reasonable default limit to prevent us using too much memory */
	uint32_t repack_limit = 10000; 

	if (argc > 0) {
		repack_limit = atoi(argv[0]);
	}

	ret = ctdb_ctrl_getdbmap(ctdb, TIMELIMIT(), CTDB_CURRENT_NODE, ctdb, &dbmap);
	if (ret != 0) {
		DEBUG(DEBUG_ERR, ("Unable to get dbids from local node\n"));
		return ret;
	}

	for (i=0;i<dbmap->num;i++) {
		if (ctdb_repack_db(ctdb, dbmap->dbs[i].dbid, 
				   dbmap->dbs[i].flags & CTDB_DB_FLAGS_PERSISTENT, repack_limit) != 0) {
			DEBUG(DEBUG_ERR,("Failed to repack db 0x%x\n", dbmap->dbs[i].dbid));
			return -1;
		}
	}

	return 0;
}
