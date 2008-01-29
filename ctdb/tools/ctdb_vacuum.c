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
#include "lib/events/events.h"
#include "system/filesys.h"
#include "system/network.h"
#include "../include/ctdb.h"
#include "../include/ctdb_private.h"
#include "db_wrap.h"

/* should be tunable */
#define TIMELIMIT() timeval_current_ofs(10, 0)

/*
  vacuum one record
 */
static int ctdb_vacuum_one(struct ctdb_context *ctdb, TDB_DATA key, 
			   struct ctdb_db_context *ctdb_db, uint32_t *count)
{
	TDB_DATA data;
	struct ctdb_ltdb_header *hdr;
	struct ctdb_rec_data *rec;
	uint64_t rsn;

	if (tdb_chainlock_nonblock(ctdb_db->ltdb->tdb, key) != 0) {
		/* the chain is busy - come back later */
		return 0;
	}

	data = tdb_fetch(ctdb_db->ltdb->tdb, key);
	tdb_chainunlock(ctdb_db->ltdb->tdb, key);
	if (data.dptr == NULL) {
		return 0;
	}
	if (data.dsize != sizeof(struct ctdb_ltdb_header)) {
		free(data.dptr);
		return 0;
	}


	hdr = (struct ctdb_ltdb_header *)data.dptr;
	rsn = hdr->rsn;

	/* if we are not the lmaster and the dmaster then skip the record */
	if (hdr->dmaster != ctdb->pnn ||
	    ctdb_lmaster(ctdb, &key) != ctdb->pnn) {
		free(data.dptr);
		return 0;
	}

	rec = ctdb_marshall_record(ctdb, ctdb_db->db_id, key, hdr, tdb_null);
	free(data.dptr);
	if (rec == NULL) {
		/* try it again later */
		return 0;
	}

	data.dptr = (void *)rec;
	data.dsize = rec->length;

	if (ctdb_client_async_control(ctdb, CTDB_CONTROL_DELETE_RECORD,
			list_of_vnnmap_nodes(ctdb, ctdb->vnn_map, rec, false),
			TIMELIMIT(), true, data) != 0) {
		/* one or more nodes failed to delete a record - no problem! */
		talloc_free(rec);
		return 0;
	}

	talloc_free(rec);

	/* its deleted on all other nodes - refetch, check and delete */
	if (tdb_chainlock_nonblock(ctdb_db->ltdb->tdb, key) != 0) {
		/* the chain is busy - come back later */
		return 0;
	}

	data = tdb_fetch(ctdb_db->ltdb->tdb, key);
	if (data.dptr == NULL) {
		tdb_chainunlock(ctdb_db->ltdb->tdb, key);
		return 0;
	}
	if (data.dsize != sizeof(struct ctdb_ltdb_header)) {
		free(data.dptr);
		tdb_chainunlock(ctdb_db->ltdb->tdb, key);
		return 0;
	}

	hdr = (struct ctdb_ltdb_header *)data.dptr;

	/* if we are not the lmaster and the dmaster then skip the record */
	if (hdr->dmaster != ctdb->pnn ||
	    ctdb_lmaster(ctdb, &key) != ctdb->pnn ||
	    rsn != hdr->rsn) {
		tdb_chainunlock(ctdb_db->ltdb->tdb, key);
		free(data.dptr);
		return 0;
	}

	ctdb_block_signal(SIGALRM);
	tdb_delete(ctdb_db->ltdb->tdb, key);
	ctdb_unblock_signal(SIGALRM);
	tdb_chainunlock(ctdb_db->ltdb->tdb, key);
	free(data.dptr);

	(*count)++;

	return 0;
}


/*
  vacuum records for which we are the lmaster 
 */
static int ctdb_vacuum_local(struct ctdb_context *ctdb, struct ctdb_control_pulldb_reply *list, 
			     struct ctdb_db_context *ctdb_db, uint32_t *count)
{
	struct ctdb_rec_data *r;
	int i;

	r = (struct ctdb_rec_data *)&list->data[0];
	
	for (i=0;
	     i<list->count;
	     r = (struct ctdb_rec_data *)(r->length + (uint8_t *)r), i++) {
		TDB_DATA key;
		key.dptr = &r->data[0];
		key.dsize = r->keylen;
		if (ctdb_vacuum_one(ctdb, key, ctdb_db, count) != 0) {
			return -1;
		}
	}

	return 0;	
}

/* 
   a list of records to possibly delete
 */
struct vacuum_data {
	uint32_t vacuum_limit;
	struct ctdb_context *ctdb;
	struct ctdb_control_pulldb_reply **list;
	bool traverse_error;
	uint32_t total;
};

/*
  traverse function for vacuuming
 */
static int vacuum_traverse(struct tdb_context *tdb, TDB_DATA key, TDB_DATA data, void *private)
{
	struct vacuum_data *vdata = talloc_get_type(private, struct vacuum_data);
	uint32_t lmaster;
	struct ctdb_ltdb_header *hdr;
	struct ctdb_rec_data *rec;
	size_t old_size;
	       
	lmaster = ctdb_lmaster(vdata->ctdb, &key);
	if (lmaster >= vdata->ctdb->vnn_map->size) {
		return 0;
	}

	if (data.dsize != sizeof(struct ctdb_ltdb_header)) {
		/* its not a deleted record */
		return 0;
	}

	hdr = (struct ctdb_ltdb_header *)data.dptr;

	if (hdr->dmaster != vdata->ctdb->pnn) {
		return 0;
	}


	/* add the record to the blob ready to send to the nodes */
	rec = ctdb_marshall_record(vdata->list[lmaster], vdata->ctdb->pnn, key, NULL, tdb_null);
	if (rec == NULL) {
		DEBUG(0,(__location__ " Out of memory\n"));
		vdata->traverse_error = true;
		return -1;
	}
	old_size = talloc_get_size(vdata->list[lmaster]);
	vdata->list[lmaster] = talloc_realloc_size(NULL, vdata->list[lmaster], 
						   old_size + rec->length);
	if (vdata->list[lmaster] == NULL) {
		DEBUG(0,(__location__ " Failed to expand\n"));
		vdata->traverse_error = true;
		return -1;
	}
	vdata->list[lmaster]->count++;
	memcpy(old_size+(uint8_t *)vdata->list[lmaster], rec, rec->length);
	talloc_free(rec);

	vdata->total++;

	/* don't gather too many records */
	if (vdata->vacuum_limit != 0 &&
	    vdata->total == vdata->vacuum_limit) {
		return -1;
	}

	return 0;
}


/* vacuum one database */
static int ctdb_vacuum_db(struct ctdb_context *ctdb, uint32_t db_id, struct ctdb_node_map *map,
			  bool persistent, uint32_t vacuum_limit)
{
	struct ctdb_db_context *ctdb_db;
	const char *name;
	struct vacuum_data *vdata;
	int i;

	vdata = talloc_zero(ctdb, struct vacuum_data);
	if (vdata == NULL) {
		DEBUG(0,(__location__ " Out of memory\n"));
		return -1;
	}

	vdata->ctdb = ctdb;
	vdata->vacuum_limit = vacuum_limit;

	if (ctdb_ctrl_getdbname(ctdb, TIMELIMIT(), CTDB_CURRENT_NODE, db_id, vdata, &name) != 0) {
		DEBUG(0,(__location__ " Failed to get name of db 0x%x\n", db_id));
		talloc_free(vdata);
		return -1;
	}

	ctdb_db = ctdb_attach(ctdb, name, persistent);
	if (ctdb_db == NULL) {
		DEBUG(0,(__location__ " Failed to attach to database '%s'\n", name));
		talloc_free(vdata);
		return -1;
	}

	/* the list needs to be of length num_nodes */
	vdata->list = talloc_array(vdata, struct ctdb_control_pulldb_reply *, ctdb->vnn_map->size);
	if (vdata->list == NULL) {
		DEBUG(0,(__location__ " Out of memory\n"));
		talloc_free(vdata);
		return -1;
	}
	for (i=0;i<ctdb->vnn_map->size;i++) {
		vdata->list[i] = (struct ctdb_control_pulldb_reply *)
			talloc_zero_size(vdata->list, 
				    offsetof(struct ctdb_control_pulldb_reply, data));
		if (vdata->list[i] == NULL) {
			DEBUG(0,(__location__ " Out of memory\n"));
			talloc_free(vdata);
			return -1;
		}
		vdata->list[i]->db_id = db_id;
	}

	/* traverse, looking for records that might be able to be vacuumed */
	if (tdb_traverse_read(ctdb_db->ltdb->tdb, vacuum_traverse, vdata) == -1 ||
	    vdata->traverse_error) {
		DEBUG(0,(__location__ " Traverse error in vacuuming '%s'\n", name));
		talloc_free(vdata);
		return -1;		
	}


	for (i=0;i<ctdb->vnn_map->size;i++) {
		if (vdata->list[i]->count == 0) {
			continue;
		}

		/* for records where we are not the lmaster, tell the lmaster to fetch the record */
		if (ctdb->vnn_map->map[i] != ctdb->pnn) {
			TDB_DATA data;
			printf("Found %u records for lmaster %u in '%s'\n", vdata->list[i]->count, i, name);

			data.dsize = talloc_get_size(vdata->list[i]);
			data.dptr  = (void *)vdata->list[i];
			if (ctdb_send_message(ctdb, ctdb->vnn_map->map[i], CTDB_SRVID_VACUUM_FETCH, data) != 0) {
				DEBUG(0,(__location__ " Failed to send vacuum fetch message to %u\n",
					 ctdb->vnn_map->map[i]));
				talloc_free(vdata);
				return -1;		
			}
			continue;
		}
	}	

	for (i=0;i<ctdb->vnn_map->size;i++) {
		uint32_t count = 0;

		if (vdata->list[i]->count == 0) {
			continue;
		}

		/* for records where we are the lmaster, we can try to delete them */
		if (ctdb_vacuum_local(ctdb, vdata->list[i], ctdb_db, &count) != 0) {
			DEBUG(0,(__location__ " Deletion error in vacuuming '%s'\n", name));
			talloc_free(vdata);
			return -1;					
		}
		if (count != 0) {
			printf("Deleted %u records on this node from '%s'\n", count, name);
		}
	}	

	/* this ensures we run our event queue */
	ctdb_ctrl_getpnn(ctdb, TIMELIMIT(), CTDB_CURRENT_NODE);

	talloc_free(vdata);

	return 0;
}


/*
  vacuum all our databases
 */
int ctdb_vacuum(struct ctdb_context *ctdb, int argc, const char **argv)
{
	struct ctdb_dbid_map *dbmap=NULL;
	struct ctdb_node_map *nodemap=NULL;
	int ret, i, pnn;
	uint32_t vacuum_limit = 0;

	if (argc > 0) {
		vacuum_limit = atoi(argv[0]);
	}

	ret = ctdb_ctrl_getdbmap(ctdb, TIMELIMIT(), CTDB_CURRENT_NODE, ctdb, &dbmap);
	if (ret != 0) {
		DEBUG(0, ("Unable to get dbids from local node\n"));
		return ret;
	}

	ret = ctdb_ctrl_getnodemap(ctdb, TIMELIMIT(), CTDB_CURRENT_NODE, ctdb, &nodemap);
	if (ret != 0) {
		DEBUG(0, ("Unable to get nodemap from local node\n"));
		return ret;
	}

	ret = ctdb_ctrl_getvnnmap(ctdb, TIMELIMIT(), CTDB_CURRENT_NODE, ctdb, &ctdb->vnn_map);
	if (ret != 0) {
		DEBUG(0, ("Unable to get vnnmap from local node\n"));
		return ret;
	}

	pnn = ctdb_ctrl_getpnn(ctdb, TIMELIMIT(), CTDB_CURRENT_NODE);
	if (pnn == -1) {
		DEBUG(0, ("Unable to get pnn from local node\n"));
		return -1;
	}
	ctdb->pnn = pnn;

	for (i=0;i<dbmap->num;i++) {
		if (ctdb_vacuum_db(ctdb, dbmap->dbs[i].dbid, nodemap, 
				   dbmap->dbs[i].persistent, vacuum_limit) != 0) {
			DEBUG(0,("Failed to vacuum db 0x%x\n", dbmap->dbs[i].dbid));
			return -1;
		}
	}

	return 0;
}

struct traverse_state {
	bool error;
	struct tdb_context *dest_db;
};

/*
  traverse function for repacking
 */
static int repack_traverse(struct tdb_context *tdb, TDB_DATA key, TDB_DATA data, void *private)
{
	struct traverse_state *state = (struct traverse_state *)private;
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
	struct traverse_state state;

	if (tdb_transaction_start(tdb) != 0) {
		DEBUG(0,(__location__ " Failed to start transaction\n"));
		return -1;
	}

	tmp_db = tdb_open("tmpdb", tdb_hash_size(tdb), TDB_INTERNAL, O_RDWR|O_CREAT, 0);
	if (tmp_db == NULL) {
		DEBUG(0,(__location__ " Failed to create tmp_db\n"));
		tdb_transaction_cancel(tdb);
		return -1;
	}

	state.error = false;
	state.dest_db = tmp_db;

	if (tdb_traverse_read(tdb, repack_traverse, &state) == -1) {
		DEBUG(0,(__location__ " Failed to traverse copying out\n"));
		tdb_transaction_cancel(tdb);
		tdb_close(tmp_db);
		return -1;		
	}

	if (state.error) {
		DEBUG(0,(__location__ " Error during traversal\n"));
		tdb_transaction_cancel(tdb);
		tdb_close(tmp_db);
		return -1;
	}

	if (tdb_wipe_all(tdb) != 0) {
		DEBUG(0,(__location__ " Failed to wipe database\n"));
		tdb_transaction_cancel(tdb);
		tdb_close(tmp_db);
		return -1;
	}

	state.error = false;
	state.dest_db = tdb;

	if (tdb_traverse_read(tmp_db, repack_traverse, &state) == -1) {
		DEBUG(0,(__location__ " Failed to traverse copying back\n"));
		tdb_transaction_cancel(tdb);
		tdb_close(tmp_db);
		return -1;		
	}

	if (state.error) {
		DEBUG(0,(__location__ " Error during second traversal\n"));
		tdb_transaction_cancel(tdb);
		tdb_close(tmp_db);
		return -1;
	}

	tdb_close(tmp_db);

	if (tdb_transaction_commit(tdb) != 0) {
		DEBUG(0,(__location__ " Failed to commit\n"));
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
		DEBUG(0,(__location__ " Failed to get name of db 0x%x\n", db_id));
		return -1;
	}

	ctdb_db = ctdb_attach(ctdb, name, persistent);
	if (ctdb_db == NULL) {
		DEBUG(0,(__location__ " Failed to attach to database '%s'\n", name));
		return -1;
	}

	size = tdb_freelist_size(ctdb_db->ltdb->tdb);
	if (size == -1) {
		DEBUG(0,(__location__ " Failed to get freelist size for '%s'\n", name));
		return -1;
	}

	if (size <= repack_limit) {
		return 0;
	}

	printf("Repacking %s with %u freelist entries\n", name, size);

	if (ctdb_repack_tdb(ctdb_db->ltdb->tdb) != 0) {
		DEBUG(0,(__location__ " Failed to repack '%s'\n", name));
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
		DEBUG(0, ("Unable to get dbids from local node\n"));
		return ret;
	}

	for (i=0;i<dbmap->num;i++) {
		if (ctdb_repack_db(ctdb, dbmap->dbs[i].dbid, 
				   dbmap->dbs[i].persistent, repack_limit) != 0) {
			DEBUG(0,("Failed to repack db 0x%x\n", dbmap->dbs[i].dbid));
			return -1;
		}
	}

	return 0;
}
