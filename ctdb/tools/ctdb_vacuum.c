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
#include "../common/rb_tree.h"
#include "db_wrap.h"

/* should be tunable */
#define TIMELIMIT() timeval_current_ofs(10, 0)


/* 
   a list of records to possibly delete
 */
struct vacuum_data {
	uint32_t vacuum_limit;
	struct ctdb_context *ctdb;
	struct ctdb_db_context *ctdb_db;
	trbt_tree_t *delete_tree;
	uint32_t delete_count;
	struct ctdb_control_pulldb_reply **list;
	bool traverse_error;
	uint32_t total;
};

/* this structure contains the information for one record to be deleted */
struct delete_record_data {
	struct ctdb_context *ctdb;
	struct ctdb_db_context *ctdb_db;
	struct ctdb_ltdb_header hdr;
	TDB_DATA key;
};

/*
  traverse function for vacuuming
 */
static int vacuum_traverse(struct tdb_context *tdb, TDB_DATA key, TDB_DATA data, void *private)
{
	struct vacuum_data *vdata = talloc_get_type(private, struct vacuum_data);
	struct ctdb_context *ctdb = vdata->ctdb;
	struct ctdb_db_context *ctdb_db = vdata->ctdb_db;
	uint32_t lmaster;
	struct ctdb_ltdb_header *hdr;
	struct ctdb_rec_data *rec;
	size_t old_size;
	       
	lmaster = ctdb_lmaster(ctdb, &key);
	if (lmaster >= ctdb->vnn_map->size) {
		return 0;
	}

	if (data.dsize != sizeof(struct ctdb_ltdb_header)) {
		/* its not a deleted record */
		return 0;
	}

	hdr = (struct ctdb_ltdb_header *)data.dptr;

	if (hdr->dmaster != ctdb->pnn) {
		return 0;
	}


	/* is this a records we could possibly delete? I.e.
	   if the record is empty and also we are both lmaster
	   and dmaster for the record we should be able to delete it
	*/
	if ( (lmaster == ctdb->pnn)
	   &&( (vdata->delete_count < vdata->vacuum_limit)
	     ||(vdata->vacuum_limit == 0) ) ){
		uint32_t hash;

		hash = ctdb_hash(&key);
		if (trbt_lookup32(vdata->delete_tree, hash)) {
			DEBUG(DEBUG_INFO, (__location__ " Hash collission when vacuuming, skipping this record.\n"));
		} else {
			struct delete_record_data *dd;

			/* store key and header indexed by the key hash */
			dd = talloc_zero(vdata->delete_tree, struct delete_record_data);
			if (dd == NULL) {
				DEBUG(DEBUG_ERR,(__location__ " Out of memory\n"));
				return -1;
			}
			dd->ctdb      = ctdb;
			dd->ctdb_db   = ctdb_db;
			dd->key.dsize = key.dsize;
			dd->key.dptr  = talloc_memdup(dd, key.dptr, key.dsize);
			if (dd->key.dptr == NULL) {
				DEBUG(DEBUG_ERR,(__location__ " Out of memory\n"));
				return -1;
			}

			dd->hdr = *hdr;

	
			trbt_insert32(vdata->delete_tree, hash, dd);

			vdata->delete_count++;
		}
	}


	/* add the record to the blob ready to send to the nodes */
	rec = ctdb_marshall_record(vdata->list[lmaster], ctdb->pnn, key, NULL, tdb_null);
	if (rec == NULL) {
		DEBUG(DEBUG_ERR,(__location__ " Out of memory\n"));
		vdata->traverse_error = true;
		return -1;
	}
	old_size = talloc_get_size(vdata->list[lmaster]);
	vdata->list[lmaster] = talloc_realloc_size(NULL, vdata->list[lmaster], 
						   old_size + rec->length);
	if (vdata->list[lmaster] == NULL) {
		DEBUG(DEBUG_ERR,(__location__ " Failed to expand\n"));
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

struct delete_records_list {
	struct ctdb_control_pulldb_reply *records;
};

/*
 traverse the tree of records to delete and marshall them into
 a blob
*/
static void
delete_traverse(void *param, void *data)
{
	struct delete_record_data *dd = talloc_get_type(data, struct delete_record_data);
	struct delete_records_list *recs = talloc_get_type(param, struct delete_records_list);
	struct ctdb_rec_data *rec;
	size_t old_size;

	rec = ctdb_marshall_record(dd, recs->records->db_id, dd->key, &dd->hdr, tdb_null);
	if (rec == NULL) {
		DEBUG(DEBUG_ERR, (__location__ " failed to marshall record\n"));
		return;
	}

	old_size = talloc_get_size(recs->records);
	recs->records = talloc_realloc_size(NULL, recs->records, old_size + rec->length);
	if (recs->records == NULL) {
		DEBUG(DEBUG_ERR,(__location__ " Failed to expand\n"));
		return;
	}
	recs->records->count++;
	memcpy(old_size+(uint8_t *)(recs->records), rec, rec->length);
}


static void delete_record(void *param, void *d)
{
	struct delete_record_data *dd = talloc_get_type(d, struct delete_record_data);
	struct ctdb_context *ctdb = dd->ctdb;
	struct ctdb_db_context *ctdb_db = dd->ctdb_db;
	uint32_t *count = (uint32_t *)param;
	struct ctdb_ltdb_header *hdr;
	TDB_DATA data;

	/* its deleted on all other nodes - refetch, check and delete */
	if (tdb_chainlock_nonblock(ctdb_db->ltdb->tdb, dd->key) != 0) {
		/* the chain is busy - come back later */
		return;
	}

	data = tdb_fetch(ctdb_db->ltdb->tdb, dd->key);
	if (data.dptr == NULL) {
		tdb_chainunlock(ctdb_db->ltdb->tdb, dd->key);
		return;
	}
	if (data.dsize != sizeof(struct ctdb_ltdb_header)) {
		free(data.dptr);
		tdb_chainunlock(ctdb_db->ltdb->tdb, dd->key);
		return;
	}

	hdr = (struct ctdb_ltdb_header *)data.dptr;

	/* if we are not the lmaster and the dmaster then skip the record */
	if (hdr->dmaster != ctdb->pnn ||
	    ctdb_lmaster(ctdb, &(dd->key)) != ctdb->pnn ||
	    dd->hdr.rsn != hdr->rsn) {
		tdb_chainunlock(ctdb_db->ltdb->tdb, dd->key);
		free(data.dptr);
		return;
	}

	ctdb_block_signal(SIGALRM);
	tdb_delete(ctdb_db->ltdb->tdb, dd->key);
	ctdb_unblock_signal(SIGALRM);
	tdb_chainunlock(ctdb_db->ltdb->tdb, dd->key);
	free(data.dptr);

	(*count)++;
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
		DEBUG(DEBUG_ERR,(__location__ " Out of memory\n"));
		return -1;
	}

	vdata->ctdb = ctdb;
	vdata->vacuum_limit = vacuum_limit;
	vdata->delete_tree = trbt_create(vdata, 0);
	if (vdata->delete_tree == NULL) {
		DEBUG(DEBUG_ERR,(__location__ " Out of memory\n"));
		return -1;
	}

	if (ctdb_ctrl_getdbname(ctdb, TIMELIMIT(), CTDB_CURRENT_NODE, db_id, vdata, &name) != 0) {
		DEBUG(DEBUG_ERR,(__location__ " Failed to get name of db 0x%x\n", db_id));
		talloc_free(vdata);
		return -1;
	}

	ctdb_db = ctdb_attach(ctdb, name, persistent);
	if (ctdb_db == NULL) {
		DEBUG(DEBUG_ERR,(__location__ " Failed to attach to database '%s'\n", name));
		talloc_free(vdata);
		return -1;
	}
	vdata->ctdb_db = ctdb_db;

	/* the list needs to be of length num_nodes */
	vdata->list = talloc_array(vdata, struct ctdb_control_pulldb_reply *, ctdb->vnn_map->size);
	if (vdata->list == NULL) {
		DEBUG(DEBUG_ERR,(__location__ " Out of memory\n"));
		talloc_free(vdata);
		return -1;
	}
	for (i=0;i<ctdb->vnn_map->size;i++) {
		vdata->list[i] = (struct ctdb_control_pulldb_reply *)
			talloc_zero_size(vdata->list, 
				    offsetof(struct ctdb_control_pulldb_reply, data));
		if (vdata->list[i] == NULL) {
			DEBUG(DEBUG_ERR,(__location__ " Out of memory\n"));
			talloc_free(vdata);
			return -1;
		}
		vdata->list[i]->db_id = db_id;
	}

	/* traverse, looking for records that might be able to be vacuumed */
	if (tdb_traverse_read(ctdb_db->ltdb->tdb, vacuum_traverse, vdata) == -1 ||
	    vdata->traverse_error) {
		DEBUG(DEBUG_ERR,(__location__ " Traverse error in vacuuming '%s'\n", name));
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
				DEBUG(DEBUG_ERR,(__location__ " Failed to send vacuum fetch message to %u\n",
					 ctdb->vnn_map->map[i]));
				talloc_free(vdata);
				return -1;		
			}
			continue;
		}
	}	


	/* Process all records we can delete (if any) */
	if (vdata->delete_count > 0) {
		struct delete_records_list *recs;
		TDB_DATA indata, outdata;
		int ret;
		int32_t res;
		uint32_t count;

		recs = talloc_zero(vdata, struct delete_records_list);
		if (recs == NULL) {
			DEBUG(DEBUG_ERR,(__location__ " Out of memory\n"));
			return -1;
		}
		recs->records = (struct ctdb_control_pulldb_reply *)
			talloc_zero_size(vdata, 
				    offsetof(struct ctdb_control_pulldb_reply, data));
		if (recs->records == NULL) {
			DEBUG(DEBUG_ERR,(__location__ " Out of memory\n"));
			return -1;
		}
		recs->records->db_id = db_id;

		/* traverse the tree of all records we want to delete and
		   create a blob we can send to the other nodes.
		*/
		trbt_traversearray32(vdata->delete_tree, 1, delete_traverse, recs);

		indata.dsize = talloc_get_size(recs->records);
		indata.dptr  = (void *)recs->records;

		/* now tell all the other nodes to delete all these records
		   (if possible)
		 */
		for (i=0;i<ctdb->vnn_map->size;i++) {
			struct ctdb_control_pulldb_reply *records;
			struct ctdb_rec_data *rec;

			if (ctdb->vnn_map->map[i] == ctdb->pnn) {
				/* we dont delete the records on the local node
				   just yet
				*/
				continue;
			}

			ret = ctdb_control(ctdb, ctdb->vnn_map->map[i], 0,
					CTDB_CONTROL_TRY_DELETE_RECORDS, 0,
					indata, recs, &outdata, &res,
					NULL, NULL);
			if (ret != 0 || res != 0) {
				DEBUG(DEBUG_ERR,("Failed to delete records on node %u\n", ctdb->vnn_map->map[i]));
				exit(10);
			}

			/* outdata countains the list of records coming back
			   from the node which the node could not delete
			*/
			records = (struct ctdb_control_pulldb_reply *)outdata.dptr;
			rec = (struct ctdb_rec_data *)&records->data[0];
			while (records->count-- > 1) {
				TDB_DATA reckey, recdata;
				struct ctdb_ltdb_header *rechdr;

				reckey.dptr = &rec->data[0];
				reckey.dsize = rec->keylen;
				recdata.dptr = &rec->data[reckey.dsize];
				recdata.dsize = rec->datalen;

				if (recdata.dsize < sizeof(struct ctdb_ltdb_header)) {
					DEBUG(DEBUG_CRIT,(__location__ " bad ltdb record\n"));
					exit(10);
				}
				rechdr = (struct ctdb_ltdb_header *)recdata.dptr;
				recdata.dptr += sizeof(*rechdr);
				recdata.dsize -= sizeof(*rechdr);

				/* that other node couldnt delete the record
				   so we shouldnt delete it either.
				   remove it from the tree.
				*/
				talloc_free(trbt_lookup32(vdata->delete_tree, ctdb_hash(&reckey)));

				rec = (struct ctdb_rec_data *)(rec->length + (uint8_t *)rec);
			}	    
		}


		/* the only records remaining in the tree would be those
		   records where all other nodes could successfully
		   delete them, so we can now safely delete them on the
		   lmaster as well.
		*/
		count = 0;
		trbt_traversearray32(vdata->delete_tree, 1, delete_record, &count);
		if (vdata->delete_count != 0) {
			printf("Deleted %u records out of %u on this node from '%s'\n", count, vdata->delete_count, name);
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
		DEBUG(DEBUG_ERR, ("Unable to get dbids from local node\n"));
		return ret;
	}

	ret = ctdb_ctrl_getnodemap(ctdb, TIMELIMIT(), CTDB_CURRENT_NODE, ctdb, &nodemap);
	if (ret != 0) {
		DEBUG(DEBUG_ERR, ("Unable to get nodemap from local node\n"));
		return ret;
	}

	ret = ctdb_ctrl_getvnnmap(ctdb, TIMELIMIT(), CTDB_CURRENT_NODE, ctdb, &ctdb->vnn_map);
	if (ret != 0) {
		DEBUG(DEBUG_ERR, ("Unable to get vnnmap from local node\n"));
		return ret;
	}

	pnn = ctdb_ctrl_getpnn(ctdb, TIMELIMIT(), CTDB_CURRENT_NODE);
	if (pnn == -1) {
		DEBUG(DEBUG_ERR, ("Unable to get pnn from local node\n"));
		return -1;
	}
	ctdb->pnn = pnn;

	for (i=0;i<dbmap->num;i++) {
		if (ctdb_vacuum_db(ctdb, dbmap->dbs[i].dbid, nodemap, 
				   dbmap->dbs[i].persistent, vacuum_limit) != 0) {
			DEBUG(DEBUG_ERR,("Failed to vacuum db 0x%x\n", dbmap->dbs[i].dbid));
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
		DEBUG(DEBUG_ERR,(__location__ " Failed to start transaction\n"));
		return -1;
	}

	tmp_db = tdb_open("tmpdb", tdb_hash_size(tdb), TDB_INTERNAL, O_RDWR|O_CREAT, 0);
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

	ctdb_db = ctdb_attach(ctdb, name, persistent);
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
				   dbmap->dbs[i].persistent, repack_limit) != 0) {
			DEBUG(DEBUG_ERR,("Failed to repack db 0x%x\n", dbmap->dbs[i].dbid));
			return -1;
		}
	}

	return 0;
}
