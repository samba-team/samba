/*
   ctdb vacuuming events

   Copyright (C) Ronnie Sahlberg  2009

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
#include "lib/tdb/include/tdb.h"
#include "system/network.h"
#include "system/filesys.h"
#include "system/dir.h"
#include "../include/ctdb_private.h"
#include "db_wrap.h"
#include "lib/util/dlinklist.h"
#include "lib/events/events.h"
#include "../include/ctdb_private.h"
#include "../common/rb_tree.h"

#define TIMELIMIT() timeval_current_ofs(10, 0)
#define TUNINGDBNAME "vactune.tdb"

enum vacuum_child_status { VACUUM_RUNNING, VACUUM_OK, VACUUM_ERROR, VACUUM_TIMEOUT};

struct ctdb_vacuum_child_context {
	struct ctdb_vacuum_handle *vacuum_handle;
	int fd[2];
	pid_t child_pid;
	enum vacuum_child_status status;
	struct timeval start_time;
};

struct ctdb_vacuum_handle {
	struct ctdb_db_context *ctdb_db;
	struct ctdb_vacuum_child_context *child_ctx;
};


/*  a list of records to possibly delete */
struct vacuum_data {
	uint32_t vacuum_limit;
	uint32_t repack_limit;
	struct ctdb_context *ctdb;
	struct ctdb_db_context *ctdb_db;
	struct tdb_context *dest_db;
	trbt_tree_t *delete_tree;
	uint32_t delete_count;
	struct ctdb_marshall_buffer **list;
	struct timeval start;
	bool traverse_error;
	bool vacuum;
	uint32_t total;
	uint32_t vacuumed;
	uint32_t copied;
};

/* tuning information stored for every db */
struct vacuum_tuning_data {
	uint32_t last_num_repack;
	uint32_t last_num_empty;
	uint32_t last_interval;
	uint32_t new_interval;
	struct timeval last_start;
	double   last_duration;
};

/* this structure contains the information for one record to be deleted */
struct delete_record_data {
	struct ctdb_context *ctdb;
	struct ctdb_db_context *ctdb_db;
	struct ctdb_ltdb_header hdr;
	TDB_DATA key;
};

struct delete_records_list {
	struct ctdb_marshall_buffer *records;
};

static void ctdb_vacuum_event(struct event_context *ev, struct timed_event *te, 
							  struct timeval t, void *private_data);


/*
 * traverse function for gathering the records that can be deleted
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
	if (lmaster == ctdb->pnn) {
		uint32_t hash;

		hash = ctdb_hash(&key);
		if (trbt_lookup32(vdata->delete_tree, hash)) {
			DEBUG(DEBUG_INFO, (__location__ " Hash collission when vacuuming, skipping this record.\n"));
		} 
		else {
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

	return 0;
}

/*
 * traverse the tree of records to delete and marshall them into
 * a blob
 */
static void delete_traverse(void *param, void *data)
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

/* 
 * read-only traverse the database in order to find
 * records that can be deleted and try to delete these
 * records on the other nodes
 * this executes in the child context
 */
static int ctdb_vacuum_db(struct ctdb_db_context *ctdb_db, struct vacuum_data *vdata)
{
	struct ctdb_context *ctdb = ctdb_db->ctdb;
	const char *name = ctdb_db->db_name;
	int ret, i, pnn;

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
	/* the list needs to be of length num_nodes */
	vdata->list = talloc_array(vdata, struct ctdb_marshall_buffer *, ctdb->vnn_map->size);
	if (vdata->list == NULL) {
		DEBUG(DEBUG_ERR,(__location__ " Out of memory\n"));
		return -1;
	}
	for (i = 0; i < ctdb->vnn_map->size; i++) {
		vdata->list[i] = (struct ctdb_marshall_buffer *)
			talloc_zero_size(vdata->list, 
							 offsetof(struct ctdb_marshall_buffer, data));
		if (vdata->list[i] == NULL) {
			DEBUG(DEBUG_ERR,(__location__ " Out of memory\n"));
			return -1;
		}
		vdata->list[i]->db_id = ctdb_db->db_id;
	}

	/* read-only traverse, looking for records that might be able to be vacuumed */
	if (tdb_traverse_read(ctdb_db->ltdb->tdb, vacuum_traverse, vdata) == -1 ||
	    vdata->traverse_error) {
		DEBUG(DEBUG_ERR,(__location__ " Traverse error in vacuuming '%s'\n", name));
		return -1;		
	}

	for ( i = 0; i < ctdb->vnn_map->size; i++) {
		if (vdata->list[i]->count == 0) {
			continue;
		}

		/* for records where we are not the lmaster, tell the lmaster to fetch the record */
		if (ctdb->vnn_map->map[i] != ctdb->pnn) {
			TDB_DATA data;
			DEBUG(DEBUG_NOTICE,("Found %u records for lmaster %u in '%s'\n", 
								vdata->list[i]->count, i, name));

			data.dsize = talloc_get_size(vdata->list[i]);
			data.dptr  = (void *)vdata->list[i];
			if (ctdb_send_message(ctdb, ctdb->vnn_map->map[i], CTDB_SRVID_VACUUM_FETCH, data) != 0) {
				DEBUG(DEBUG_ERR,(__location__ " Failed to send vacuum fetch message to %u\n",
					 ctdb->vnn_map->map[i]));
				return -1;		
			}
			continue;
		}
	}	

	/* Process all records we can delete (if any) */
	if (vdata->delete_count > 0) {
		struct delete_records_list *recs;
		TDB_DATA indata, outdata;
		int32_t res;

		recs = talloc_zero(vdata, struct delete_records_list);
		if (recs == NULL) {
			DEBUG(DEBUG_ERR,(__location__ " Out of memory\n"));
			return -1;
		}
		recs->records = (struct ctdb_marshall_buffer *)
			talloc_zero_size(vdata, 
				    offsetof(struct ctdb_marshall_buffer, data));
		if (recs->records == NULL) {
			DEBUG(DEBUG_ERR,(__location__ " Out of memory\n"));
			return -1;
		}
		recs->records->db_id = ctdb_db->db_id;

		/* 
		 * traverse the tree of all records we want to delete and
		 * create a blob we can send to the other nodes.
		 */
		trbt_traversearray32(vdata->delete_tree, 1, delete_traverse, recs);

		indata.dsize = talloc_get_size(recs->records);
		indata.dptr  = (void *)recs->records;

		/* 
		 * now tell all the other nodes to delete all these records
		 * (if possible)
		 */
		for (i = 0; i < ctdb->vnn_map->size; i++) {
			struct ctdb_marshall_buffer *records;
			struct ctdb_rec_data *rec;

			if (ctdb->vnn_map->map[i] == ctdb->pnn) {
				/* we dont delete the records on the local node just yet */
				continue;
			}

			ret = ctdb_control(ctdb, ctdb->vnn_map->map[i], 0,
					CTDB_CONTROL_TRY_DELETE_RECORDS, 0,
					indata, recs, &outdata, &res,
					NULL, NULL);
			if (ret != 0 || res != 0) {
				DEBUG(DEBUG_ERR,("Failed to delete records on node %u\n", ctdb->vnn_map->map[i]));
				return -1;
			}

			/* 
			 * outdata countains the list of records coming back
			 * from the node which the node could not delete
			 */
			records = (struct ctdb_marshall_buffer *)outdata.dptr;
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
					return -1;
				}
				rechdr = (struct ctdb_ltdb_header *)recdata.dptr;
				recdata.dptr += sizeof(*rechdr);
				recdata.dsize -= sizeof(*rechdr);

				/* 
				 * that other node couldnt delete the record
				 * so we should delete it and thereby remove it from the tree
				 */
				talloc_free(trbt_lookup32(vdata->delete_tree, ctdb_hash(&reckey)));

				rec = (struct ctdb_rec_data *)(rec->length + (uint8_t *)rec);
			}	    
		}

		/* 
		 * The only records remaining in the tree would be those
		 * records where all other nodes could successfully
		 * delete them, so we can safely delete them on the
		 * lmaster as well. Deletion implictely happens while
		 * we repack the database. The repack algorithm revisits 
		 * the tree in order to find the records that don't need
		 * to be copied / repacked.
		 */
	}

	/* this ensures we run our event queue */
	ctdb_ctrl_getpnn(ctdb, TIMELIMIT(), CTDB_CURRENT_NODE);

	return 0;
}


/*
 * traverse function for repacking
 */
static int repack_traverse(struct tdb_context *tdb, TDB_DATA key, TDB_DATA data, void *private)
{
	struct vacuum_data *vdata = (struct vacuum_data *)private;

	if (vdata->vacuum) {
		uint32_t hash = ctdb_hash(&key);
		struct delete_record_data *kd;
		/*
		 * check if we can ignore this record because it's in the delete_tree
		 */
		kd = (struct delete_record_data *)trbt_lookup32(vdata->delete_tree, hash);
		/*
		 * there might be hash collisions so we have to compare the keys here to be sure
		 */
		if (kd && kd->key.dsize == key.dsize && memcmp(kd->key.dptr, key.dptr, key.dsize) == 0) {
			vdata->vacuumed++;
			return 0;
		}
	}
	if (tdb_store(vdata->dest_db, key, data, TDB_INSERT) != 0) {
		vdata->traverse_error = true;
		return -1;
	}
	vdata->copied++;
	return 0;
}

/*
 * repack a tdb
 */
static int ctdb_repack_tdb(struct tdb_context *tdb, TALLOC_CTX *mem_ctx, struct vacuum_data *vdata)
{
	struct tdb_context *tmp_db;

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

	vdata->traverse_error = false;
	vdata->dest_db = tmp_db;
	vdata->vacuum = true;
	vdata->vacuumed = 0;
	vdata->copied = 0;

	/*
	 * repack and vacuum on-the-fly by not writing the records that are
	 * no longer needed
	 */
	if (tdb_traverse_read(tdb, repack_traverse, vdata) == -1) {
		DEBUG(DEBUG_ERR,(__location__ " Failed to traverse copying out\n"));
		tdb_transaction_cancel(tdb);
		tdb_close(tmp_db);
		return -1;		
	}

	DEBUG(DEBUG_NOTICE,(__location__ " %u records vacuumed\n", vdata->vacuumed));
	
	if (vdata->traverse_error) {
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

	vdata->traverse_error = false;
	vdata->dest_db = tdb;
	vdata->vacuum = false;
	vdata->copied = 0;

	if (tdb_traverse_read(tmp_db, repack_traverse, vdata) == -1) {
		DEBUG(DEBUG_ERR,(__location__ " Failed to traverse copying back\n"));
		tdb_transaction_cancel(tdb);
		tdb_close(tmp_db);
		return -1;		
	}

	if (vdata->traverse_error) {
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
	DEBUG(DEBUG_NOTICE,(__location__ " %u records copied\n", vdata->copied));

	return 0;
}

static int update_tuning_db(struct ctdb_db_context *ctdb_db, struct vacuum_data *vdata, uint32_t freelist)
{
	TALLOC_CTX *tmp_ctx = talloc_new(NULL);
	TDB_CONTEXT *tune_tdb;
	TDB_DATA key, value;
	struct vacuum_tuning_data tdata;
	struct vacuum_tuning_data *tptr;
	char *vac_dbname;

	vac_dbname = talloc_asprintf(tmp_ctx, "%s/%s.%u",
					ctdb_db->ctdb->db_directory, 
					TUNINGDBNAME, ctdb_db->ctdb->pnn);
	if (vac_dbname == NULL) {
		DEBUG(DEBUG_CRIT,(__location__ " Out of memory error while allocating '%s'\n", vac_dbname));
		talloc_free(tmp_ctx);
		return -1;
	}

	tune_tdb = tdb_open(vac_dbname, 0, 0, O_RDWR|O_CREAT, 0600);
	if (tune_tdb == NULL) {
		DEBUG(DEBUG_ERR,(__location__ " Failed to create/open %s\n", TUNINGDBNAME));
		talloc_free(tmp_ctx);
		return -1;
	}
	
	if (tdb_transaction_start(tune_tdb) != 0) {
		DEBUG(DEBUG_ERR,(__location__ " Failed to start transaction\n"));
		tdb_close(tune_tdb);
		return -1;
	}
	key.dptr = discard_const(ctdb_db->db_name);
	key.dsize = strlen(ctdb_db->db_name);
	value = tdb_fetch(tune_tdb, key);

	if (value.dptr != NULL && value.dsize == sizeof(struct vacuum_tuning_data)) {
		tptr = (struct vacuum_tuning_data *)value.dptr;
		tdata = *tptr;

		/*
		 * re-calc new vacuum interval:
		 * in case no limit was reached we continously increase the interval
		 * until vacuum_max_interval is reached
		 * in case a limit was reached we divide the current interval by 2
		 * unless vacuum_min_interval is reached
		 */
		if (freelist < vdata->repack_limit &&
		    vdata->delete_count < vdata->vacuum_limit) {
			if (tdata.last_interval < ctdb_db->ctdb->tunable.vacuum_max_interval) {
				tdata.new_interval = tdata.last_interval * 110 / 100;
				DEBUG(DEBUG_NOTICE,("Increasing vacuum interval %u -> %u for %s\n", 
					tdata.last_interval, tdata.new_interval, ctdb_db->db_name));
			}
		} else {
			tdata.new_interval = tdata.last_interval / 2;
			if (tdata.new_interval < ctdb_db->ctdb->tunable.vacuum_min_interval ||
				tdata.new_interval > ctdb_db->ctdb->tunable.vacuum_max_interval) {
				tdata.new_interval = ctdb_db->ctdb->tunable.vacuum_min_interval;
			}		
			DEBUG(DEBUG_ERR,("Decreasing vacuum interval %u -> %u for %s\n", 
					 tdata.last_interval, tdata.new_interval, ctdb_db->db_name));
		}
		tdata.last_interval = tdata.new_interval;
	} else {
		DEBUG(DEBUG_ERR,(__location__ " Cannot find tunedb record for %s. Using default interval\n", ctdb_db->db_name));
		tdata.last_num_repack = freelist;
		tdata.last_num_empty = vdata->delete_count;
		tdata.last_interval = ctdb_db->ctdb->tunable.vacuum_default_interval;
	}

	if (value.dptr != NULL) {
		free(value.dptr);
	}

	tdata.last_start = vdata->start;
	tdata.last_duration = timeval_elapsed(&vdata->start);

	value.dptr = (unsigned char *)&tdata;
	value.dsize = sizeof(tdata);

	if (tdb_store(tune_tdb, key, value, 0) != 0) {
		DEBUG(DEBUG_ERR,(__location__ " Unable to store tundb record for %s\n", ctdb_db->db_name));
		tdb_transaction_cancel(tune_tdb);
		tdb_close(tune_tdb);
		talloc_free(tmp_ctx);
		return -1;
	}
	tdb_transaction_commit(tune_tdb);
	tdb_close(tune_tdb);
	talloc_free(tmp_ctx);

	return 0;
}

/*
 * repack and vaccum a db
 * called from the child context
 */
static int ctdb_repack_db(struct ctdb_db_context *ctdb_db, TALLOC_CTX *mem_ctx)
{
	uint32_t repack_limit = ctdb_db->ctdb->tunable.repack_limit;
	uint32_t vacuum_limit = ctdb_db->ctdb->tunable.vacuum_limit;
	const char *name = ctdb_db->db_name;
	int size;
	struct vacuum_data *vdata;

	size = tdb_freelist_size(ctdb_db->ltdb->tdb);
	if (size == -1) {
		DEBUG(DEBUG_ERR,(__location__ " Failed to get freelist size for '%s'\n", name));
		return -1;
	}

	vdata = talloc_zero(mem_ctx, struct vacuum_data);
	if (vdata == NULL) {
		DEBUG(DEBUG_ERR,(__location__ " Out of memory\n"));
		return -1;
	}

	vdata->ctdb = ctdb_db->ctdb;
	vdata->vacuum_limit = vacuum_limit;
	vdata->repack_limit = repack_limit;
	vdata->delete_tree = trbt_create(vdata, 0);
	if (vdata->delete_tree == NULL) {
		DEBUG(DEBUG_ERR,(__location__ " Out of memory\n"));
		talloc_free(vdata);
		return -1;
	}

	vdata->start = timeval_current();
 
	/*
	 * gather all records that can be deleted in vdata
	 */
	if (ctdb_vacuum_db(ctdb_db, vdata) != 0) {
		DEBUG(DEBUG_ERR,(__location__ " Failed to vacuum '%s'\n", name));
	}

	/*
	 * decide if a repack is necessary
	 */
	if (size < repack_limit && vdata->delete_count < vacuum_limit) {
		talloc_free(vdata);
		update_tuning_db(ctdb_db, vdata, size);
		return 0;
	}

	DEBUG(DEBUG_NOTICE,("Repacking %s with %u freelist entries and %u records to delete\n", 
			name, size, vdata->delete_count));

	/*
	 * repack and implicitely get rid of the records we can delete
	 */
	if (ctdb_repack_tdb(ctdb_db->ltdb->tdb, mem_ctx, vdata) != 0) {
		DEBUG(DEBUG_ERR,(__location__ " Failed to repack '%s'\n", name));
		update_tuning_db(ctdb_db, vdata, size);
		talloc_free(vdata);
		return -1;
	}
	update_tuning_db(ctdb_db, vdata, size);
	talloc_free(vdata);

	return 0;
}

static int get_vacuum_interval(struct ctdb_db_context *ctdb_db)
{
	TALLOC_CTX *tmp_ctx = talloc_new(NULL);
	TDB_CONTEXT *tdb;
	TDB_DATA key, value;
	char *vac_dbname;
	uint interval = ctdb_db->ctdb->tunable.vacuum_default_interval;
	struct ctdb_context *ctdb = ctdb_db->ctdb;

	vac_dbname = talloc_asprintf(tmp_ctx, "%s/%s.%u", ctdb->db_directory, TUNINGDBNAME, ctdb->pnn);
	if (vac_dbname == NULL) {
		DEBUG(DEBUG_CRIT,(__location__ " Out of memory error while allocating '%s'\n", vac_dbname));
		talloc_free(tmp_ctx);
		return interval;
	}

	tdb = tdb_open(vac_dbname, 0, 0, O_RDONLY, 0600);
	if (!tdb) {
		DEBUG(DEBUG_ERR,("Unable to open database %s using default interval\n", vac_dbname));
		talloc_free(tmp_ctx);
		return interval;
	}

	key.dptr = discard_const(ctdb_db->db_name);
	key.dsize = strlen(ctdb_db->db_name);

	value = tdb_fetch(tdb, key);

	if (value.dptr != NULL) {
		if (value.dsize == sizeof(struct vacuum_tuning_data)) {
			struct vacuum_tuning_data *tptr = (struct vacuum_tuning_data *)value.dptr;

			interval = tptr->new_interval;

			if (interval < ctdb->tunable.vacuum_min_interval) {
				interval = ctdb->tunable.vacuum_min_interval;
			} 
			if (interval > ctdb->tunable.vacuum_max_interval) {
				interval = ctdb->tunable.vacuum_max_interval;
			}
		}
		free(value.dptr);

		DEBUG(DEBUG_NOTICE,("Using new interval %u for database %s\n", interval, ctdb_db->db_name));
	}
	tdb_close(tdb);

	talloc_free(tmp_ctx);

	return interval;
}

static int vacuum_child_destructor(struct ctdb_vacuum_child_context *child_ctx)
{
	double l = timeval_elapsed(&child_ctx->start_time);
	struct ctdb_db_context *ctdb_db = child_ctx->vacuum_handle->ctdb_db;
	struct ctdb_context *ctdb = ctdb_db->ctdb;

	DEBUG(DEBUG_ERR,("Vacuuming took %.3f seconds for database %s\n", l, ctdb_db->db_name));

	if (child_ctx->child_pid != -1) {
		kill(child_ctx->child_pid, SIGKILL);
	}

	event_add_timed(ctdb->ev, child_ctx->vacuum_handle,
			timeval_current_ofs(get_vacuum_interval(ctdb_db), 0), 
			ctdb_vacuum_event, child_ctx->vacuum_handle);

	return 0;
}

/*
 * this event is generated when a vacuum child process times out
 */
static void vacuum_child_timeout(struct event_context *ev, struct timed_event *te,
					 struct timeval t, void *private_data)
{
	struct ctdb_vacuum_child_context *child_ctx = talloc_get_type(private_data, struct ctdb_vacuum_child_context);

	DEBUG(DEBUG_ERR,("Vacuuming child process timed out for db %s\n", child_ctx->vacuum_handle->ctdb_db->db_name));

	child_ctx->status = VACUUM_TIMEOUT;

	talloc_free(child_ctx);
}


/*
 * this event is generated when a vacuum child process has completed
 */
static void vacuum_child_handler(struct event_context *ev, struct fd_event *fde,
			     uint16_t flags, void *private_data)
{
	struct ctdb_vacuum_child_context *child_ctx = talloc_get_type(private_data, struct ctdb_vacuum_child_context);
	char c = 0;
	int ret;

	DEBUG(DEBUG_NOTICE,("Vacuuming child finished for db %s\n", child_ctx->vacuum_handle->ctdb_db->db_name));
	child_ctx->child_pid = -1;

	ret = read(child_ctx->fd[0], &c, 1);
	if (ret != 1 || c != 0) {
		child_ctx->status = VACUUM_ERROR;
		DEBUG(DEBUG_ERR, ("A vacuum child process failed with an error for database %s. ret=%d c=%d\n", child_ctx->vacuum_handle->ctdb_db->db_name, ret, c));
	} else {
		child_ctx->status = VACUUM_OK;
	}

	talloc_free(child_ctx);
}

/*
 * this event is called every time we need to start a new vacuum process
 */
static void
ctdb_vacuum_event(struct event_context *ev, struct timed_event *te,
			       struct timeval t, void *private_data)
{
	struct ctdb_vacuum_handle *vacuum_handle = talloc_get_type(private_data, struct ctdb_vacuum_handle);
	struct ctdb_db_context *ctdb_db = vacuum_handle->ctdb_db;
	struct ctdb_context *ctdb = ctdb_db->ctdb;
	struct ctdb_vacuum_child_context *child_ctx;
	int ret;

	/* we dont vacuum if we are in recovery mode */
	if (ctdb->recovery_mode == CTDB_RECOVERY_ACTIVE) {
		event_add_timed(ctdb->ev, vacuum_handle, timeval_current_ofs(ctdb->tunable.vacuum_default_interval, 0), ctdb_vacuum_event, vacuum_handle);
		return;
	}

	DEBUG(DEBUG_NOTICE,("Start a vacuuming child process for db %s\n", ctdb_db->db_name));

	child_ctx = talloc(vacuum_handle, struct ctdb_vacuum_child_context);
	if (child_ctx == NULL) {
		DEBUG(DEBUG_CRIT, (__location__ " Failed to allocate child context for vacuuming of %s\n", ctdb_db->db_name));
		ctdb_fatal(ctdb, "Out of memory when crating vacuum child context. Shutting down\n");
	}


	ret = pipe(child_ctx->fd);
	if (ret != 0) {
		talloc_free(child_ctx);
		DEBUG(DEBUG_ERR, ("Failed to create pipe for vacuum child process.\n"));
		event_add_timed(ctdb->ev, vacuum_handle, timeval_current_ofs(ctdb->tunable.vacuum_default_interval, 0), ctdb_vacuum_event, vacuum_handle);
		return;
	}

	child_ctx->child_pid = fork();
	if (child_ctx->child_pid == (pid_t)-1) {
		close(child_ctx->fd[0]);
		close(child_ctx->fd[1]);
		talloc_free(child_ctx);
		DEBUG(DEBUG_ERR, ("Failed to fork vacuum child process.\n"));
		event_add_timed(ctdb->ev, vacuum_handle, timeval_current_ofs(ctdb->tunable.vacuum_default_interval, 0), ctdb_vacuum_event, vacuum_handle);
		return;
	}


	if (child_ctx->child_pid == 0) {
		char cc = 0;
		close(child_ctx->fd[0]);

		if (switch_from_server_to_client(ctdb) != 0) {
			DEBUG(DEBUG_CRIT, (__location__ "ERROR: failed to switch vacuum daemon into client mode. Shutting down.\n"));
			_exit(1);
		}

		/* 
		 * repack the db
		 */
		cc = ctdb_repack_db(ctdb_db, child_ctx);

		write(child_ctx->fd[1], &cc, 1);
		_exit(0);
	}

	set_close_on_exec(child_ctx->fd[0]);
	close(child_ctx->fd[1]);

	child_ctx->status = VACUUM_RUNNING;
	child_ctx->start_time = timeval_current();

	talloc_set_destructor(child_ctx, vacuum_child_destructor);

	event_add_timed(ctdb->ev, child_ctx,
		timeval_current_ofs(ctdb->tunable.vacuum_max_run_time, 0),
		vacuum_child_timeout, child_ctx);

	DEBUG(DEBUG_NOTICE, (__location__ " Created PIPE FD:%d to child vacuum process\n", child_ctx->fd[0]));

	event_add_fd(ctdb->ev, child_ctx, child_ctx->fd[0],
		EVENT_FD_READ|EVENT_FD_AUTOCLOSE,
		vacuum_child_handler,
		child_ctx);

	vacuum_handle->child_ctx = child_ctx;
	child_ctx->vacuum_handle = vacuum_handle;
}


/* this function initializes the vacuuming context for a database
 * starts the vacuuming events
 */
int ctdb_vacuum_init(struct ctdb_db_context *ctdb_db)
{
	ctdb_db->vacuum_handle = talloc(ctdb_db, struct ctdb_vacuum_handle);
	CTDB_NO_MEMORY(ctdb_db->ctdb, ctdb_db->vacuum_handle);

	ctdb_db->vacuum_handle->ctdb_db = ctdb_db;

	event_add_timed(ctdb_db->ctdb->ev, ctdb_db->vacuum_handle, 
			timeval_current_ofs(get_vacuum_interval(ctdb_db), 0), 
			ctdb_vacuum_event, ctdb_db->vacuum_handle);

	return 0;
}
