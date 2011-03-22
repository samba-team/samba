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
#include "lib/tevent/tevent.h"
#include "lib/tdb/include/tdb.h"
#include "system/network.h"
#include "system/filesys.h"
#include "system/dir.h"
#include "../include/ctdb_private.h"
#include "db_wrap.h"
#include "lib/util/dlinklist.h"
#include "lib/tevent/tevent.h"
#include "../include/ctdb_private.h"
#include "../common/rb_tree.h"

#define TIMELIMIT() timeval_current_ofs(10, 0)
#define TUNINGDBNAME "vactune.tdb"

enum vacuum_child_status { VACUUM_RUNNING, VACUUM_OK, VACUUM_ERROR, VACUUM_TIMEOUT};

struct ctdb_vacuum_child_context {
	struct ctdb_vacuum_child_context *next, *prev;
	struct ctdb_vacuum_handle *vacuum_handle;
	/* fd child writes status to */
	int fd[2];
	pid_t child_pid;
	enum vacuum_child_status status;
	struct timeval start_time;
};

struct ctdb_vacuum_handle {
	struct ctdb_db_context *ctdb_db;
	struct ctdb_vacuum_child_context *child_ctx;
	uint32_t fast_path_count;
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
	uint32_t fast_added_to_vacuum_fetch_list;
	uint32_t fast_added_to_delete_tree;
	uint32_t fast_deleted;
	uint32_t fast_skipped;
	uint32_t fast_error;
	uint32_t fast_total;
	uint32_t full_added_to_vacuum_fetch_list;
	uint32_t full_added_to_delete_tree;
	uint32_t full_skipped;
	uint32_t full_error;
	uint32_t full_total;
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

/**
 * Store key and header in a tree, indexed by the key hash.
 */
static int insert_delete_record_data_into_tree(struct ctdb_context *ctdb,
					       struct ctdb_db_context *ctdb_db,
					       trbt_tree_t *tree,
					       const struct ctdb_ltdb_header *hdr,
					       TDB_DATA key)
{
	struct delete_record_data *dd;
	uint32_t hash;

	dd = talloc_zero(tree, struct delete_record_data);
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

	hash = ctdb_hash(&key);

	trbt_insert32(tree, hash, dd);

	return 0;
}

static int add_record_to_delete_tree(struct vacuum_data *vdata, TDB_DATA key,
				     struct ctdb_ltdb_header *hdr)
{
	struct ctdb_context *ctdb = vdata->ctdb;
	struct ctdb_db_context *ctdb_db = vdata->ctdb_db;
	uint32_t hash;
	int ret;

	hash = ctdb_hash(&key);

	if (trbt_lookup32(vdata->delete_tree, hash)) {
		DEBUG(DEBUG_INFO, (__location__ " Hash collission when vacuuming, skipping this record.\n"));
		return 0;
	}

	ret = insert_delete_record_data_into_tree(ctdb, ctdb_db,
						  vdata->delete_tree,
						  hdr, key);
	if (ret != 0) {
		return -1;
	}

	vdata->delete_count++;

	return 0;
}

/**
 * Add a record to the list of records to be sent
 * to their lmaster with VACUUM_FETCH.
 */
static int add_record_to_vacuum_fetch_list(struct vacuum_data *vdata,
					   TDB_DATA key)
{
	struct ctdb_context *ctdb = vdata->ctdb;
	struct ctdb_rec_data *rec;
	uint32_t lmaster;
	size_t old_size;

	lmaster = ctdb_lmaster(ctdb, &key);

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


static void ctdb_vacuum_event(struct event_context *ev, struct timed_event *te, 
							  struct timeval t, void *private_data);


/*
 * traverse function for gathering the records that can be deleted
 */
static int vacuum_traverse(struct tdb_context *tdb, TDB_DATA key, TDB_DATA data, void *private)
{
	struct vacuum_data *vdata = talloc_get_type(private, struct vacuum_data);
	struct ctdb_context *ctdb = vdata->ctdb;
	uint32_t lmaster;
	struct ctdb_ltdb_header *hdr;
	int res = 0;

	vdata->full_total++;

	lmaster = ctdb_lmaster(ctdb, &key);
	if (lmaster >= ctdb->num_nodes) {
		vdata->full_error++;
		DEBUG(DEBUG_CRIT, (__location__
				   " lmaster[%u] >= ctdb->num_nodes[%u] for key"
				   " with hash[%u]!\n",
				   (unsigned)lmaster,
				   (unsigned)ctdb->num_nodes,
				   (unsigned)ctdb_hash(&key)));
		return -1;
	}

	if (data.dsize != sizeof(struct ctdb_ltdb_header)) {
		/* its not a deleted record */
		vdata->full_skipped++;
		return 0;
	}

	hdr = (struct ctdb_ltdb_header *)data.dptr;

	if (hdr->dmaster != ctdb->pnn) {
		vdata->full_skipped++;
		return 0;
	}

	if (lmaster == ctdb->pnn) {
		/*
		 * We are both lmaster and dmaster, and the record * is empty.
		 * So we should be able to delete it.
		 */
		res = add_record_to_delete_tree(vdata, key, hdr);
		if (res != 0) {
			vdata->full_error++;
		} else {
			vdata->full_added_to_delete_tree++;
		}
	} else {
		/*
		 * We are not lmaster.
		 * Add the record to the blob ready to send to the nodes.
		 */
		res = add_record_to_vacuum_fetch_list(vdata, key);
		if (res != 0) {
			vdata->full_error++;
		} else {
			vdata->full_added_to_vacuum_fetch_list++;
		}
	}

	return res;
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

/**
 * traverse function for the traversal of the delete_queue,
 * the fast-path vacuuming list.
 *
 *  - If the record has been migrated off the node
 *    or has been revived (filled with data) on the node,
 *    then skip the record.
 *
 *  - If the current node is the record's lmaster and it is
 *    a record that has never been migrated with data, then
 *    delete the record from the local tdb.
 *
 *  - If the current node is the record's lmaster and it has
 *    been migrated with data, then schedule it for the normal
 *    vacuuming procedure (i.e. add it to the delete_list).
 *
 *  - If the current node is NOT the record's lmaster then
 *    add it to the list of records that are to be sent to
 *    the lmaster with the VACUUM_FETCH message.
 */
static void delete_queue_traverse(void *param, void *data)
{
	struct delete_record_data *dd =
		talloc_get_type(data, struct delete_record_data);
	struct vacuum_data *vdata = talloc_get_type(param, struct vacuum_data);
	struct ctdb_db_context *ctdb_db = dd->ctdb_db;
	struct ctdb_context *ctdb = ctdb_db->ctdb; /* or dd->ctdb ??? */
	int res;
	struct ctdb_ltdb_header *header;
	TDB_DATA tdb_data;
	uint32_t lmaster;

	vdata->fast_total++;

	res = tdb_chainlock(ctdb_db->ltdb->tdb, dd->key);
	if (res != 0) {
		DEBUG(DEBUG_ERR, (__location__ " Error getting chainlock.\n"));
		vdata->fast_error++;
		return;
	}

	tdb_data = tdb_fetch(ctdb_db->ltdb->tdb, dd->key);
	if (tdb_data.dsize < sizeof(struct ctdb_ltdb_header)) {
		/* Does not exist or not a ctdb record. Skip. */
		goto skipped;
	}

	if (tdb_data.dsize > sizeof(struct ctdb_ltdb_header)) {
		/* The record has been recycled (filled with data). Skip. */
		goto skipped;
	}

	header = (struct ctdb_ltdb_header *)tdb_data.dptr;

	if (header->dmaster != ctdb->pnn) {
		/* The record has been migrated off the node. Skip. */
		goto skipped;
	}


	if (header->rsn != dd->hdr.rsn) {
		/*
		 * The record has been migrated off the node and back again.
		 * But not requeued for deletion. Skip it.
		 */
		goto skipped;
	}

	/*
	 * We are dmaster, and the record has no data, and it has
	 * not been migrated after it has been queued for deletion.
	 *
	 * At this stage, the record could still have been revived locally
	 * and last been written with empty data. This can only be
	 * fixed with the addition of an active or delete flag. (TODO)
	 */

	lmaster = ctdb_lmaster(ctdb_db->ctdb, &dd->key);

	if (lmaster != ctdb->pnn) {
		res = add_record_to_vacuum_fetch_list(vdata, dd->key);

		if (res != 0) {
			DEBUG(DEBUG_ERR,
			      (__location__ " Error adding record to list "
			       "of records to send to lmaster.\n"));
			vdata->fast_error++;
		} else {
			vdata->fast_added_to_vacuum_fetch_list++;
		}
		goto done;
	}

	/* use header->flags or dd->hdr.flags ?? */
	if (dd->hdr.flags & CTDB_REC_FLAG_MIGRATED_WITH_DATA) {
		res = add_record_to_delete_tree(vdata, dd->key, &dd->hdr);

		if (res != 0) {
			DEBUG(DEBUG_ERR,
			      (__location__ " Error adding record to list "
			       "of records for deletion on lmaster.\n"));
			vdata->fast_error++;
		} else {
			vdata->fast_added_to_delete_tree++;
		}
	} else {
		res = tdb_delete(ctdb_db->ltdb->tdb, dd->key);

		if (res != 0) {
			DEBUG(DEBUG_ERR,
			      (__location__ " Error deleting record from local "
			       "data base.\n"));
			vdata->fast_error++;
		} else {
			vdata->fast_deleted++;
		}
	}

	goto done;

skipped:
	vdata->fast_skipped++;

done:
	if (tdb_data.dptr != NULL) {
		free(tdb_data.dptr);
	}
	tdb_chainunlock(ctdb_db->ltdb->tdb, dd->key);

	return;
}

/* 
 * read-only traverse the database in order to find
 * records that can be deleted and try to delete these
 * records on the other nodes
 * this executes in the child context
 */
static int ctdb_vacuum_db(struct ctdb_db_context *ctdb_db,
			  struct vacuum_data *vdata,
			  bool full_vacuum_run)
{
	struct ctdb_context *ctdb = ctdb_db->ctdb;
	const char *name = ctdb_db->db_name;
	int ret, i, pnn;

	DEBUG(DEBUG_INFO, (__location__ " Entering %s vacuum run for db "
			   "%s db_id[0x%08x]\n",
			   full_vacuum_run ? "full" : "fast",
			   ctdb_db->db_name, ctdb_db->db_id));

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

	vdata->fast_added_to_delete_tree = 0;
	vdata->fast_added_to_vacuum_fetch_list = 0;
	vdata->fast_deleted = 0;
	vdata->fast_skipped = 0;
	vdata->fast_error = 0;
	vdata->fast_total = 0;
	vdata->full_added_to_delete_tree = 0;
	vdata->full_added_to_vacuum_fetch_list = 0;
	vdata->full_skipped = 0;
	vdata->full_error = 0;
	vdata->full_total = 0;

	/* the list needs to be of length num_nodes */
	vdata->list = talloc_array(vdata, struct ctdb_marshall_buffer *, ctdb->num_nodes);
	if (vdata->list == NULL) {
		DEBUG(DEBUG_ERR,(__location__ " Out of memory\n"));
		return -1;
	}
	for (i = 0; i < ctdb->num_nodes; i++) {
		vdata->list[i] = (struct ctdb_marshall_buffer *)
			talloc_zero_size(vdata->list, 
							 offsetof(struct ctdb_marshall_buffer, data));
		if (vdata->list[i] == NULL) {
			DEBUG(DEBUG_ERR,(__location__ " Out of memory\n"));
			return -1;
		}
		vdata->list[i]->db_id = ctdb_db->db_id;
	}

	/*
	 * Traverse the delete_queue.
	 * This builds the same lists as the db traverse.
	 */
	trbt_traversearray32(ctdb_db->delete_queue, 1, delete_queue_traverse, vdata);

	if (vdata->fast_total > 0) {
		DEBUG(DEBUG_INFO,
		      (__location__
		       " fast vacuuming delete_queue traverse statistics: "
		       "db[%s] "
		       "total[%u] "
		       "del[%u] "
		       "skp[%u] "
		       "err[%u] "
		       "adt[%u] "
		       "avf[%u]\n",
		       ctdb_db->db_name,
		       (unsigned)vdata->fast_total,
		       (unsigned)vdata->fast_deleted,
		       (unsigned)vdata->fast_skipped,
		       (unsigned)vdata->fast_error,
		       (unsigned)vdata->fast_added_to_delete_tree,
		       (unsigned)vdata->fast_added_to_vacuum_fetch_list));
	}

	/*
	 * read-only traverse of the database, looking for records that
	 * might be able to be vacuumed.
	 *
	 * This is not done each time but only every tunable
	 * VacuumFastPathCount times.
	 */
	if (full_vacuum_run) {
		ret = tdb_traverse_read(ctdb_db->ltdb->tdb, vacuum_traverse, vdata);
		if (ret == -1 || vdata->traverse_error) {
			DEBUG(DEBUG_ERR,(__location__ " Traverse error in vacuuming '%s'\n", name));
			return -1;
		}
		if (vdata->full_total > 0) {
			DEBUG(DEBUG_INFO,
			      (__location__
			       " full vacuuming db traverse statistics: "
			       "db[%s] "
			       "total[%u] "
			       "skp[%u] "
			       "err[%u] "
			       "adt[%u] "
			       "avf[%u]\n",
			       ctdb_db->db_name,
			       (unsigned)vdata->full_total,
			       (unsigned)vdata->full_skipped,
			       (unsigned)vdata->full_error,
			       (unsigned)vdata->full_added_to_delete_tree,
			       (unsigned)vdata->full_added_to_vacuum_fetch_list));
		}
	}

	/*
	 * For records where we are not the lmaster,
	 * tell the lmaster to fetch the record.
	 */
	for (i = 0; i < ctdb->num_nodes; i++) {
		TDB_DATA data;

		if (ctdb->nodes[i]->pnn == ctdb->pnn) {
			continue;
		}

		if (vdata->list[i]->count == 0) {
			continue;
		}

		DEBUG(DEBUG_INFO, ("Found %u records for lmaster %u in '%s'\n",
				   vdata->list[i]->count, ctdb->nodes[i]->pnn,
				   name));

		data.dsize = talloc_get_size(vdata->list[i]);
		data.dptr  = (void *)vdata->list[i];
		if (ctdb_client_send_message(ctdb, ctdb->nodes[i]->pnn, CTDB_SRVID_VACUUM_FETCH, data) != 0) {
			DEBUG(DEBUG_ERR, (__location__ " Failed to send vacuum "
					  "fetch message to %u\n",
					  ctdb->nodes[i]->pnn));
			return -1;
		}
	}	

	/* Process all records we can delete (if any) */
	if (vdata->delete_count > 0) {
		struct delete_records_list *recs;
		TDB_DATA indata, outdata;
		int32_t res;
		struct ctdb_node_map *nodemap;
		uint32_t *active_nodes;
		int num_active_nodes;

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
		 * now tell all the active nodes to delete all these records
		 * (if possible)
		 */

		ret = ctdb_ctrl_getnodemap(ctdb, TIMELIMIT(),
					   CTDB_CURRENT_NODE,
					   recs, /* talloc context */
					   &nodemap);
		if (ret != 0) {
			DEBUG(DEBUG_ERR,(__location__ " unable to get node map\n"));
			return -1;
		}

		active_nodes = list_of_active_nodes(ctdb, nodemap,
						    nodemap, /* talloc context */
						    false /* include self */);
		/* yuck! ;-) */
		num_active_nodes = talloc_get_size(active_nodes)/sizeof(*active_nodes);

		for (i = 0; i < num_active_nodes; i++) {
			struct ctdb_marshall_buffer *records;
			struct ctdb_rec_data *rec;

			ret = ctdb_control(ctdb, active_nodes[i], 0,
					CTDB_CONTROL_TRY_DELETE_RECORDS, 0,
					indata, recs, &outdata, &res,
					NULL, NULL);
			if (ret != 0 || res != 0) {
				DEBUG(DEBUG_ERR, ("Failed to delete records on "
						  "node %u: ret[%d] res[%d]\n",
						  active_nodes[i], ret, res));
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

		/* free nodemap and active_nodes */
		talloc_free(nodemap);

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
			struct ctdb_ltdb_header *hdr = (struct ctdb_ltdb_header *)data.dptr;
			/*
			 * we have to check if the record hasn't changed in the meantime in order to
			 * savely remove it from the database
			 */
			if (data.dsize == sizeof(struct ctdb_ltdb_header) &&
				hdr->dmaster == kd->ctdb->pnn &&
				ctdb_lmaster(kd->ctdb, &(kd->key)) == kd->ctdb->pnn &&
				kd->hdr.rsn == hdr->rsn) {
				vdata->vacuumed++;
				return 0;
			}
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

	tmp_db = tdb_open("tmpdb", tdb_hash_size(tdb),
			  TDB_INTERNAL|TDB_DISALLOW_NESTING,
			  O_RDWR|O_CREAT, 0);
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

	DEBUG(DEBUG_INFO,(__location__ " %u records vacuumed\n", vdata->vacuumed));
	
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
	DEBUG(DEBUG_INFO,(__location__ " %u records copied\n", vdata->copied));

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
	int flags;

	vac_dbname = talloc_asprintf(tmp_ctx, "%s/%s.%u",
				     ctdb_db->ctdb->db_directory_state,
				     TUNINGDBNAME, ctdb_db->ctdb->pnn);
	if (vac_dbname == NULL) {
		DEBUG(DEBUG_CRIT,(__location__ " Out of memory error while allocating '%s'\n", vac_dbname));
		talloc_free(tmp_ctx);
		return -1;
	}

	flags  = ctdb_db->ctdb->valgrinding ? TDB_NOMMAP : 0;
	flags |= TDB_DISALLOW_NESTING;
	tune_tdb = tdb_open(vac_dbname, 0,
			    flags,
			    O_RDWR|O_CREAT, 0600);
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
		 * in case no limit was reached we continuously increase the interval
		 * until vacuum_max_interval is reached
		 * in case a limit was reached we divide the current interval by 2
		 * unless vacuum_min_interval is reached
		 */
		if (freelist < vdata->repack_limit &&
		    vdata->delete_count < vdata->vacuum_limit) {
			if (tdata.last_interval < ctdb_db->ctdb->tunable.vacuum_max_interval) {
				tdata.new_interval = tdata.last_interval * 110 / 100;
				DEBUG(DEBUG_INFO,("Increasing vacuum interval %u -> %u for %s\n", 
					tdata.last_interval, tdata.new_interval, ctdb_db->db_name));
			}
		} else {
			tdata.new_interval = tdata.last_interval / 2;
			if (tdata.new_interval < ctdb_db->ctdb->tunable.vacuum_min_interval ||
				tdata.new_interval > ctdb_db->ctdb->tunable.vacuum_max_interval) {
				tdata.new_interval = ctdb_db->ctdb->tunable.vacuum_min_interval;
			}		
			DEBUG(DEBUG_INFO,("Decreasing vacuum interval %u -> %u for %s\n", 
					 tdata.last_interval, tdata.new_interval, ctdb_db->db_name));
		}
		tdata.last_interval = tdata.new_interval;
	} else {
		DEBUG(DEBUG_DEBUG,(__location__ " Cannot find tunedb record for %s. Using default interval\n", ctdb_db->db_name));
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
static int ctdb_vacuum_and_repack_db(struct ctdb_db_context *ctdb_db,
				     TALLOC_CTX *mem_ctx,
				     bool full_vacuum_run)
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
	vdata->ctdb_db = ctdb_db;
	if (vdata->delete_tree == NULL) {
		DEBUG(DEBUG_ERR,(__location__ " Out of memory\n"));
		talloc_free(vdata);
		return -1;
	}

	vdata->start = timeval_current();
 
	/*
	 * gather all records that can be deleted in vdata
	 */
	if (ctdb_vacuum_db(ctdb_db, vdata, full_vacuum_run) != 0) {
		DEBUG(DEBUG_ERR,(__location__ " Failed to vacuum '%s'\n", name));
	}

	/*
	 * decide if a repack is necessary
	 */
	if (size < repack_limit && vdata->delete_count < vacuum_limit) {
		update_tuning_db(ctdb_db, vdata, size);
		talloc_free(vdata);
		return 0;
	}

	DEBUG(DEBUG_INFO,("Repacking %s with %u freelist entries and %u records to delete\n", 
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
	int flags;

	vac_dbname = talloc_asprintf(tmp_ctx, "%s/%s.%u", ctdb->db_directory, TUNINGDBNAME, ctdb->pnn);
	if (vac_dbname == NULL) {
		DEBUG(DEBUG_CRIT,(__location__ " Out of memory error while allocating '%s'\n", vac_dbname));
		talloc_free(tmp_ctx);
		return interval;
	}

	flags  = ctdb_db->ctdb->valgrinding ? TDB_NOMMAP : 0;
	flags |= TDB_DISALLOW_NESTING;
	tdb = tdb_open(vac_dbname, 0,
		       flags,
		       O_RDWR|O_CREAT, 0600);
	if (!tdb) {
		DEBUG(DEBUG_ERR,("Unable to open/create database %s using default interval. Errno : %s (%d)\n", vac_dbname, strerror(errno), errno));
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

	DEBUG(DEBUG_INFO,("Vacuuming took %.3f seconds for database %s\n", l, ctdb_db->db_name));

	if (child_ctx->child_pid != -1) {
		kill(child_ctx->child_pid, SIGKILL);
	} else {
		/* Bump the number of successful fast-path runs. */
		child_ctx->vacuum_handle->fast_path_count++;
	}

	DLIST_REMOVE(ctdb->vacuumers, child_ctx);

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

	DEBUG(DEBUG_INFO,("Vacuuming child process %d finished for db %s\n", child_ctx->child_pid, child_ctx->vacuum_handle->ctdb_db->db_name));
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
	struct tevent_fd *fde;
	int ret;

	/* we dont vacuum if we are in recovery mode, or db frozen */
	if (ctdb->recovery_mode == CTDB_RECOVERY_ACTIVE ||
	    ctdb->freeze_mode[ctdb_db->priority] != CTDB_FREEZE_NONE) {
		DEBUG(DEBUG_INFO, ("Not vacuuming %s (%s)\n", ctdb_db->db_name,
				   ctdb->recovery_mode == CTDB_RECOVERY_ACTIVE ? "in recovery"
				   : ctdb->freeze_mode[ctdb_db->priority] == CTDB_FREEZE_PENDING
				   ? "freeze pending"
				   : "frozen"));
		event_add_timed(ctdb->ev, vacuum_handle, timeval_current_ofs(ctdb->tunable.vacuum_default_interval, 0), ctdb_vacuum_event, vacuum_handle);
		return;
	}

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

	if (vacuum_handle->fast_path_count > ctdb->tunable.vacuum_fast_path_count) {
		vacuum_handle->fast_path_count = 0;
	}

	child_ctx->child_pid = ctdb_fork(ctdb);
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
		bool full_vacuum_run = false;
		close(child_ctx->fd[0]);

		DEBUG(DEBUG_INFO,("Vacuuming child process %d for db %s started\n", getpid(), ctdb_db->db_name));
	
		if (switch_from_server_to_client(ctdb, "vacuum-%s", ctdb_db->db_name) != 0) {
			DEBUG(DEBUG_CRIT, (__location__ "ERROR: failed to switch vacuum daemon into client mode. Shutting down.\n"));
			_exit(1);
		}

		/* 
		 * repack the db
		 */
		if ((ctdb->tunable.vacuum_fast_path_count > 0) &&
		    (vacuum_handle->fast_path_count == 0))
		{
			full_vacuum_run = true;
		}
		cc = ctdb_vacuum_and_repack_db(ctdb_db, child_ctx,
					       full_vacuum_run);

		write(child_ctx->fd[1], &cc, 1);
		_exit(0);
	}

	set_close_on_exec(child_ctx->fd[0]);
	close(child_ctx->fd[1]);

	child_ctx->status = VACUUM_RUNNING;
	child_ctx->start_time = timeval_current();

	DLIST_ADD(ctdb->vacuumers, child_ctx);
	talloc_set_destructor(child_ctx, vacuum_child_destructor);

	/*
	 * Clear the fastpath vacuuming list in the parent.
	 */
	talloc_free(ctdb_db->delete_queue);
	ctdb_db->delete_queue = trbt_create(ctdb_db, 0);
	if (ctdb_db->delete_queue == NULL) {
		/* fatal here? ... */
		ctdb_fatal(ctdb, "Out of memory when re-creating vacuum tree "
				 "in parent context. Shutting down\n");
	}

	event_add_timed(ctdb->ev, child_ctx,
		timeval_current_ofs(ctdb->tunable.vacuum_max_run_time, 0),
		vacuum_child_timeout, child_ctx);

	DEBUG(DEBUG_DEBUG, (__location__ " Created PIPE FD:%d to child vacuum process\n", child_ctx->fd[0]));

	fde = event_add_fd(ctdb->ev, child_ctx, child_ctx->fd[0],
			   EVENT_FD_READ, vacuum_child_handler, child_ctx);
	tevent_fd_set_auto_close(fde);

	vacuum_handle->child_ctx = child_ctx;
	child_ctx->vacuum_handle = vacuum_handle;
}

void ctdb_stop_vacuuming(struct ctdb_context *ctdb)
{
	/* Simply free them all. */
	while (ctdb->vacuumers) {
		DEBUG(DEBUG_INFO, ("Aborting vacuuming for %s (%i)\n",
			   ctdb->vacuumers->vacuum_handle->ctdb_db->db_name,
			   (int)ctdb->vacuumers->child_pid));
		/* vacuum_child_destructor kills it, removes from list */
		talloc_free(ctdb->vacuumers);
	}
}

/* this function initializes the vacuuming context for a database
 * starts the vacuuming events
 */
int ctdb_vacuum_init(struct ctdb_db_context *ctdb_db)
{
	if (ctdb_db->persistent != 0) {
		DEBUG(DEBUG_ERR,("Vacuuming is disabled for persistent database %s\n", ctdb_db->db_name));
		return 0;
	}

	ctdb_db->vacuum_handle = talloc(ctdb_db, struct ctdb_vacuum_handle);
	CTDB_NO_MEMORY(ctdb_db->ctdb, ctdb_db->vacuum_handle);

	ctdb_db->vacuum_handle->ctdb_db         = ctdb_db;
	ctdb_db->vacuum_handle->fast_path_count = 0;

	event_add_timed(ctdb_db->ctdb->ev, ctdb_db->vacuum_handle, 
			timeval_current_ofs(get_vacuum_interval(ctdb_db), 0), 
			ctdb_vacuum_event, ctdb_db->vacuum_handle);

	return 0;
}

/**
 * Insert a record into the ctdb_db context's delete queue,
 * handling hash collisions.
 */
static int insert_record_into_delete_queue(struct ctdb_db_context *ctdb_db,
					   const struct ctdb_ltdb_header *hdr,
					   TDB_DATA key)
{
	struct delete_record_data *kd;
	uint32_t hash;
	int ret;

	hash = (uint32_t)ctdb_hash(&key);

	DEBUG(DEBUG_INFO, (__location__ " Schedule for deletion: db[%s] "
			   "db_id[0x%08x] "
			   "key_hash[0x%08x] "
			   "lmaster[%u] "
			   "migrated_with_data[%s]\n",
			    ctdb_db->db_name, ctdb_db->db_id,
			    hash,
			    ctdb_lmaster(ctdb_db->ctdb, &key),
			    hdr->flags & CTDB_REC_FLAG_MIGRATED_WITH_DATA ? "yes" : "no"));

	kd = (struct delete_record_data *)trbt_lookup32(ctdb_db->delete_queue, hash);
	if (kd != NULL) {
		if ((kd->key.dsize != key.dsize) ||
		    (memcmp(kd->key.dptr, key.dptr, key.dsize) != 0))
		{
			DEBUG(DEBUG_INFO,
			      ("schedule for deletion: Hash collision (0x%08x)."
			       " Skipping the record.\n", hash));
			return 0;
		} else {
			DEBUG(DEBUG_DEBUG,
			      ("schedule for deletion: Overwriting entry for "
			       "key with hash 0x%08x.\n", hash));
		}
	}

	ret = insert_delete_record_data_into_tree(ctdb_db->ctdb, ctdb_db,
						  ctdb_db->delete_queue,
						  hdr, key);
	if (ret != 0) {
		return -1;
	}

	return 0;
}

/**
 * Schedule a record for deletetion.
 * Called from the parent context.
 */
int32_t ctdb_control_schedule_for_deletion(struct ctdb_context *ctdb,
					   TDB_DATA indata)
{
	struct ctdb_control_schedule_for_deletion *dd;
	struct ctdb_db_context *ctdb_db;
	int ret;
	TDB_DATA key;

	dd = (struct ctdb_control_schedule_for_deletion *)indata.dptr;

	ctdb_db = find_ctdb_db(ctdb, dd->db_id);
	if (ctdb_db == NULL) {
		DEBUG(DEBUG_ERR, (__location__ " Unknown db id 0x%08x\n",
				  dd->db_id));
		return -1;
	}

	key.dsize = dd->keylen;
	key.dptr = dd->key;

	ret = insert_record_into_delete_queue(ctdb_db, &dd->hdr, key);

	return ret;
}

int32_t ctdb_local_schedule_for_deletion(struct ctdb_db_context *ctdb_db,
					 const struct ctdb_ltdb_header *hdr,
					 TDB_DATA key)
{
	int ret;
	struct ctdb_control_schedule_for_deletion *dd;
	TDB_DATA indata;
	int32_t status;

	if (ctdb_db->ctdb->ctdbd_pid == getpid()) {
		/* main daemon - directly queue */
		ret = insert_record_into_delete_queue(ctdb_db, hdr, key);

		return ret;
	}

	/* child process: send the main daemon a control */

	indata.dsize = offsetof(struct ctdb_control_schedule_for_deletion, key) + key.dsize;
	indata.dptr = talloc_zero_array(ctdb_db, uint8_t, indata.dsize);
	if (indata.dptr == NULL) {
		DEBUG(DEBUG_ERR, (__location__ " out of memory\n"));
		return -1;
	}
	dd = (struct ctdb_control_schedule_for_deletion *)(void *)indata.dptr;
	dd->db_id = ctdb_db->db_id;
	dd->hdr = *hdr;
	dd->keylen = key.dsize;
	memcpy(dd->key, key.dptr, key.dsize);

	ret = ctdb_control(ctdb_db->ctdb,
			   CTDB_CURRENT_NODE,
			   ctdb_db->db_id,
			   CTDB_CONTROL_SCHEDULE_FOR_DELETION,
			   CTDB_CTRL_FLAG_NOREPLY, /* flags */
			   indata,
			   NULL, /* mem_ctx */
			   NULL, /* outdata */
			   &status,
			   NULL, /* timeout : NULL == wait forever */
			   NULL); /* error message */

	talloc_free(indata.dptr);

	if (ret != 0 || status != 0) {
		DEBUG(DEBUG_ERR, (__location__ " Error sending "
				  "SCHEDULE_FOR_DELETION "
				  "control.\n"));
		if (status != 0) {
			ret = -1;
		}
	}

	return ret;
}
