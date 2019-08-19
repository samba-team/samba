/* 
   ctdb recovery code

   Copyright (C) Andrew Tridgell  2007
   Copyright (C) Ronnie Sahlberg  2007

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
#include "replace.h"
#include "system/time.h"
#include "system/network.h"
#include "system/filesys.h"
#include "system/wait.h"

#include <talloc.h>
#include <tevent.h>
#include <tdb.h>

#include "lib/tdb_wrap/tdb_wrap.h"
#include "lib/util/dlinklist.h"
#include "lib/util/debug.h"
#include "lib/util/time.h"
#include "lib/util/util_process.h"

#include "ctdb_private.h"
#include "ctdb_client.h"

#include "common/system.h"
#include "common/common.h"
#include "common/logging.h"

#include "ctdb_cluster_mutex.h"

int 
ctdb_control_getvnnmap(struct ctdb_context *ctdb, uint32_t opcode, TDB_DATA indata, TDB_DATA *outdata)
{
	struct ctdb_vnn_map_wire *map;
	size_t len;

	CHECK_CONTROL_DATA_SIZE(0);

	len = offsetof(struct ctdb_vnn_map_wire, map) + sizeof(uint32_t)*ctdb->vnn_map->size;
	map = talloc_size(outdata, len);
	CTDB_NO_MEMORY(ctdb, map);

	map->generation = ctdb->vnn_map->generation;
	map->size = ctdb->vnn_map->size;
	memcpy(map->map, ctdb->vnn_map->map, sizeof(uint32_t)*map->size);

	outdata->dsize = len;
	outdata->dptr  = (uint8_t *)map;

	return 0;
}

int
ctdb_control_setvnnmap(struct ctdb_context *ctdb, uint32_t opcode, TDB_DATA indata, TDB_DATA *outdata)
{
	struct ctdb_vnn_map_wire *map = (struct ctdb_vnn_map_wire *)indata.dptr;

	if (ctdb->recovery_mode != CTDB_RECOVERY_ACTIVE) {
		DEBUG(DEBUG_ERR, ("Attempt to set vnnmap when not in recovery\n"));
		return -1;
	}

	talloc_free(ctdb->vnn_map);

	ctdb->vnn_map = talloc(ctdb, struct ctdb_vnn_map);
	CTDB_NO_MEMORY(ctdb, ctdb->vnn_map);

	ctdb->vnn_map->generation = map->generation;
	ctdb->vnn_map->size       = map->size;
	ctdb->vnn_map->map = talloc_array(ctdb->vnn_map, uint32_t, map->size);
	CTDB_NO_MEMORY(ctdb, ctdb->vnn_map->map);

	memcpy(ctdb->vnn_map->map, map->map, sizeof(uint32_t)*map->size);

	return 0;
}

int 
ctdb_control_getdbmap(struct ctdb_context *ctdb, uint32_t opcode, TDB_DATA indata, TDB_DATA *outdata)
{
	uint32_t i, len;
	struct ctdb_db_context *ctdb_db;
	struct ctdb_dbid_map_old *dbid_map;

	CHECK_CONTROL_DATA_SIZE(0);

	len = 0;
	for(ctdb_db=ctdb->db_list;ctdb_db;ctdb_db=ctdb_db->next){
		len++;
	}


	outdata->dsize = offsetof(struct ctdb_dbid_map_old, dbs) + sizeof(dbid_map->dbs[0])*len;
	outdata->dptr  = (unsigned char *)talloc_zero_size(outdata, outdata->dsize);
	if (!outdata->dptr) {
		DEBUG(DEBUG_ALERT, (__location__ " Failed to allocate dbmap array\n"));
		exit(1);
	}

	dbid_map = (struct ctdb_dbid_map_old *)outdata->dptr;
	dbid_map->num = len;
	for (i=0,ctdb_db=ctdb->db_list;ctdb_db;i++,ctdb_db=ctdb_db->next){
		dbid_map->dbs[i].db_id       = ctdb_db->db_id;
		dbid_map->dbs[i].flags       = ctdb_db->db_flags;
	}

	return 0;
}

int
ctdb_control_getnodemap(struct ctdb_context *ctdb, uint32_t opcode, TDB_DATA indata, TDB_DATA *outdata)
{
	CHECK_CONTROL_DATA_SIZE(0);

	outdata->dptr  = (unsigned char *)ctdb_node_list_to_map(ctdb->nodes,
								ctdb->num_nodes,
								outdata);
	if (outdata->dptr == NULL) {
		return -1;
	}

	outdata->dsize = talloc_get_size(outdata->dptr);

	return 0;
}

/*
  reload the nodes file
*/
int
ctdb_control_reload_nodes_file(struct ctdb_context *ctdb, uint32_t opcode)
{
	unsigned int i, num_nodes;
	TALLOC_CTX *tmp_ctx;
	struct ctdb_node **nodes;

	tmp_ctx = talloc_new(ctdb);

	/* steal the old nodes file for a while */
	talloc_steal(tmp_ctx, ctdb->nodes);
	nodes = ctdb->nodes;
	ctdb->nodes = NULL;
	num_nodes = ctdb->num_nodes;
	ctdb->num_nodes = 0;

	/* load the new nodes file */
	ctdb_load_nodes_file(ctdb);

	for (i=0; i<ctdb->num_nodes; i++) {
		/* keep any identical pre-existing nodes and connections */
		if ((i < num_nodes) && ctdb_same_address(&ctdb->nodes[i]->address, &nodes[i]->address)) {
			talloc_free(ctdb->nodes[i]);
			ctdb->nodes[i] = talloc_steal(ctdb->nodes, nodes[i]);
			continue;
		}

		if (ctdb->nodes[i]->flags & NODE_FLAGS_DELETED) {
			continue;
		}

		/* any new or different nodes must be added */
		if (ctdb->methods->add_node(ctdb->nodes[i]) != 0) {
			DEBUG(DEBUG_CRIT, (__location__ " methods->add_node failed at %d\n", i));
			ctdb_fatal(ctdb, "failed to add node. shutting down\n");
		}
		if (ctdb->methods->connect_node(ctdb->nodes[i]) != 0) {
			DEBUG(DEBUG_CRIT, (__location__ " methods->add_connect failed at %d\n", i));
			ctdb_fatal(ctdb, "failed to connect to node. shutting down\n");
		}
	}

	/* tell the recovery daemon to reaload the nodes file too */
	ctdb_daemon_send_message(ctdb, ctdb->pnn, CTDB_SRVID_RELOAD_NODES, tdb_null);

	talloc_free(tmp_ctx);

	return 0;
}

/* 
   a traverse function for pulling all relevent records from pulldb
 */
struct pulldb_data {
	struct ctdb_context *ctdb;
	struct ctdb_db_context *ctdb_db;
	struct ctdb_marshall_buffer *pulldata;
	uint32_t len;
	uint32_t allocated_len;
	bool failed;
};

static int traverse_pulldb(struct tdb_context *tdb, TDB_DATA key, TDB_DATA data, void *p)
{
	struct pulldb_data *params = (struct pulldb_data *)p;
	struct ctdb_rec_data_old *rec;
	struct ctdb_context *ctdb = params->ctdb;
	struct ctdb_db_context *ctdb_db = params->ctdb_db;

	/* add the record to the blob */
	rec = ctdb_marshall_record(params->pulldata, 0, key, NULL, data);
	if (rec == NULL) {
		params->failed = true;
		return -1;
	}
	if (params->len + rec->length >= params->allocated_len) {
		params->allocated_len = rec->length + params->len + ctdb->tunable.pulldb_preallocation_size;
		params->pulldata = talloc_realloc_size(NULL, params->pulldata, params->allocated_len);
	}
	if (params->pulldata == NULL) {
		DEBUG(DEBUG_CRIT,(__location__ " Failed to expand pulldb_data to %u\n", rec->length + params->len));
		ctdb_fatal(params->ctdb, "failed to allocate memory for recovery. shutting down\n");
	}
	params->pulldata->count++;
	memcpy(params->len+(uint8_t *)params->pulldata, rec, rec->length);
	params->len += rec->length;

	if (ctdb->tunable.db_record_size_warn != 0 && rec->length > ctdb->tunable.db_record_size_warn) {
		DEBUG(DEBUG_ERR,("Data record in %s is big. Record size is %d bytes\n", ctdb_db->db_name, (int)rec->length));
	}

	talloc_free(rec);

	return 0;
}

/*
  pull a bunch of records from a ltdb, filtering by lmaster
 */
int32_t ctdb_control_pull_db(struct ctdb_context *ctdb, TDB_DATA indata, TDB_DATA *outdata)
{
	struct ctdb_pulldb *pull;
	struct ctdb_db_context *ctdb_db;
	struct pulldb_data params;
	struct ctdb_marshall_buffer *reply;

	pull = (struct ctdb_pulldb *)indata.dptr;

	ctdb_db = find_ctdb_db(ctdb, pull->db_id);
	if (!ctdb_db) {
		DEBUG(DEBUG_ERR,(__location__ " Unknown db 0x%08x\n", pull->db_id));
		return -1;
	}

	if (!ctdb_db_frozen(ctdb_db)) {
		DEBUG(DEBUG_ERR,
		      ("rejecting ctdb_control_pull_db when not frozen\n"));
		return -1;
	}

	reply = talloc_zero(outdata, struct ctdb_marshall_buffer);
	CTDB_NO_MEMORY(ctdb, reply);

	reply->db_id = pull->db_id;

	params.ctdb = ctdb;
	params.ctdb_db = ctdb_db;
	params.pulldata = reply;
	params.len = offsetof(struct ctdb_marshall_buffer, data);
	params.allocated_len = params.len;
	params.failed = false;

	if (ctdb_db->unhealthy_reason) {
		/* this is just a warning, as the tdb should be empty anyway */
		DEBUG(DEBUG_WARNING,("db(%s) unhealty in ctdb_control_pull_db: %s\n",
				     ctdb_db->db_name, ctdb_db->unhealthy_reason));
	}

	/* If the records are invalid, we are done */
	if (ctdb_db->invalid_records) {
		goto done;
	}

	if (ctdb_lockdb_mark(ctdb_db) != 0) {
		DEBUG(DEBUG_ERR,(__location__ " Failed to get lock on entire db - failing\n"));
		return -1;
	}

	if (tdb_traverse_read(ctdb_db->ltdb->tdb, traverse_pulldb, &params) == -1) {
		DEBUG(DEBUG_ERR,(__location__ " Failed to get traverse db '%s'\n", ctdb_db->db_name));
		ctdb_lockdb_unmark(ctdb_db);
		talloc_free(params.pulldata);
		return -1;
	}

	ctdb_lockdb_unmark(ctdb_db);

done:
	outdata->dptr = (uint8_t *)params.pulldata;
	outdata->dsize = params.len;

	if (ctdb->tunable.db_record_count_warn != 0 && params.pulldata->count > ctdb->tunable.db_record_count_warn) {
		DEBUG(DEBUG_ERR,("Database %s is big. Contains %d records\n", ctdb_db->db_name, params.pulldata->count));
	}
	if (ctdb->tunable.db_size_warn != 0 && outdata->dsize > ctdb->tunable.db_size_warn) {
		DEBUG(DEBUG_ERR,("Database %s is big. Contains %d bytes\n", ctdb_db->db_name, (int)outdata->dsize));
	}


	return 0;
}

struct db_pull_state {
	struct ctdb_context *ctdb;
	struct ctdb_db_context *ctdb_db;
	struct ctdb_marshall_buffer *recs;
	uint32_t pnn;
	uint64_t srvid;
	uint32_t num_records;
};

static int traverse_db_pull(struct tdb_context *tdb, TDB_DATA key,
			    TDB_DATA data, void *private_data)
{
	struct db_pull_state *state = (struct db_pull_state *)private_data;
	struct ctdb_marshall_buffer *recs;

	recs = ctdb_marshall_add(state->ctdb, state->recs,
				 state->ctdb_db->db_id, 0, key, NULL, data);
	if (recs == NULL) {
		TALLOC_FREE(state->recs);
		return -1;
	}
	state->recs = recs;

	if (talloc_get_size(state->recs) >=
			state->ctdb->tunable.rec_buffer_size_limit) {
		TDB_DATA buffer;
		int ret;

		buffer = ctdb_marshall_finish(state->recs);
		ret = ctdb_daemon_send_message(state->ctdb, state->pnn,
					       state->srvid, buffer);
		if (ret != 0) {
			TALLOC_FREE(state->recs);
			return -1;
		}

		state->num_records += state->recs->count;
		TALLOC_FREE(state->recs);
	}

	return 0;
}

int32_t ctdb_control_db_pull(struct ctdb_context *ctdb,
			     struct ctdb_req_control_old *c,
			     TDB_DATA indata, TDB_DATA *outdata)
{
	struct ctdb_pulldb_ext *pulldb_ext;
	struct ctdb_db_context *ctdb_db;
	struct db_pull_state state;
	int ret;

	pulldb_ext = (struct ctdb_pulldb_ext *)indata.dptr;

	ctdb_db = find_ctdb_db(ctdb, pulldb_ext->db_id);
	if (ctdb_db == NULL) {
		DEBUG(DEBUG_ERR,(__location__ " Unknown db 0x%08x\n",
				 pulldb_ext->db_id));
		return -1;
	}

	if (!ctdb_db_frozen(ctdb_db)) {
		DEBUG(DEBUG_ERR,
		      ("rejecting ctdb_control_pull_db when not frozen\n"));
		return -1;
	}

	if (ctdb_db->unhealthy_reason) {
		/* this is just a warning, as the tdb should be empty anyway */
		DEBUG(DEBUG_WARNING,
		      ("db(%s) unhealty in ctdb_control_db_pull: %s\n",
		       ctdb_db->db_name, ctdb_db->unhealthy_reason));
	}

	state.ctdb = ctdb;
	state.ctdb_db = ctdb_db;
	state.recs = NULL;
	state.pnn = c->hdr.srcnode;
	state.srvid = pulldb_ext->srvid;
	state.num_records = 0;

	/* If the records are invalid, we are done */
	if (ctdb_db->invalid_records) {
		goto done;
	}

	if (ctdb_lockdb_mark(ctdb_db) != 0) {
		DEBUG(DEBUG_ERR,
		      (__location__ " Failed to get lock on entire db - failing\n"));
		return -1;
	}

	ret = tdb_traverse_read(ctdb_db->ltdb->tdb, traverse_db_pull, &state);
	if (ret == -1) {
		DEBUG(DEBUG_ERR,
		      (__location__ " Failed to get traverse db '%s'\n",
		       ctdb_db->db_name));
		ctdb_lockdb_unmark(ctdb_db);
		return -1;
	}

	/* Last few records */
	if (state.recs != NULL) {
		TDB_DATA buffer;

		buffer = ctdb_marshall_finish(state.recs);
		ret = ctdb_daemon_send_message(state.ctdb, state.pnn,
					       state.srvid, buffer);
		if (ret != 0) {
			TALLOC_FREE(state.recs);
			ctdb_lockdb_unmark(ctdb_db);
			return -1;
		}

		state.num_records += state.recs->count;
		TALLOC_FREE(state.recs);
	}

	ctdb_lockdb_unmark(ctdb_db);

done:
	outdata->dptr = talloc_size(outdata, sizeof(uint32_t));
	if (outdata->dptr == NULL) {
		DEBUG(DEBUG_ERR, (__location__ " Memory allocation error\n"));
		return -1;
	}

	memcpy(outdata->dptr, (uint8_t *)&state.num_records, sizeof(uint32_t));
	outdata->dsize = sizeof(uint32_t);

	return 0;
}

/*
  push a bunch of records into a ltdb, filtering by rsn
 */
int32_t ctdb_control_push_db(struct ctdb_context *ctdb, TDB_DATA indata)
{
	struct ctdb_marshall_buffer *reply = (struct ctdb_marshall_buffer *)indata.dptr;
	struct ctdb_db_context *ctdb_db;
	unsigned int i;
	int ret;
	struct ctdb_rec_data_old *rec;

	if (indata.dsize < offsetof(struct ctdb_marshall_buffer, data)) {
		DEBUG(DEBUG_ERR,(__location__ " invalid data in pulldb reply\n"));
		return -1;
	}

	ctdb_db = find_ctdb_db(ctdb, reply->db_id);
	if (!ctdb_db) {
		DEBUG(DEBUG_ERR,(__location__ " Unknown db 0x%08x\n", reply->db_id));
		return -1;
	}

	if (!ctdb_db_frozen(ctdb_db)) {
		DEBUG(DEBUG_ERR,
		      ("rejecting ctdb_control_push_db when not frozen\n"));
		return -1;
	}

	if (ctdb_lockdb_mark(ctdb_db) != 0) {
		DEBUG(DEBUG_ERR,(__location__ " Failed to get lock on entire db - failing\n"));
		return -1;
	}

	rec = (struct ctdb_rec_data_old *)&reply->data[0];

	DEBUG(DEBUG_INFO,("starting push of %u records for dbid 0x%x\n",
		 reply->count, reply->db_id));

	for (i=0;i<reply->count;i++) {
		TDB_DATA key, data;
		struct ctdb_ltdb_header *hdr;

		key.dptr = &rec->data[0];
		key.dsize = rec->keylen;
		data.dptr = &rec->data[key.dsize];
		data.dsize = rec->datalen;

		if (data.dsize < sizeof(struct ctdb_ltdb_header)) {
			DEBUG(DEBUG_CRIT,(__location__ " bad ltdb record\n"));
			goto failed;
		}
		hdr = (struct ctdb_ltdb_header *)data.dptr;
		/* strip off any read only record flags. All readonly records
		   are revoked implicitely by a recovery
		*/
		hdr->flags &= ~CTDB_REC_RO_FLAGS;

		data.dptr += sizeof(*hdr);
		data.dsize -= sizeof(*hdr);

		ret = ctdb_ltdb_store(ctdb_db, key, hdr, data);
		if (ret != 0) {
			DEBUG(DEBUG_CRIT, (__location__ " Unable to store record\n"));
			goto failed;
		}

		rec = (struct ctdb_rec_data_old *)(rec->length + (uint8_t *)rec);
	}	    

	DEBUG(DEBUG_DEBUG,("finished push of %u records for dbid 0x%x\n",
		 reply->count, reply->db_id));

	if (ctdb_db_readonly(ctdb_db)) {
		DEBUG(DEBUG_CRIT,("Clearing the tracking database for dbid 0x%x\n",
				  ctdb_db->db_id));
		if (tdb_wipe_all(ctdb_db->rottdb) != 0) {
			DEBUG(DEBUG_ERR,("Failed to wipe tracking database for 0x%x. Dropping read-only delegation support\n", ctdb_db->db_id));
			tdb_close(ctdb_db->rottdb);
			ctdb_db->rottdb = NULL;
			ctdb_db_reset_readonly(ctdb_db);
		}
		while (ctdb_db->revokechild_active != NULL) {
			talloc_free(ctdb_db->revokechild_active);
		}
	}

	ctdb_lockdb_unmark(ctdb_db);
	return 0;

failed:
	ctdb_lockdb_unmark(ctdb_db);
	return -1;
}

struct db_push_state {
	struct ctdb_context *ctdb;
	struct ctdb_db_context *ctdb_db;
	uint64_t srvid;
	uint32_t num_records;
	bool failed;
};

static void db_push_msg_handler(uint64_t srvid, TDB_DATA indata,
				void *private_data)
{
	struct db_push_state *state = talloc_get_type(
		private_data, struct db_push_state);
	struct ctdb_marshall_buffer *recs;
	struct ctdb_rec_data_old *rec;
	unsigned int i;
	int ret;

	if (state->failed) {
		return;
	}

	recs = (struct ctdb_marshall_buffer *)indata.dptr;
	rec = (struct ctdb_rec_data_old *)&recs->data[0];

	DEBUG(DEBUG_INFO, ("starting push of %u records for dbid 0x%x\n",
			   recs->count, recs->db_id));

	for (i=0; i<recs->count; i++) {
		TDB_DATA key, data;
		struct ctdb_ltdb_header *hdr;

		key.dptr = &rec->data[0];
		key.dsize = rec->keylen;
		data.dptr = &rec->data[key.dsize];
		data.dsize = rec->datalen;

		if (data.dsize < sizeof(struct ctdb_ltdb_header)) {
			DEBUG(DEBUG_CRIT,(__location__ " bad ltdb record\n"));
			goto failed;
		}

		hdr = (struct ctdb_ltdb_header *)data.dptr;
		/* Strip off any read only record flags.
		 * All readonly records are revoked implicitely by a recovery.
		 */
		hdr->flags &= ~CTDB_REC_RO_FLAGS;

		data.dptr += sizeof(*hdr);
		data.dsize -= sizeof(*hdr);

		ret = ctdb_ltdb_store(state->ctdb_db, key, hdr, data);
		if (ret != 0) {
			DEBUG(DEBUG_ERR,
			      (__location__ " Unable to store record\n"));
			goto failed;
		}

		rec = (struct ctdb_rec_data_old *)(rec->length + (uint8_t *)rec);
	}

	DEBUG(DEBUG_DEBUG, ("finished push of %u records for dbid 0x%x\n",
			    recs->count, recs->db_id));

	state->num_records += recs->count;
	return;

failed:
	state->failed = true;
}

int32_t ctdb_control_db_push_start(struct ctdb_context *ctdb, TDB_DATA indata)
{
	struct ctdb_pulldb_ext *pulldb_ext;
	struct ctdb_db_context *ctdb_db;
	struct db_push_state *state;
	int ret;

	pulldb_ext = (struct ctdb_pulldb_ext *)indata.dptr;

	ctdb_db = find_ctdb_db(ctdb, pulldb_ext->db_id);
	if (ctdb_db == NULL) {
		DEBUG(DEBUG_ERR,
		      (__location__ " Unknown db 0x%08x\n", pulldb_ext->db_id));
		return -1;
	}

	if (!ctdb_db_frozen(ctdb_db)) {
		DEBUG(DEBUG_ERR,
		      ("rejecting ctdb_control_db_push_start when not frozen\n"));
		return -1;
	}

	if (ctdb_db->push_started) {
		DEBUG(DEBUG_WARNING,
		      (__location__ " DB push already started for %s\n",
		       ctdb_db->db_name));

		/* De-register old state */
		state = (struct db_push_state *)ctdb_db->push_state;
		if (state != NULL) {
			srvid_deregister(ctdb->srv, state->srvid, state);
			talloc_free(state);
			ctdb_db->push_state = NULL;
		}
	}

	state = talloc_zero(ctdb_db, struct db_push_state);
	if (state == NULL) {
		DEBUG(DEBUG_ERR, (__location__ " Memory allocation error\n"));
		return -1;
	}

	state->ctdb = ctdb;
	state->ctdb_db = ctdb_db;
	state->srvid = pulldb_ext->srvid;
	state->failed = false;

	ret = srvid_register(ctdb->srv, state, state->srvid,
			     db_push_msg_handler, state);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,
		      (__location__ " Failed to register srvid for db push\n"));
		talloc_free(state);
		return -1;
	}

	if (ctdb_lockdb_mark(ctdb_db) != 0) {
		DEBUG(DEBUG_ERR,
		      (__location__ " Failed to get lock on entire db - failing\n"));
		srvid_deregister(ctdb->srv, state->srvid, state);
		talloc_free(state);
		return -1;
	}

	ctdb_db->push_started = true;
	ctdb_db->push_state = state;

	return 0;
}

int32_t ctdb_control_db_push_confirm(struct ctdb_context *ctdb,
				     TDB_DATA indata, TDB_DATA *outdata)
{
	uint32_t db_id;
	struct ctdb_db_context *ctdb_db;
	struct db_push_state *state;

	db_id = *(uint32_t *)indata.dptr;

	ctdb_db = find_ctdb_db(ctdb, db_id);
	if (ctdb_db == NULL) {
		DEBUG(DEBUG_ERR,(__location__ " Unknown db 0x%08x\n", db_id));
		return -1;
	}

	if (!ctdb_db_frozen(ctdb_db)) {
		DEBUG(DEBUG_ERR,
		      ("rejecting ctdb_control_db_push_confirm when not frozen\n"));
		return -1;
	}

	if (!ctdb_db->push_started) {
		DEBUG(DEBUG_ERR, (__location__ " DB push not started\n"));
		return -1;
	}

	if (ctdb_db_readonly(ctdb_db)) {
		DEBUG(DEBUG_ERR,
		      ("Clearing the tracking database for dbid 0x%x\n",
		       ctdb_db->db_id));
		if (tdb_wipe_all(ctdb_db->rottdb) != 0) {
			DEBUG(DEBUG_ERR,
			      ("Failed to wipe tracking database for 0x%x."
			       " Dropping read-only delegation support\n",
			       ctdb_db->db_id));
			tdb_close(ctdb_db->rottdb);
			ctdb_db->rottdb = NULL;
			ctdb_db_reset_readonly(ctdb_db);
		}

		while (ctdb_db->revokechild_active != NULL) {
			talloc_free(ctdb_db->revokechild_active);
		}
	}

	ctdb_lockdb_unmark(ctdb_db);

	state = (struct db_push_state *)ctdb_db->push_state;
	if (state == NULL) {
		DEBUG(DEBUG_ERR, (__location__ " Missing push db state\n"));
		return -1;
	}

	srvid_deregister(ctdb->srv, state->srvid, state);

	outdata->dptr = talloc_size(outdata, sizeof(uint32_t));
	if (outdata->dptr == NULL) {
		DEBUG(DEBUG_ERR, (__location__ " Memory allocation error\n"));
		talloc_free(state);
		ctdb_db->push_state = NULL;
		return -1;
	}

	memcpy(outdata->dptr, (uint8_t *)&state->num_records, sizeof(uint32_t));
	outdata->dsize = sizeof(uint32_t);

	talloc_free(state);
	ctdb_db->push_started = false;
	ctdb_db->push_state = NULL;

	return 0;
}

struct set_recmode_state {
	struct ctdb_context *ctdb;
	struct ctdb_req_control_old *c;
};

static void set_recmode_handler(char status,
				double latency,
				void *private_data)
{
	struct set_recmode_state *state = talloc_get_type_abort(
		private_data, struct set_recmode_state);
	int s = 0;
	const char *err = NULL;

	switch (status) {
	case '0':
		/* Mutex taken */
		DEBUG(DEBUG_ERR,
		      ("ERROR: Daemon able to take recovery lock on \"%s\" during recovery\n",
		       state->ctdb->recovery_lock));
		s = -1;
		err = "Took recovery lock from daemon during recovery - probably a cluster filesystem lock coherence problem";
		break;

	case '1':
		/* Contention */
		DEBUG(DEBUG_DEBUG, (__location__ " Recovery lock check OK\n"));
		state->ctdb->recovery_mode = CTDB_RECOVERY_NORMAL;
		ctdb_process_deferred_attach(state->ctdb);

		s = 0;

		CTDB_UPDATE_RECLOCK_LATENCY(state->ctdb, "daemon reclock",
					    reclock.ctdbd, latency);
		break;

	case '2':
		/* Timeout.  Consider this a success, not a failure,
		 * as we failed to set the recovery lock which is what
		 * we wanted.  This can be caused by the cluster
		 * filesystem being very slow to arbitrate locks
		 * immediately after a node failure. */
		DEBUG(DEBUG_WARNING,
		      (__location__
		       "Time out getting recovery lock, allowing recmode set anyway\n"));
		state->ctdb->recovery_mode = CTDB_RECOVERY_NORMAL;
		ctdb_process_deferred_attach(state->ctdb);

		s = 0;
		break;

	default:
		DEBUG(DEBUG_ERR,
		      ("Unexpected error when testing recovery lock\n"));
		s = -1;
		err = "Unexpected error when testing recovery lock";
	}

	ctdb_request_control_reply(state->ctdb, state->c, NULL, s, err);
	talloc_free(state);
}

static void
ctdb_drop_all_ips_event(struct tevent_context *ev, struct tevent_timer *te,
			struct timeval t, void *private_data)
{
	struct ctdb_context *ctdb = talloc_get_type(private_data, struct ctdb_context);

	DEBUG(DEBUG_ERR,(__location__ " Been in recovery mode for too long. Dropping all IPS\n"));
	talloc_free(ctdb->release_ips_ctx);
	ctdb->release_ips_ctx = NULL;

	ctdb_release_all_ips(ctdb);
}

/*
 * Set up an event to drop all public ips if we remain in recovery for too
 * long
 */
int ctdb_deferred_drop_all_ips(struct ctdb_context *ctdb)
{
	if (ctdb->release_ips_ctx != NULL) {
		talloc_free(ctdb->release_ips_ctx);
	}
	ctdb->release_ips_ctx = talloc_new(ctdb);
	CTDB_NO_MEMORY(ctdb, ctdb->release_ips_ctx);

	tevent_add_timer(ctdb->ev, ctdb->release_ips_ctx,
			 timeval_current_ofs(ctdb->tunable.recovery_drop_all_ips, 0),
			 ctdb_drop_all_ips_event, ctdb);
	return 0;
}

/*
  set the recovery mode
 */
int32_t ctdb_control_set_recmode(struct ctdb_context *ctdb, 
				 struct ctdb_req_control_old *c,
				 TDB_DATA indata, bool *async_reply,
				 const char **errormsg)
{
	uint32_t recmode = *(uint32_t *)indata.dptr;
	struct ctdb_db_context *ctdb_db;
	struct set_recmode_state *state;
	struct ctdb_cluster_mutex_handle *h;

	if (recmode == ctdb->recovery_mode) {
		D_INFO("Recovery mode already set to %s\n",
		       recmode == CTDB_RECOVERY_NORMAL ? "NORMAL" : "ACTIVE");
		return 0;
	}

	D_NOTICE("Recovery mode set to %s\n",
		 recmode == CTDB_RECOVERY_NORMAL ? "NORMAL" : "ACTIVE");

	/* if we enter recovery but stay in recovery for too long
	   we will eventually drop all our ip addresses
	*/
	if (recmode == CTDB_RECOVERY_ACTIVE) {
		if (ctdb_deferred_drop_all_ips(ctdb) != 0) {
			D_ERR("Failed to set up deferred drop all ips\n");
		}

		ctdb->recovery_mode = CTDB_RECOVERY_ACTIVE;
		return 0;
	}

	/* From this point: recmode == CTDB_RECOVERY_NORMAL
	 *
	 * Therefore, what follows is special handling when setting
	 * recovery mode back to normal */

	TALLOC_FREE(ctdb->release_ips_ctx);

	for (ctdb_db = ctdb->db_list; ctdb_db != NULL; ctdb_db = ctdb_db->next) {
		if (ctdb_db->generation != ctdb->vnn_map->generation) {
			DEBUG(DEBUG_ERR,
			      ("Inconsistent DB generation %u for %s\n",
			       ctdb_db->generation, ctdb_db->db_name));
			DEBUG(DEBUG_ERR, ("Recovery mode set to ACTIVE\n"));
			return -1;
		}
	}

	/* force the databases to thaw */
	if (ctdb_db_all_frozen(ctdb)) {
		ctdb_control_thaw(ctdb, false);
	}

	if (ctdb->recovery_lock == NULL) {
		/* Not using recovery lock file */
		ctdb->recovery_mode = CTDB_RECOVERY_NORMAL;
		ctdb_process_deferred_attach(ctdb);
		return 0;
	}

	state = talloc_zero(ctdb, struct set_recmode_state);
	if (state == NULL) {
		DEBUG(DEBUG_ERR, (__location__ " out of memory\n"));
		return -1;
	}
	state->ctdb = ctdb;
	state->c = NULL;

	h = ctdb_cluster_mutex(state, ctdb, ctdb->recovery_lock, 5,
			       set_recmode_handler, state, NULL, NULL);
	if (h == NULL) {
		talloc_free(state);
		return -1;
	}

	state->c = talloc_steal(state, c);
	*async_reply = true;

	return 0;
}


/*
  delete a record as part of the vacuum process
  only delete if we are not lmaster or dmaster, and our rsn is <= the provided rsn
  use non-blocking locks

  return 0 if the record was successfully deleted (i.e. it does not exist
  when the function returns)
  or !0 is the record still exists in the tdb after returning.
 */
static int delete_tdb_record(struct ctdb_context *ctdb, struct ctdb_db_context *ctdb_db, struct ctdb_rec_data_old *rec)
{
	TDB_DATA key, data, data2;
	struct ctdb_ltdb_header *hdr, *hdr2;
	
	/* these are really internal tdb functions - but we need them here for
	   non-blocking lock of the freelist */
	int tdb_lock_nonblock(struct tdb_context *tdb, int list, int ltype);
	int tdb_unlock(struct tdb_context *tdb, int list, int ltype);


	key.dsize = rec->keylen;
	key.dptr  = &rec->data[0];
	data.dsize = rec->datalen;
	data.dptr = &rec->data[rec->keylen];

	if (ctdb_lmaster(ctdb, &key) == ctdb->pnn) {
		DBG_INFO("Called delete on record where we are lmaster\n");
		return -1;
	}

	if (data.dsize != sizeof(struct ctdb_ltdb_header)) {
		DBG_ERR("Bad record size\n");
		return -1;
	}

	hdr = (struct ctdb_ltdb_header *)data.dptr;

	/* use a non-blocking lock */
	if (tdb_chainlock_nonblock(ctdb_db->ltdb->tdb, key) != 0) {
		DBG_INFO("Failed to get non-blocking chain lock\n");
		return -1;
	}

	data2 = tdb_fetch(ctdb_db->ltdb->tdb, key);
	if (data2.dptr == NULL) {
		tdb_chainunlock(ctdb_db->ltdb->tdb, key);
		return 0;
	}

	if (data2.dsize < sizeof(struct ctdb_ltdb_header)) {
		if (tdb_lock_nonblock(ctdb_db->ltdb->tdb, -1, F_WRLCK) == 0) {
			if (tdb_delete(ctdb_db->ltdb->tdb, key) != 0) {
				DBG_ERR("Failed to delete corrupt record\n");
			}
			tdb_unlock(ctdb_db->ltdb->tdb, -1, F_WRLCK);
			DBG_ERR("Deleted corrupt record\n");
		}
		tdb_chainunlock(ctdb_db->ltdb->tdb, key);
		free(data2.dptr);
		return 0;
	}
	
	hdr2 = (struct ctdb_ltdb_header *)data2.dptr;

	if (hdr2->rsn > hdr->rsn) {
		tdb_chainunlock(ctdb_db->ltdb->tdb, key);
		DBG_INFO("Skipping record with rsn=%llu - called with rsn=%llu\n",
			 (unsigned long long)hdr2->rsn,
			 (unsigned long long)hdr->rsn);
		free(data2.dptr);
		return -1;
	}

	/* do not allow deleting record that have readonly flags set. */
	if (hdr->flags & CTDB_REC_RO_FLAGS) {
		tdb_chainunlock(ctdb_db->ltdb->tdb, key);
		DBG_INFO("Skipping record with readonly flags set\n");
		free(data2.dptr);
		return -1;
	}
	if (hdr2->flags & CTDB_REC_RO_FLAGS) {
		tdb_chainunlock(ctdb_db->ltdb->tdb, key);
		DBG_INFO("Skipping record with readonly flags set locally\n");
		free(data2.dptr);
		return -1;
	}

	if (hdr2->dmaster == ctdb->pnn) {
		tdb_chainunlock(ctdb_db->ltdb->tdb, key);
		DBG_INFO("Attempted delete record where we are the dmaster\n");
		free(data2.dptr);
		return -1;
	}

	if (tdb_lock_nonblock(ctdb_db->ltdb->tdb, -1, F_WRLCK) != 0) {
		tdb_chainunlock(ctdb_db->ltdb->tdb, key);
		DBG_INFO("Failed to get non-blocking freelist lock\n");
		free(data2.dptr);
		return -1;
	}

	if (tdb_delete(ctdb_db->ltdb->tdb, key) != 0) {
		tdb_unlock(ctdb_db->ltdb->tdb, -1, F_WRLCK);
		tdb_chainunlock(ctdb_db->ltdb->tdb, key);
		DBG_INFO("Failed to delete record\n");
		free(data2.dptr);
		return -1;
	}

	tdb_unlock(ctdb_db->ltdb->tdb, -1, F_WRLCK);
	tdb_chainunlock(ctdb_db->ltdb->tdb, key);
	free(data2.dptr);
	return 0;
}



struct recovery_callback_state {
	struct ctdb_req_control_old *c;
};


/*
  called when the 'recovered' event script has finished
 */
static void ctdb_end_recovery_callback(struct ctdb_context *ctdb, int status, void *p)
{
	struct recovery_callback_state *state = talloc_get_type(p, struct recovery_callback_state);

	CTDB_INCREMENT_STAT(ctdb, num_recoveries);

	if (status != 0) {
		DEBUG(DEBUG_ERR,(__location__ " recovered event script failed (status %d)\n", status));
		if (status == -ETIMEDOUT) {
			ctdb_ban_self(ctdb);
		}
	}

	ctdb_request_control_reply(ctdb, state->c, NULL, status, NULL);
	talloc_free(state);

	gettimeofday(&ctdb->last_recovery_finished, NULL);

	if (ctdb->runstate == CTDB_RUNSTATE_FIRST_RECOVERY) {
		ctdb_set_runstate(ctdb, CTDB_RUNSTATE_STARTUP);
	}
}

/*
  recovery has finished
 */
int32_t ctdb_control_end_recovery(struct ctdb_context *ctdb, 
				struct ctdb_req_control_old *c,
				bool *async_reply)
{
	int ret;
	struct recovery_callback_state *state;

	DEBUG(DEBUG_ERR,("Recovery has finished\n"));

	ctdb_persistent_finish_trans3_commits(ctdb);

	state = talloc(ctdb, struct recovery_callback_state);
	CTDB_NO_MEMORY(ctdb, state);

	state->c    = c;

	ret = ctdb_event_script_callback(ctdb, state,
					 ctdb_end_recovery_callback, 
					 state, 
					 CTDB_EVENT_RECOVERED, "%s", "");

	if (ret != 0) {
		DEBUG(DEBUG_ERR,(__location__ " Failed to end recovery\n"));
		talloc_free(state);
		return -1;
	}

	/* tell the control that we will be reply asynchronously */
	state->c    = talloc_steal(state, c);
	*async_reply = true;
	return 0;
}

/*
  called when the 'startrecovery' event script has finished
 */
static void ctdb_start_recovery_callback(struct ctdb_context *ctdb, int status, void *p)
{
	struct recovery_callback_state *state = talloc_get_type(p, struct recovery_callback_state);

	if (status != 0) {
		DEBUG(DEBUG_ERR,(__location__ " startrecovery event script failed (status %d)\n", status));
	}

	ctdb_request_control_reply(ctdb, state->c, NULL, status, NULL);
	talloc_free(state);
}

static void run_start_recovery_event(struct ctdb_context *ctdb,
				     struct recovery_callback_state *state)
{
	int ret;

	ret = ctdb_event_script_callback(ctdb, state,
					 ctdb_start_recovery_callback,
					 state,
					 CTDB_EVENT_START_RECOVERY,
					 "%s", "");

	if (ret != 0) {
		DEBUG(DEBUG_ERR,("Unable to run startrecovery event\n"));
		ctdb_request_control_reply(ctdb, state->c, NULL, -1, NULL);
		talloc_free(state);
		return;
	}

	return;
}

static bool reclock_strings_equal(const char *a, const char *b)
{
	return (a == NULL && b == NULL) ||
		(a != NULL && b != NULL && strcmp(a, b) == 0);
}

static void start_recovery_reclock_callback(struct ctdb_context *ctdb,
						int32_t status,
						TDB_DATA data,
						const char *errormsg,
						void *private_data)
{
	struct recovery_callback_state *state = talloc_get_type_abort(
		private_data, struct recovery_callback_state);
	const char *local = ctdb->recovery_lock;
	const char *remote = NULL;

	if (status != 0) {
		DEBUG(DEBUG_ERR, (__location__ " GET_RECLOCK failed\n"));
		ctdb_request_control_reply(ctdb, state->c, NULL,
					   status, errormsg);
		talloc_free(state);
		return;
	}

	/* Check reclock consistency */
	if (data.dsize > 0) {
		/* Ensure NUL-termination */
		data.dptr[data.dsize-1] = '\0';
		remote = (const char *)data.dptr;
	}
	if (! reclock_strings_equal(local, remote)) {
		/* Inconsistent */
		ctdb_request_control_reply(ctdb, state->c, NULL, -1, NULL);
		DEBUG(DEBUG_ERR,
		      ("Recovery lock configuration inconsistent: "
		       "recmaster has %s, this node has %s, shutting down\n",
		       remote == NULL ? "NULL" : remote,
		       local == NULL ? "NULL" : local));
		talloc_free(state);
		ctdb_shutdown_sequence(ctdb, 1);
	}
	DEBUG(DEBUG_INFO,
	      ("Recovery lock consistency check successful\n"));

	run_start_recovery_event(ctdb, state);
}

/* Check recovery lock consistency and run eventscripts for the
 * "startrecovery" event */
int32_t ctdb_control_start_recovery(struct ctdb_context *ctdb,
				    struct ctdb_req_control_old *c,
				    bool *async_reply)
{
	int ret;
	struct recovery_callback_state *state;
	uint32_t recmaster = c->hdr.srcnode;

	DEBUG(DEBUG_ERR, ("Recovery has started\n"));
	gettimeofday(&ctdb->last_recovery_started, NULL);

	state = talloc(ctdb, struct recovery_callback_state);
	CTDB_NO_MEMORY(ctdb, state);

	state->c = c;

	/* Although the recovery master sent this node a start
	 * recovery control, this node might still think the recovery
	 * master is disconnected.  In this case defer the recovery
	 * lock consistency check. */
	if (ctdb->nodes[recmaster]->flags & NODE_FLAGS_DISCONNECTED) {
		run_start_recovery_event(ctdb, state);
	} else {
		/* Ask the recovery master about its reclock setting */
		ret = ctdb_daemon_send_control(ctdb,
					       recmaster,
					       0,
					       CTDB_CONTROL_GET_RECLOCK_FILE,
					       0, 0,
					       tdb_null,
					       start_recovery_reclock_callback,
					       state);

		if (ret != 0) {
			DEBUG(DEBUG_ERR, (__location__ " GET_RECLOCK failed\n"));
			talloc_free(state);
			return -1;
		}
	}

	/* tell the control that we will be reply asynchronously */
	state->c = talloc_steal(state, c);
	*async_reply = true;

	return 0;
}

/*
 try to delete all these records as part of the vacuuming process
 and return the records we failed to delete
*/
int32_t ctdb_control_try_delete_records(struct ctdb_context *ctdb, TDB_DATA indata, TDB_DATA *outdata)
{
	struct ctdb_marshall_buffer *reply = (struct ctdb_marshall_buffer *)indata.dptr;
	struct ctdb_db_context *ctdb_db;
	unsigned int i;
	struct ctdb_rec_data_old *rec;
	struct ctdb_marshall_buffer *records;

	if (indata.dsize < offsetof(struct ctdb_marshall_buffer, data)) {
		DEBUG(DEBUG_ERR,(__location__ " invalid data in try_delete_records\n"));
		return -1;
	}

	ctdb_db = find_ctdb_db(ctdb, reply->db_id);
	if (!ctdb_db) {
		DEBUG(DEBUG_ERR,(__location__ " Unknown db 0x%08x\n", reply->db_id));
		return -1;
	}


	DEBUG(DEBUG_DEBUG,("starting try_delete_records of %u records for dbid 0x%x\n",
		 reply->count, reply->db_id));


	/* create a blob to send back the records we couldnt delete */	
	records = (struct ctdb_marshall_buffer *)
			talloc_zero_size(outdata, 
				    offsetof(struct ctdb_marshall_buffer, data));
	if (records == NULL) {
		DEBUG(DEBUG_ERR,(__location__ " Out of memory\n"));
		return -1;
	}
	records->db_id = ctdb_db->db_id;


	rec = (struct ctdb_rec_data_old *)&reply->data[0];
	for (i=0;i<reply->count;i++) {
		TDB_DATA key, data;

		key.dptr = &rec->data[0];
		key.dsize = rec->keylen;
		data.dptr = &rec->data[key.dsize];
		data.dsize = rec->datalen;

		if (data.dsize < sizeof(struct ctdb_ltdb_header)) {
			DEBUG(DEBUG_CRIT,(__location__ " bad ltdb record in indata\n"));
			talloc_free(records);
			return -1;
		}

		/* If we cant delete the record we must add it to the reply
		   so the lmaster knows it may not purge this record
		*/
		if (delete_tdb_record(ctdb, ctdb_db, rec) != 0) {
			size_t old_size;
			struct ctdb_ltdb_header *hdr;

			hdr = (struct ctdb_ltdb_header *)data.dptr;
			data.dptr += sizeof(*hdr);
			data.dsize -= sizeof(*hdr);

			DEBUG(DEBUG_INFO, (__location__ " Failed to vacuum delete record with hash 0x%08x\n", ctdb_hash(&key)));

			old_size = talloc_get_size(records);
			records = talloc_realloc_size(outdata, records, old_size + rec->length);
			if (records == NULL) {
				DEBUG(DEBUG_ERR,(__location__ " Failed to expand\n"));
				return -1;
			}
			records->count++;
			memcpy(old_size+(uint8_t *)records, rec, rec->length);
		} 

		rec = (struct ctdb_rec_data_old *)(rec->length + (uint8_t *)rec);
	}	    


	*outdata = ctdb_marshall_finish(records);

	return 0;
}

/*
  report capabilities
 */
int32_t ctdb_control_get_capabilities(struct ctdb_context *ctdb, TDB_DATA *outdata)
{
	uint32_t *capabilities = NULL;

	capabilities = talloc(outdata, uint32_t);
	CTDB_NO_MEMORY(ctdb, capabilities);
	*capabilities = ctdb->capabilities;

	outdata->dsize = sizeof(uint32_t);
	outdata->dptr = (uint8_t *)capabilities;

	return 0;	
}

/* The recovery daemon will ping us at regular intervals.
   If we havent been pinged for a while we assume the recovery
   daemon is inoperable and we restart.
*/
static void ctdb_recd_ping_timeout(struct tevent_context *ev,
				   struct tevent_timer *te,
				   struct timeval t, void *p)
{
	struct ctdb_context *ctdb = talloc_get_type(p, struct ctdb_context);
	uint32_t *count = talloc_get_type(ctdb->recd_ping_count, uint32_t);

	DEBUG(DEBUG_ERR, ("Recovery daemon ping timeout. Count : %u\n", *count));

	if (*count < ctdb->tunable.recd_ping_failcount) {
		(*count)++;
		tevent_add_timer(ctdb->ev, ctdb->recd_ping_count,
				 timeval_current_ofs(ctdb->tunable.recd_ping_timeout, 0),
				 ctdb_recd_ping_timeout, ctdb);
		return;
	}

	DEBUG(DEBUG_ERR, ("Final timeout for recovery daemon ping. Restarting recovery daemon. (This can be caused if the cluster filesystem has hung)\n"));

	ctdb_stop_recoverd(ctdb);
	ctdb_start_recoverd(ctdb);
}

int32_t ctdb_control_recd_ping(struct ctdb_context *ctdb)
{
	talloc_free(ctdb->recd_ping_count);

	ctdb->recd_ping_count = talloc_zero(ctdb, uint32_t);
	CTDB_NO_MEMORY(ctdb, ctdb->recd_ping_count);

	if (ctdb->tunable.recd_ping_timeout != 0) {
		tevent_add_timer(ctdb->ev, ctdb->recd_ping_count,
				 timeval_current_ofs(ctdb->tunable.recd_ping_timeout, 0),
				 ctdb_recd_ping_timeout, ctdb);
	}

	return 0;
}



int32_t ctdb_control_set_recmaster(struct ctdb_context *ctdb, uint32_t opcode, TDB_DATA indata)
{
	uint32_t new_recmaster;

	CHECK_CONTROL_DATA_SIZE(sizeof(uint32_t));
	new_recmaster = ((uint32_t *)(&indata.dptr[0]))[0];

	if (ctdb->pnn != new_recmaster && ctdb->recovery_master == ctdb->pnn) {
		DEBUG(DEBUG_ERR,
		      ("Remote node (%u) is now the recovery master\n",
		       new_recmaster));
	}

	if (ctdb->pnn == new_recmaster && ctdb->recovery_master != new_recmaster) {
		DEBUG(DEBUG_ERR,
		      ("This node (%u) is now the recovery master\n",
		       ctdb->pnn));
	}

	ctdb->recovery_master = new_recmaster;
	return 0;
}

void ctdb_node_become_inactive(struct ctdb_context *ctdb)
{
	struct ctdb_db_context *ctdb_db;

	D_WARNING("Making node INACTIVE\n");

	/*
	 * Do not service database calls - reset generation to invalid
	 * so this node ignores any REQ/REPLY CALL/DMASTER
	 */
	ctdb->vnn_map->generation = INVALID_GENERATION;
	for (ctdb_db = ctdb->db_list; ctdb_db != NULL; ctdb_db = ctdb_db->next) {
		ctdb_db->generation = INVALID_GENERATION;
	}

	/*
	 * Although this bypasses the control, the only thing missing
	 * is the deferred drop of all public IPs, which isn't
	 * necessary because they are dropped below
	 */
	if (ctdb->recovery_mode != CTDB_RECOVERY_ACTIVE) {
		D_NOTICE("Recovery mode set to ACTIVE\n");
		ctdb->recovery_mode = CTDB_RECOVERY_ACTIVE;
	}

	/*
	 * Initiate database freeze - this will be scheduled for
	 * immediate execution and will be in progress long before the
	 * calling control returns
	 */
	ctdb_daemon_send_control(ctdb,
				 ctdb->pnn,
				 0,
				 CTDB_CONTROL_FREEZE,
				 0,
				 CTDB_CTRL_FLAG_NOREPLY,
				 tdb_null,
				 NULL,
				 NULL);

	D_NOTICE("Dropping all public IP addresses\n");
	ctdb_release_all_ips(ctdb);
}

int32_t ctdb_control_stop_node(struct ctdb_context *ctdb)
{
	DEBUG(DEBUG_ERR, ("Stopping node\n"));
	ctdb->nodes[ctdb->pnn]->flags |= NODE_FLAGS_STOPPED;

	ctdb_node_become_inactive(ctdb);

	return 0;
}

int32_t ctdb_control_continue_node(struct ctdb_context *ctdb)
{
	DEBUG(DEBUG_ERR, ("Continue node\n"));
	ctdb->nodes[ctdb->pnn]->flags &= ~NODE_FLAGS_STOPPED;

	return 0;
}

