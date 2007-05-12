/* 
   ctdb recovery code

   Copyright (C) Andrew Tridgell  2007
   Copyright (C) Ronnie Sahlberg  2007

   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2 of the License, or (at your option) any later version.

   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with this library; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/
#include "includes.h"
#include "lib/events/events.h"
#include "lib/tdb/include/tdb.h"
#include "system/network.h"
#include "system/filesys.h"
#include "system/wait.h"
#include "../include/ctdb_private.h"
#include "lib/util/dlinklist.h"
#include "db_wrap.h"

/*
  lock all databases - mark only
 */
static int ctdb_lock_all_databases_mark(struct ctdb_context *ctdb)
{
	struct ctdb_db_context *ctdb_db;
	if (ctdb->freeze_mode != CTDB_FREEZE_FROZEN) {
		DEBUG(0,("Attempt to mark all databases locked when not frozen\n"));
		return -1;
	}
	for (ctdb_db=ctdb->db_list;ctdb_db;ctdb_db=ctdb_db->next) {
		if (tdb_lockall_mark(ctdb_db->ltdb->tdb) != 0) {
			return -1;
		}
	}
	return 0;
}

/*
  lock all databases - unmark only
 */
static int ctdb_lock_all_databases_unmark(struct ctdb_context *ctdb)
{
	struct ctdb_db_context *ctdb_db;
	if (ctdb->freeze_mode != CTDB_FREEZE_FROZEN) {
		DEBUG(0,("Attempt to unmark all databases locked when not frozen\n"));
		return -1;
	}
	for (ctdb_db=ctdb->db_list;ctdb_db;ctdb_db=ctdb_db->next) {
		if (tdb_lockall_unmark(ctdb_db->ltdb->tdb) != 0) {
			return -1;
		}
	}
	return 0;
}


int 
ctdb_control_getvnnmap(struct ctdb_context *ctdb, uint32_t opcode, TDB_DATA indata, TDB_DATA *outdata)
{
	CHECK_CONTROL_DATA_SIZE(0);
	struct ctdb_vnn_map_wire *map;
	size_t len;

	len = offsetof(struct ctdb_vnn_map_wire, map) + sizeof(uint32_t)*ctdb->vnn_map->size;
	map = talloc_size(outdata, len);
	CTDB_NO_MEMORY_VOID(ctdb, map);

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
	struct ctdb_dbid_map *dbid_map;

	CHECK_CONTROL_DATA_SIZE(0);

	len = 0;
	for(ctdb_db=ctdb->db_list;ctdb_db;ctdb_db=ctdb_db->next){
		len++;
	}


	outdata->dsize = offsetof(struct ctdb_dbid_map, dbids) + 4*len;
	outdata->dptr  = (unsigned char *)talloc_zero_size(outdata, outdata->dsize);
	if (!outdata->dptr) {
		DEBUG(0, (__location__ " Failed to allocate dbmap array\n"));
		exit(1);
	}

	dbid_map = (struct ctdb_dbid_map *)outdata->dptr;
	dbid_map->num = len;
	for(i=0,ctdb_db=ctdb->db_list;ctdb_db;i++,ctdb_db=ctdb_db->next){
		dbid_map->dbids[i] = ctdb_db->db_id;
	}

	return 0;
}

int 
ctdb_control_getnodemap(struct ctdb_context *ctdb, uint32_t opcode, TDB_DATA indata, TDB_DATA *outdata)
{
	uint32_t i, num_nodes;
	struct ctdb_node_map *node_map;

	CHECK_CONTROL_DATA_SIZE(0);

	num_nodes = ctdb_get_num_nodes(ctdb);

	outdata->dsize = offsetof(struct ctdb_node_map, nodes) + num_nodes*sizeof(struct ctdb_node_and_flags);
	outdata->dptr  = (unsigned char *)talloc_zero_size(outdata, outdata->dsize);
	if (!outdata->dptr) {
		DEBUG(0, (__location__ " Failed to allocate nodemap array\n"));
		exit(1);
	}

	node_map = (struct ctdb_node_map *)outdata->dptr;
	node_map->num = num_nodes;
	for (i=0; i<num_nodes; i++) {
		node_map->nodes[i].vnn   = ctdb->nodes[i]->vnn;
		node_map->nodes[i].flags = ctdb->nodes[i]->flags;
	}

	return 0;
}

struct getkeys_params {
	struct ctdb_context *ctdb;
	uint32_t lmaster;
	uint32_t rec_count;
	struct getkeys_rec {
		TDB_DATA key;
		TDB_DATA data;
	} *recs;
};

static int traverse_getkeys(struct tdb_context *tdb, TDB_DATA key, TDB_DATA data, void *p)
{
	struct getkeys_params *params = (struct getkeys_params *)p;
	uint32_t lmaster;

	lmaster = ctdb_lmaster(params->ctdb, &key);

	/* only include this record if the lmaster matches or if
	   the wildcard lmaster (-1) was specified.
	*/
	if ((params->lmaster != CTDB_LMASTER_ANY) && (params->lmaster != lmaster)) {
		return 0;
	}

	params->recs = talloc_realloc(NULL, params->recs, struct getkeys_rec, params->rec_count+1);
	key.dptr = talloc_memdup(params->recs, key.dptr, key.dsize);
	data.dptr = talloc_memdup(params->recs, data.dptr, data.dsize);
	params->recs[params->rec_count].key = key;
	params->recs[params->rec_count].data = data;
	params->rec_count++;

	return 0;
}

/*
  pul a bunch of records from a ltdb, filtering by lmaster
 */
int32_t ctdb_control_pull_db(struct ctdb_context *ctdb, TDB_DATA indata, TDB_DATA *outdata)
{
	struct ctdb_control_pulldb *pull;
	struct ctdb_db_context *ctdb_db;
	struct getkeys_params params;
	struct ctdb_control_pulldb_reply *reply;
	int i;
	size_t len = 0;

	if (ctdb->freeze_mode != CTDB_FREEZE_FROZEN) {
		DEBUG(0,("rejecting ctdb_control_pull_db when not frozen\n"));
		return -1;
	}

	pull = (struct ctdb_control_pulldb *)indata.dptr;
	
	ctdb_db = find_ctdb_db(ctdb, pull->db_id);
	if (!ctdb_db) {
		DEBUG(0,(__location__ " Unknown db\n"));
		return -1;
	}

	params.ctdb = ctdb;
	params.lmaster = pull->lmaster;

	params.rec_count = 0;
	params.recs = talloc_array(outdata, struct getkeys_rec, 0);
	CTDB_NO_MEMORY(ctdb, params.recs);

	if (ctdb_lock_all_databases_mark(ctdb) != 0) {
		DEBUG(0,(__location__ " Failed to get lock on entired db - failing\n"));
		return -1;
	}

	tdb_traverse_read(ctdb_db->ltdb->tdb, traverse_getkeys, &params);

	ctdb_lock_all_databases_unmark(ctdb);

	reply = talloc(outdata, struct ctdb_control_pulldb_reply);
	CTDB_NO_MEMORY(ctdb, reply);

	reply->db_id = pull->db_id;
	reply->count = params.rec_count;

	len = offsetof(struct ctdb_control_pulldb_reply, data);

	for (i=0;i<reply->count;i++) {
		struct ctdb_rec_data *rec;
		rec = ctdb_marshall_record(outdata, 0, params.recs[i].key, params.recs[i].data);
		reply = talloc_realloc_size(outdata, reply, rec->length + len);
		memcpy(len+(uint8_t *)reply, rec, rec->length);
		len += rec->length;
		talloc_free(rec);
	}

	talloc_free(params.recs);

	outdata->dptr = (uint8_t *)reply;
	outdata->dsize = len;

	return 0;
}

/*
  push a bunch of records into a ltdb, filtering by rsn
 */
int32_t ctdb_control_push_db(struct ctdb_context *ctdb, TDB_DATA indata)
{
	struct ctdb_control_pulldb_reply *reply = (struct ctdb_control_pulldb_reply *)indata.dptr;
	struct ctdb_db_context *ctdb_db;
	int i, ret;
	struct ctdb_rec_data *rec;

	if (ctdb->freeze_mode != CTDB_FREEZE_FROZEN) {
		DEBUG(0,("rejecting ctdb_control_push_db when not frozen\n"));
		return -1;
	}

	if (indata.dsize < offsetof(struct ctdb_control_pulldb_reply, data)) {
		DEBUG(0,(__location__ " invalid data in pulldb reply\n"));
		return -1;
	}

	ctdb_db = find_ctdb_db(ctdb, reply->db_id);
	if (!ctdb_db) {
		DEBUG(0,(__location__ " Unknown db 0x%08x\n", reply->db_id));
		return -1;
	}

	if (ctdb_lock_all_databases_mark(ctdb) != 0) {
		DEBUG(0,(__location__ " Failed to get lock on entired db - failing\n"));
		return -1;
	}

	rec = (struct ctdb_rec_data *)&reply->data[0];

	for (i=0;i<reply->count;i++) {
		TDB_DATA key, data;
		struct ctdb_ltdb_header *hdr, header;

		key.dptr = &rec->data[0];
		key.dsize = rec->keylen;
		data.dptr = &rec->data[key.dsize];
		data.dsize = rec->datalen;

		if (data.dsize < sizeof(struct ctdb_ltdb_header)) {
			DEBUG(0,(__location__ " bad ltdb record\n"));
			goto failed;
		}
		hdr = (struct ctdb_ltdb_header *)data.dptr;
		data.dptr += sizeof(*hdr);
		data.dsize -= sizeof(*hdr);

		ret = ctdb_ltdb_fetch(ctdb_db, key, &header, NULL, NULL);
		if (ret != 0) {
			DEBUG(0, (__location__ " Unable to fetch record\n"));
			goto failed;
		}
		/* The check for dmaster gives priority to the dmaster
		   if the rsn values are equal */
		if (header.rsn < hdr->rsn ||
		    (header.dmaster != ctdb->vnn && header.rsn == hdr->rsn)) {
			ret = ctdb_ltdb_store(ctdb_db, key, hdr, data);
			if (ret != 0) {
				DEBUG(0, (__location__ " Unable to store record\n"));
				goto failed;
			}
		}

		rec = (struct ctdb_rec_data *)(rec->length + (uint8_t *)rec);
	}	    

	ctdb_lock_all_databases_unmark(ctdb);
	return 0;

failed:
	ctdb_lock_all_databases_unmark(ctdb);
	return -1;
}


static int traverse_setdmaster(struct tdb_context *tdb, TDB_DATA key, TDB_DATA data, void *p)
{
	uint32_t *dmaster = (uint32_t *)p;
	struct ctdb_ltdb_header *header = (struct ctdb_ltdb_header *)data.dptr;
	int ret;

	header->dmaster = *dmaster;

	ret = tdb_store(tdb, key, data, TDB_REPLACE);
	if (ret) {
		DEBUG(0,(__location__ " failed to write tdb data back  ret:%d\n",ret));
		return ret;
	}
	return 0;
}

int32_t ctdb_control_set_dmaster(struct ctdb_context *ctdb, TDB_DATA indata)
{
	struct ctdb_control_set_dmaster *p = (struct ctdb_control_set_dmaster *)indata.dptr;
	struct ctdb_db_context *ctdb_db;

	if (ctdb->freeze_mode != CTDB_FREEZE_FROZEN) {
		DEBUG(0,("rejecting ctdb_control_set_dmaster when not frozen\n"));
		return -1;
	}

	ctdb_db = find_ctdb_db(ctdb, p->db_id);
	if (!ctdb_db) {
		DEBUG(0,(__location__ " Unknown db 0x%08x\n", p->db_id));
		return -1;
	}

	if (ctdb_lock_all_databases_mark(ctdb) != 0) {
		DEBUG(0,(__location__ " Failed to get lock on entired db - failing\n"));
		return -1;
	}

	tdb_traverse(ctdb_db->ltdb->tdb, traverse_setdmaster, &p->dmaster);

	ctdb_lock_all_databases_unmark(ctdb);
	
	return 0;
}


static int traverse_cleardb(struct tdb_context *tdb, TDB_DATA key, TDB_DATA data, void *p)
{
	int ret;

	ret = tdb_delete(tdb, key);
	if (ret) {
		DEBUG(0,(__location__ " failed to delete tdb record\n"));
		return ret;
	}
	return 0;
}

		
int32_t ctdb_control_clear_db(struct ctdb_context *ctdb, TDB_DATA indata)
{
	uint32_t dbid = *(uint32_t *)indata.dptr;
	struct ctdb_db_context *ctdb_db;

	if (ctdb->freeze_mode != CTDB_FREEZE_FROZEN) {
		DEBUG(0,("rejecting ctdb_control_clear_db when not frozen\n"));
		return -1;
	}

	ctdb_db = find_ctdb_db(ctdb, dbid);
	if (!ctdb_db) {
		DEBUG(0,(__location__ " Unknown db 0x%08x\n",dbid));
		return -1;
	}

	if (ctdb_lock_all_databases_mark(ctdb) != 0) {
		DEBUG(0,(__location__ " Failed to get lock on entired db - failing\n"));
		return -1;
	}

	tdb_traverse(ctdb_db->ltdb->tdb, traverse_cleardb, NULL);

	ctdb_lock_all_databases_unmark(ctdb);

	return 0;
}

/*
  set the recovery mode
 */
int32_t ctdb_control_set_recmode(struct ctdb_context *ctdb, TDB_DATA indata)
{
	uint32_t recmode = *(uint32_t *)indata.dptr;
	if (ctdb->freeze_mode != CTDB_FREEZE_FROZEN) {
		DEBUG(0,("Attempt to change recovery mode to %u when not frozen\n", 
			 recmode));
		return -1;
	}
	ctdb->recovery_mode = recmode;
	return 0;
}
