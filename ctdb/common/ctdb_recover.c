/* 
   ctdb_control protocol code

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
		DEBUG(0, (__location__ "Failed to allocate dbmap array\n"));
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
		DEBUG(0, (__location__ "Failed to allocate nodemap array\n"));
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

int 
ctdb_control_writerecord(struct ctdb_context *ctdb, uint32_t opcode, TDB_DATA indata, TDB_DATA *outdata)
{
	struct ctdb_write_record *wr;
	struct ctdb_db_context *ctdb_db;
	struct ctdb_ltdb_header header;
	TDB_DATA key, data;
	int ret;

	outdata->dsize = 0;
	outdata->dptr = NULL;

	wr = (struct ctdb_write_record *)indata.dptr;

	ctdb_db = find_ctdb_db(ctdb, wr->dbid);
	if (!ctdb_db) {
		DEBUG(0,(__location__ " Unknown db 0x%08x\n", wr->dbid));
		return -1;
	}

	key.dsize  = wr->keylen;
	key.dptr   = (unsigned char *)talloc_memdup(outdata, &wr->blob[0], wr->keylen);

	data.dsize = wr->datalen;
	data.dptr  = (unsigned char *)talloc_memdup(outdata, &wr->blob[wr->keylen], wr->datalen);


	ret = ctdb_ltdb_lock(ctdb_db, key);
	if (ret != 0) {
		DEBUG(0, (__location__ "Unable to lock db\n"));
		return -1;
	}
	ret = ctdb_ltdb_fetch(ctdb_db, key, &header, outdata, NULL);
	if (ret != 0) {
		DEBUG(0, (__location__ "Unable to fetch record\n"));
		ctdb_ltdb_unlock(ctdb_db, key);
		return -1;
	}
	header.rsn++;

	ret = ctdb_ltdb_store(ctdb_db, key, &header, data);
	if (ret != 0) {
		DEBUG(0, (__location__ "Unable to store record\n"));
		ctdb_ltdb_unlock(ctdb_db, key);
		return -1;
	}
	ctdb_ltdb_unlock(ctdb_db, key);

	return 0;
}
