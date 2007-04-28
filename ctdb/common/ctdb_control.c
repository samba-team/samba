/* 
   ctdb_control protocol code

   Copyright (C) Andrew Tridgell  2007

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

struct ctdb_control_state {
	struct ctdb_context *ctdb;
	uint32_t reqid;
	ctdb_control_callback_fn_t callback;
	void *private_data;
};

#define CHECK_CONTROL_DATA_SIZE(size) do { \
 if (indata.dsize != size) { \
	 DEBUG(0,(__location__ " Invalid data size in opcode %u. Got %u expected %u\n", \
		  opcode, indata.dsize, size));				\
	 return -1; \
 } \
 } while (0)


struct getkeys_params {
	struct ctdb_db_context *ctdb_db;
	TDB_DATA *outdata;
};

static int traverse_getkeys(struct tdb_context *tdb, TDB_DATA key, TDB_DATA data, void *p)
{
	struct getkeys_params *params = (struct getkeys_params *)p;
	TDB_DATA *outdata = talloc_get_type(params->outdata, TDB_DATA);
	struct ctdb_db_context *ctdb_db = talloc_get_type(params->ctdb_db, struct ctdb_db_context);
	unsigned char *ptr;
	int len, ret;

	len=outdata->dsize;
	len+=4; /*lmaster*/
	len+=4; /*key len*/
	len+=key.dsize;
	len=(len+CTDB_DS_ALIGNMENT-1)& ~(CTDB_DS_ALIGNMENT-1);
	len+=sizeof(struct ctdb_ltdb_header);
	len=(len+CTDB_DS_ALIGNMENT-1)& ~(CTDB_DS_ALIGNMENT-1);
	len+=4; /*data len */
	len+=data.dsize;
	len=(len+CTDB_DS_ALIGNMENT-1)& ~(CTDB_DS_ALIGNMENT-1);

	ptr=outdata->dptr=talloc_realloc_size(outdata, outdata->dptr, len);
	ptr+=outdata->dsize;
	outdata->dsize=len;
	/* number of records is stored as the first 4 bytes */
	(*((uint32_t *)(&outdata->dptr[0])))++;

	*((uint32_t *)ptr)=ctdb_lmaster(ctdb_db->ctdb, &key);
	ptr+=4;

	*((uint32_t *)ptr)=key.dsize;
	ptr+=4;
	memcpy(ptr, key.dptr, key.dsize);
	ptr+= (key.dsize+CTDB_DS_ALIGNMENT-1)& ~(CTDB_DS_ALIGNMENT-1);

	memcpy(ptr, data.dptr, sizeof(struct ctdb_ltdb_header));
	ptr+=(sizeof(struct ctdb_ltdb_header)+CTDB_DS_ALIGNMENT-1)& ~(CTDB_DS_ALIGNMENT-1);

	*((uint32_t *)ptr)=data.dsize-sizeof(struct ctdb_ltdb_header);
	ptr+=4;
	memcpy(ptr, data.dptr+sizeof(struct ctdb_ltdb_header), data.dsize-sizeof(struct ctdb_ltdb_header));
	ptr+= (data.dsize-sizeof(struct ctdb_ltdb_header)+CTDB_DS_ALIGNMENT-1)& ~(CTDB_DS_ALIGNMENT-1);

	return 0;
}

/*
  process a control request
 */
static int32_t ctdb_control_dispatch(struct ctdb_context *ctdb, 
				     uint32_t opcode, TDB_DATA indata,
				     TDB_DATA *outdata)
{
	switch (opcode) {
	case CTDB_CONTROL_PROCESS_EXISTS: {
		pid_t pid;
		int32_t ret;
		CHECK_CONTROL_DATA_SIZE(sizeof(pid));
		pid = *(pid_t *)indata.dptr;
		ret = kill(pid, 0);
		DEBUG(5,("process_exists on %u:%u gave %d\n", 
			 ctdb->vnn, pid, ret));
		return ret;
	}

	case CTDB_CONTROL_SET_DEBUG: {
		CHECK_CONTROL_DATA_SIZE(sizeof(uint32_t));
		LogLevel = *(uint32_t *)indata.dptr;
		return 0;
	}

	case CTDB_CONTROL_GET_DEBUG: {
		CHECK_CONTROL_DATA_SIZE(0);
		outdata->dptr = (uint8_t *)&LogLevel;
		outdata->dsize = sizeof(LogLevel);
		return 0;
	}

	case CTDB_CONTROL_STATUS: {
		CHECK_CONTROL_DATA_SIZE(0);
		outdata->dptr = (uint8_t *)&ctdb->status;
		outdata->dsize = sizeof(ctdb->status);
		return 0;
	}

	case CTDB_CONTROL_GETVNNMAP: {
		uint32_t i, len;
		CHECK_CONTROL_DATA_SIZE(0);
		len = 2+ctdb->vnn_map->size;
		outdata->dsize = 4*len;
		outdata->dptr = (unsigned char *)talloc_array(outdata, uint32_t, len);
		
		((uint32_t *)outdata->dptr)[0] = ctdb->vnn_map->generation;
		((uint32_t *)outdata->dptr)[1] = ctdb->vnn_map->size;
		for (i=0;i<ctdb->vnn_map->size;i++) {
			((uint32_t *)outdata->dptr)[i+2] = ctdb->vnn_map->map[i];
		}

		return 0;
	}

	case CTDB_CONTROL_GET_DBMAP: {
		uint32_t i, len;
		struct ctdb_db_context *ctdb_db;

		CHECK_CONTROL_DATA_SIZE(0);
		len = 0;
		for(ctdb_db=ctdb->db_list;ctdb_db;ctdb_db=ctdb_db->next){
			len++;
		}

		outdata->dsize = (len+1)*sizeof(uint32_t);
		outdata->dptr = (unsigned char *)talloc_array(outdata, uint32_t, len+1);
		if (!outdata->dptr) {
			DEBUG(0, (__location__ "Failed to allocate dbmap array\n"));
			exit(1);
		}

		((uint32_t *)outdata->dptr)[0] = len;
		for(i=0,ctdb_db=ctdb->db_list;ctdb_db;i++,ctdb_db=ctdb_db->next){
			((uint32_t *)outdata->dptr)[i+1] = ctdb_db->db_id;
		}
	
		return 0;
	}

	case CTDB_CONTROL_GET_NODEMAP: {
		uint32_t num_nodes, i, len;
		struct ctdb_node *node;

		num_nodes = ctdb_get_num_nodes(ctdb);
		len = 2*num_nodes + 1;

		outdata->dsize = len*sizeof(uint32_t);
		outdata->dptr = (unsigned char *)talloc_array(outdata, uint32_t, len);
		if (!outdata->dptr) {
			DEBUG(0, (__location__ "Failed to allocate node array\n"));
			exit(1);
		}

		
		((uint32_t *)outdata->dptr)[0] = num_nodes;
		for (i=0; i<num_nodes; i++) {
			node=ctdb->nodes[i];
			((uint32_t *)outdata->dptr)[i*2+1]=node->vnn;
			((uint32_t *)outdata->dptr)[i*2+2]=node->flags;
		}

		return 0;
	}

	case CTDB_CONTROL_SETVNNMAP: {
		uint32_t *ptr, i;
		
		ptr = (uint32_t *)(&indata.dptr[0]);
		ctdb->vnn_map->generation = ptr[0];
		ctdb->vnn_map->size = ptr[1];
		if (ctdb->vnn_map->map) {
			talloc_free(ctdb->vnn_map->map);
			ctdb->vnn_map->map = NULL;
		}
		ctdb->vnn_map->map = talloc_array(ctdb->vnn_map, uint32_t, ctdb->vnn_map->size);
		if (ctdb->vnn_map->map == NULL) {
			DEBUG(0,(__location__ " Unable to allocate vnn_map->map structure\n"));
			exit(1);
		}
		for (i=0;i<ctdb->vnn_map->size;i++) {
			ctdb->vnn_map->map[i] = ptr[i+2];
		}
		return 0;
	}

	case CTDB_CONTROL_GET_KEYS: {
		uint32_t dbid;
		struct ctdb_db_context *ctdb_db;
		struct tdb_wrap *db;
		struct getkeys_params params;

		dbid = *((uint32_t *)(&indata.dptr[0]));
		ctdb_db = find_ctdb_db(ctdb, dbid);
		if (!ctdb_db) {
			DEBUG(0,(__location__ " Unknown db\n"));
			return -1;
		}

		outdata->dsize = sizeof(uint32_t);
		outdata->dptr = (unsigned char *)talloc_array(outdata, uint32_t, 1);
		*((uint32_t *)(&outdata->dptr[0]))=0;

		db = tdb_wrap_open(NULL, ctdb_db->db_path, 0, TDB_DEFAULT, O_RDONLY, 0);
		if (db == NULL) {
			DEBUG(0,(__location__ " failed to open db\n"));
			return -1;
		}

		params.ctdb_db = ctdb_db;
		params.outdata = outdata;
		tdb_traverse(db->tdb, traverse_getkeys, &params);

		talloc_free(db);

		return 0;
	}

	case CTDB_CONTROL_CONFIG: {
		CHECK_CONTROL_DATA_SIZE(0);
		outdata->dptr = (uint8_t *)ctdb;
		outdata->dsize = sizeof(*ctdb);
		return 0;
	}

	case CTDB_CONTROL_PING:
		CHECK_CONTROL_DATA_SIZE(0);
		return 0;

	case CTDB_CONTROL_GETDBPATH: {
		uint32_t db_id;
		struct ctdb_db_context *ctdb_db;

		CHECK_CONTROL_DATA_SIZE(sizeof(db_id));
		db_id = *(uint32_t *)indata.dptr;
		ctdb_db = find_ctdb_db(ctdb, db_id);
		if (ctdb_db == NULL) return -1;
		outdata->dptr = discard_const(ctdb_db->db_path);
		outdata->dsize = strlen(ctdb_db->db_path)+1;
		return 0;
	}

	default:
		DEBUG(0,(__location__ " Unknown CTDB control opcode %u\n", opcode));
		return -1;
	}
}

/*
  called when a CTDB_REQ_CONTROL packet comes in
*/
void ctdb_request_control(struct ctdb_context *ctdb, struct ctdb_req_header *hdr)
{
	struct ctdb_req_control *c = (struct ctdb_req_control *)hdr;
	TDB_DATA data, *outdata;
	struct ctdb_reply_control *r;
	int32_t status;
	size_t len;

	data.dptr = &c->data[0];
	data.dsize = c->datalen;

	outdata = talloc_zero(c, TDB_DATA);
	status = ctdb_control_dispatch(ctdb, c->opcode, data, outdata);

	len = offsetof(struct ctdb_reply_control, data) + outdata->dsize;
	r = ctdb_transport_allocate(ctdb, ctdb, CTDB_REPLY_CONTROL, len, struct ctdb_reply_control);
	CTDB_NO_MEMORY_VOID(ctdb, r);

	r->hdr.destnode     = hdr->srcnode;
	r->hdr.reqid        = hdr->reqid;
	r->status           = status;
	r->datalen          = outdata->dsize;
	if (outdata->dsize) {
		memcpy(&r->data[0], outdata->dptr, outdata->dsize);
	}
	
	ctdb_queue_packet(ctdb, &r->hdr);	

	talloc_free(r);
}

/*
  called when a CTDB_REPLY_CONTROL packet comes in
*/
void ctdb_reply_control(struct ctdb_context *ctdb, struct ctdb_req_header *hdr)
{
	struct ctdb_reply_control *c = (struct ctdb_reply_control *)hdr;
	TDB_DATA data;
	struct ctdb_control_state *state;

	state = ctdb_reqid_find(ctdb, hdr->reqid, struct ctdb_control_state);
	if (state == NULL) {
		return;
	}

	if (hdr->reqid != state->reqid) {
		/* we found a record  but it was the wrong one */
		DEBUG(0, ("Dropped orphaned control reply with reqid:%d\n", hdr->reqid));
		return;
	}

	data.dptr = &c->data[0];
	data.dsize = c->datalen;

	state->callback(ctdb, c->status, data, state->private_data);
	talloc_free(state);
}

static int ctdb_control_destructor(struct ctdb_control_state *state)
{
	ctdb_reqid_remove(state->ctdb, state->reqid);
	return 0;
}

/*
  send a control message to a node
 */
int ctdb_daemon_send_control(struct ctdb_context *ctdb, uint32_t destnode,
			     uint64_t srvid, uint32_t opcode, TDB_DATA data,
			     ctdb_control_callback_fn_t callback,
			     void *private_data)
{
	struct ctdb_req_control *c;
	struct ctdb_control_state *state;
	size_t len;

	state = talloc(ctdb, struct ctdb_control_state);
	CTDB_NO_MEMORY(ctdb, state);

	state->reqid = ctdb_reqid_new(ctdb, state);
	state->callback = callback;
	state->private_data = private_data;
	state->ctdb = ctdb;

	talloc_set_destructor(state, ctdb_control_destructor);

	len = offsetof(struct ctdb_req_control, data) + data.dsize;
	c = ctdb_transport_allocate(ctdb, state, CTDB_REQ_CONTROL, len, 
				    struct ctdb_req_control);
	CTDB_NO_MEMORY(ctdb, c);
	talloc_set_name_const(c, "ctdb_req_control packet");

	c->hdr.destnode     = destnode;
	c->hdr.reqid        = state->reqid;
	c->opcode           = opcode;
	c->srvid            = srvid;
	c->datalen          = data.dsize;
	if (data.dsize) {
		memcpy(&c->data[0], data.dptr, data.dsize);
	}
	
	ctdb_queue_packet(ctdb, &c->hdr);	

#if CTDB_REQ_TIMEOUT
	event_add_timed(ctdb->ev, state, timeval_current_ofs(CTDB_REQ_TIMEOUT, 0), 
			ctdb_control_timeout, state);
#endif

	talloc_free(c);
	return 0;
}
