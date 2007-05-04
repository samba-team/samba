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

static int traverse_cleardb(struct tdb_context *tdb, TDB_DATA key, TDB_DATA data, void *p)
{
	int ret;


	ret = tdb_delete(tdb, key);
	if (ret) {
		DEBUG(0,(__location__ "failed to delete tdb record\n"));
		return ret;
	}
	return 0;
}

static int traverse_setdmaster(struct tdb_context *tdb, TDB_DATA key, TDB_DATA data, void *p)
{
	uint32_t *dmaster = (uint32_t *)p;
	struct ctdb_ltdb_header *header = (struct ctdb_ltdb_header *)data.dptr;
	int ret;

	header->dmaster = *dmaster;

	ret = tdb_store(tdb, key, data, TDB_REPLACE);
	if (ret) {
		DEBUG(0,(__location__ "failed to write tdb data back  ret:%d\n",ret));
		return ret;
	}
	return 0;
}

struct getkeys_params {
	struct ctdb_db_context *ctdb_db;
	TDB_DATA *outdata;
	uint32_t lmaster;
};

static int traverse_getkeys(struct tdb_context *tdb, TDB_DATA key, TDB_DATA data, void *p)
{
	struct getkeys_params *params = (struct getkeys_params *)p;
	TDB_DATA *outdata = talloc_get_type(params->outdata, TDB_DATA);
	struct ctdb_db_context *ctdb_db = talloc_get_type(params->ctdb_db, struct ctdb_db_context);
	unsigned char *ptr;
	int len;
	uint32_t lmaster;

	lmaster = ctdb_lmaster(ctdb_db->ctdb, &key);

	/* only include this record if the lmaster matches or if
	   the wildcard lmaster (-1) was specified.
	*/
	if((params->lmaster!=CTDB_LMASTER_ANY)
	&& (params->lmaster!=lmaster) ){
		return 0;
	}

	len=outdata->dsize;
	len+=4; /*lmaster*/
	len+=4; /*key len*/
	len+=4; /*data len */
	len+=key.dsize;
	len=(len+CTDB_DS_ALIGNMENT-1)& ~(CTDB_DS_ALIGNMENT-1);
	len+=sizeof(struct ctdb_ltdb_header);
	len=(len+CTDB_DS_ALIGNMENT-1)& ~(CTDB_DS_ALIGNMENT-1);
	len+=(data.dsize-sizeof(struct ctdb_ltdb_header));
	len=(len+CTDB_DS_ALIGNMENT-1)& ~(CTDB_DS_ALIGNMENT-1);

	ptr=outdata->dptr=talloc_realloc_size(outdata, outdata->dptr, len);
	ptr+=outdata->dsize;
	outdata->dsize=len;
	/* number of records is stored as the second 4 bytes */
	((uint32_t *)(&outdata->dptr[0]))[1]++;

	*((uint32_t *)ptr)=lmaster;
	ptr+=4;
	*((uint32_t *)ptr)=key.dsize;
	ptr+=4;
	*((uint32_t *)ptr)=data.dsize-sizeof(struct ctdb_ltdb_header);
	ptr+=4;

	ptr = outdata->dptr+(((ptr-outdata->dptr)+CTDB_DS_ALIGNMENT-1)& ~(CTDB_DS_ALIGNMENT-1));
	memcpy(ptr, key.dptr, key.dsize);
	ptr += key.dsize;

	ptr = outdata->dptr+(((ptr-outdata->dptr)+CTDB_DS_ALIGNMENT-1)& ~(CTDB_DS_ALIGNMENT-1));
	memcpy(ptr, data.dptr, sizeof(struct ctdb_ltdb_header));
	ptr += sizeof(struct ctdb_ltdb_header);

	ptr = outdata->dptr+(((ptr-outdata->dptr)+CTDB_DS_ALIGNMENT-1)& ~(CTDB_DS_ALIGNMENT-1));
	memcpy(ptr, data.dptr+sizeof(struct ctdb_ltdb_header), data.dsize-sizeof(struct ctdb_ltdb_header));

	return 0;
}

/*
  process a control request
 */
static int32_t ctdb_control_dispatch(struct ctdb_context *ctdb, 
				     uint32_t opcode, 
				     uint64_t srvid, uint32_t client_id,
				     TDB_DATA indata,
				     TDB_DATA *outdata, uint32_t srcnode)
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

	case CTDB_CONTROL_STATUS_RESET: {
		CHECK_CONTROL_DATA_SIZE(0);
		ZERO_STRUCT(ctdb->status);
		return 0;
	}

	case CTDB_CONTROL_GETVNNMAP:
		return ctdb_control_getvnnmap(ctdb, opcode, indata, outdata);

	case CTDB_CONTROL_GET_DBMAP:
		return ctdb_control_getdbmap(ctdb, opcode, indata, outdata);

	case CTDB_CONTROL_GET_NODEMAP:
		return ctdb_control_getnodemap(ctdb, opcode, indata, outdata);

	case CTDB_CONTROL_SETVNNMAP:
		return ctdb_control_setvnnmap(ctdb, opcode, indata, outdata);

	case CTDB_CONTROL_PULL_DB: {
		uint32_t dbid, lmaster;
		struct ctdb_db_context *ctdb_db;
		struct getkeys_params params;

		dbid = ((uint32_t *)(&indata.dptr[0]))[0];
		ctdb_db = find_ctdb_db(ctdb, dbid);
		if (!ctdb_db) {
			DEBUG(0,(__location__ " Unknown db\n"));
			return -1;
		}

		lmaster = ((uint32_t *)(&indata.dptr[0]))[1];

		outdata->dsize = 2* sizeof(uint32_t);
		outdata->dptr = (unsigned char *)talloc_array(outdata, uint32_t, 2);
		((uint32_t *)(&outdata->dptr[0]))[0]=dbid;
		((uint32_t *)(&outdata->dptr[0]))[1]=0;

		params.ctdb_db = ctdb_db;
		params.outdata = outdata;
		params.lmaster = lmaster;
		tdb_traverse_read(ctdb_db->ltdb->tdb, traverse_getkeys, &params);


		return 0;
	}

	case CTDB_CONTROL_SET_DMASTER: {
		uint32_t dbid, dmaster;
		struct ctdb_db_context *ctdb_db;

		dbid = ((uint32_t *)(&indata.dptr[0]))[0];
		ctdb_db = find_ctdb_db(ctdb, dbid);
		if (!ctdb_db) {
			DEBUG(0,(__location__ " Unknown db 0x%08x\n",dbid));
			return -1;
		}

		dmaster = ((uint32_t *)(&indata.dptr[0]))[1];

		outdata->dsize = 0;
		outdata->dptr = NULL;

		tdb_traverse(ctdb_db->ltdb->tdb, traverse_setdmaster, &dmaster);

		return 0;
	}

	case CTDB_CONTROL_CLEAR_DB: {
		uint32_t dbid;
		struct ctdb_db_context *ctdb_db;

		dbid = ((uint32_t *)(&indata.dptr[0]))[0];
		ctdb_db = find_ctdb_db(ctdb, dbid);
		if (!ctdb_db) {
			DEBUG(0,(__location__ " Unknown db 0x%08x\n",dbid));
			return -1;
		}

		outdata->dsize = 0;
		outdata->dptr = NULL;

		tdb_traverse(ctdb_db->ltdb->tdb, traverse_cleardb, NULL);

		return 0;
	}

	case CTDB_CONTROL_PUSH_DB: {
		uint32_t dbid, num;
		struct ctdb_db_context *ctdb_db;
		unsigned char *ptr;
		int i, ret;
		TDB_DATA key, data;
		struct ctdb_ltdb_header *hdr, header;

		outdata->dsize = 0;
		outdata->dptr = NULL;

		dbid = ((uint32_t *)(&indata.dptr[0]))[0];
		ctdb_db = find_ctdb_db(ctdb, dbid);
		if (!ctdb_db) {
			DEBUG(0,(__location__ " Unknown db 0x%08x\n",dbid));
			return -1;
		}

		num = ((uint32_t *)(&indata.dptr[0]))[1];

		ptr=&indata.dptr[8];
		for(i=0;i<num;i++){
			/* skip the lmaster*/
			ptr += 4;

			/* keylength  */
			key.dsize = *((uint32_t *)ptr);
			ptr += 4;

			/* data length */
			data.dsize = *((uint32_t *)ptr);
			ptr += 4;

			/* key */
			ptr = indata.dptr+(((ptr-indata.dptr)+CTDB_DS_ALIGNMENT-1)& ~(CTDB_DS_ALIGNMENT-1));
			key.dptr = ptr;
			ptr += key.dsize;
			
			/* header */
			ptr = indata.dptr+(((ptr-indata.dptr)+CTDB_DS_ALIGNMENT-1)& ~(CTDB_DS_ALIGNMENT-1));
			hdr = (struct ctdb_ltdb_header *)ptr;
			ptr += sizeof(struct ctdb_ltdb_header);
			
			/* data */
			ptr = indata.dptr+(((ptr-indata.dptr)+CTDB_DS_ALIGNMENT-1)& ~(CTDB_DS_ALIGNMENT-1));
			data.dptr=ptr;
			ptr += data.dsize;

			ptr = indata.dptr+(((ptr-indata.dptr)+CTDB_DS_ALIGNMENT-1)& ~(CTDB_DS_ALIGNMENT-1));

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
			if (header.rsn < hdr->rsn) {
				ret = ctdb_ltdb_store(ctdb_db, key, hdr, data);
				if (ret != 0) {
					DEBUG(0, (__location__ "Unable to store record\n"));
					ctdb_ltdb_unlock(ctdb_db, key);
					return -1;
				}
			}
			ctdb_ltdb_unlock(ctdb_db, key);
		}

		return 0;
	}

	case CTDB_CONTROL_WRITE_RECORD:
		return ctdb_control_writerecord(ctdb, opcode, indata, outdata);

	case CTDB_CONTROL_SET_RECMODE: {
		ctdb->recovery_mode = ((uint32_t *)(&indata.dptr[0]))[0];

		return 0;
	}

	case CTDB_CONTROL_GET_RECMODE: {
		outdata->dsize = sizeof(uint32_t);
		outdata->dptr = (unsigned char *)talloc_array(outdata, uint32_t, 1);
		*((uint32_t *)(&outdata->dptr[0])) = ctdb->recovery_mode;

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
		return ctdb->num_clients;

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

	case CTDB_CONTROL_DB_ATTACH:
		return ctdb_control_db_attach(ctdb, indata, outdata);

	case CTDB_CONTROL_SET_CALL: {
		struct ctdb_control_set_call *sc = 
			(struct ctdb_control_set_call *)indata.dptr;
		CHECK_CONTROL_DATA_SIZE(sizeof(struct ctdb_control_set_call));
		return ctdb_daemon_set_call(ctdb, sc->db_id, sc->fn, sc->id);
	}

	case CTDB_CONTROL_TRAVERSE_START:
		CHECK_CONTROL_DATA_SIZE(sizeof(struct ctdb_traverse_start));
		return ctdb_control_traverse_start(ctdb, indata, outdata, srcnode);

	case CTDB_CONTROL_TRAVERSE_ALL:
		return ctdb_control_traverse_all(ctdb, indata, outdata);

	case CTDB_CONTROL_TRAVERSE_DATA:
		return ctdb_control_traverse_data(ctdb, indata, outdata);

	case CTDB_CONTROL_REGISTER_SRVID:
		return daemon_register_message_handler(ctdb, client_id, srvid);

	case CTDB_CONTROL_DEREGISTER_SRVID:
		return daemon_deregister_message_handler(ctdb, client_id, srvid);

	case CTDB_CONTROL_ENABLE_SEQNUM:
		CHECK_CONTROL_DATA_SIZE(sizeof(uint32_t));
		return ctdb_ltdb_enable_seqnum(ctdb, *(uint32_t *)indata.dptr);

	case CTDB_CONTROL_UPDATE_SEQNUM:
		CHECK_CONTROL_DATA_SIZE(sizeof(uint32_t));		
		return ctdb_ltdb_update_seqnum(ctdb, *(uint32_t *)indata.dptr, srcnode);

	case CTDB_CONTROL_SET_SEQNUM_FREQUENCY:
		CHECK_CONTROL_DATA_SIZE(sizeof(uint32_t));		
		return ctdb_ltdb_set_seqnum_frequency(ctdb, *(uint32_t *)indata.dptr);

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
	status = ctdb_control_dispatch(ctdb, c->opcode, c->srvid, c->client_id,
				       data, outdata, hdr->srcnode);

	/* some controls send no reply */
	if (c->flags & CTDB_CTRL_FLAG_NOREPLY) {
		return;
	}

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
		DEBUG(0,("vnn %u Invalid reqid %u in ctdb_reply_control\n",
			 ctdb->vnn, hdr->reqid));
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
			     uint64_t srvid, uint32_t opcode, uint32_t client_id,
			     uint32_t flags,
			     TDB_DATA data,
			     ctdb_control_callback_fn_t callback,
			     void *private_data)
{
	struct ctdb_req_control *c;
	struct ctdb_control_state *state;
	size_t len;

	if (destnode == CTDB_BROADCAST_VNN && !(flags & CTDB_CTRL_FLAG_NOREPLY)) {
		DEBUG(0,("Attempt to broadcast control without NOREPLY\n"));
		return -1;
	}

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
	c->client_id        = client_id;
	c->flags            = flags;
	c->srvid            = srvid;
	c->datalen          = data.dsize;
	if (data.dsize) {
		memcpy(&c->data[0], data.dptr, data.dsize);
	}

	ctdb_queue_packet(ctdb, &c->hdr);	

	if (flags & CTDB_CTRL_FLAG_NOREPLY) {
		talloc_free(state);
		return 0;
	}

#if CTDB_REQ_TIMEOUT
	event_add_timed(ctdb->ev, state, timeval_current_ofs(CTDB_REQ_TIMEOUT, 0), 
			ctdb_control_timeout, state);
#endif

	talloc_free(c);
	return 0;
}
