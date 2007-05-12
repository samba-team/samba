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

/*
  process a control request
 */
static int32_t ctdb_control_dispatch(struct ctdb_context *ctdb, 
				     struct ctdb_req_control *c,
				     TDB_DATA indata,
				     TDB_DATA *outdata, uint32_t srcnode,
				     bool *async_reply)
{
	uint32_t opcode = c->opcode;
	uint64_t srvid = c->srvid;
	uint32_t client_id = c->client_id;

	switch (opcode) {
	case CTDB_CONTROL_PROCESS_EXISTS: {
		CHECK_CONTROL_DATA_SIZE(sizeof(pid_t));
		ctdb->status.controls.process_exists++;
		return kill(*(pid_t *)indata.dptr, 0);
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
		ctdb->status.controls.status++;
		ctdb->status.memory_used = talloc_total_size(ctdb);
		outdata->dptr = (uint8_t *)&ctdb->status;
		outdata->dsize = sizeof(ctdb->status);
		return 0;
	}

	case CTDB_CONTROL_DUMP_MEMORY: {
		CHECK_CONTROL_DATA_SIZE(0);
		talloc_report_full(ctdb, stdout);
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

	case CTDB_CONTROL_PULL_DB: 
		CHECK_CONTROL_DATA_SIZE(sizeof(struct ctdb_control_pulldb));
		return ctdb_control_pull_db(ctdb, indata, outdata);

	case CTDB_CONTROL_SET_DMASTER: 
		CHECK_CONTROL_DATA_SIZE(sizeof(struct ctdb_control_set_dmaster));
		return ctdb_control_set_dmaster(ctdb, indata);

	case CTDB_CONTROL_CLEAR_DB: 
		CHECK_CONTROL_DATA_SIZE(sizeof(uint32_t));
		return ctdb_control_clear_db(ctdb, indata);

	case CTDB_CONTROL_PUSH_DB:
		return ctdb_control_push_db(ctdb, indata);

	case CTDB_CONTROL_GET_RECMODE: {
		return ctdb->recovery_mode;
	}

	case CTDB_CONTROL_SET_RECMASTER: {
		ctdb->recovery_master = ((uint32_t *)(&indata.dptr[0]))[0];

		return 0;
	}

	case CTDB_CONTROL_GET_RECMASTER: {
		return ctdb->recovery_master;
	}

	case CTDB_CONTROL_GET_PID: {
		return getpid();
	}

	case CTDB_CONTROL_CONFIG: {
		CHECK_CONTROL_DATA_SIZE(0);
		ctdb->status.controls.get_config++;
		outdata->dptr = (uint8_t *)ctdb;
		outdata->dsize = sizeof(*ctdb);
		return 0;
	}

	case CTDB_CONTROL_PING:
		CHECK_CONTROL_DATA_SIZE(0);
		ctdb->status.controls.ping++;
		return ctdb->status.num_clients;

	case CTDB_CONTROL_GET_DBNAME: {
		uint32_t db_id;
		struct ctdb_db_context *ctdb_db;

		CHECK_CONTROL_DATA_SIZE(sizeof(db_id));
		db_id = *(uint32_t *)indata.dptr;
		ctdb_db = find_ctdb_db(ctdb, db_id);
		if (ctdb_db == NULL) return -1;
		outdata->dptr = discard_const(ctdb_db->db_name);
		outdata->dsize = strlen(ctdb_db->db_name)+1;
		return 0;
	}

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
		ctdb->status.controls.attach++;
		return ctdb_control_db_attach(ctdb, indata, outdata);

	case CTDB_CONTROL_SET_CALL: {
		struct ctdb_control_set_call *sc = 
			(struct ctdb_control_set_call *)indata.dptr;
		ctdb->status.controls.set_call++;
		CHECK_CONTROL_DATA_SIZE(sizeof(struct ctdb_control_set_call));
		return ctdb_daemon_set_call(ctdb, sc->db_id, sc->fn, sc->id);
	}

	case CTDB_CONTROL_TRAVERSE_START:
		CHECK_CONTROL_DATA_SIZE(sizeof(struct ctdb_traverse_start));
		ctdb->status.controls.traverse_start++;
		return ctdb_control_traverse_start(ctdb, indata, outdata, srcnode);

	case CTDB_CONTROL_TRAVERSE_ALL:
		ctdb->status.controls.traverse_all++;
		return ctdb_control_traverse_all(ctdb, indata, outdata);

	case CTDB_CONTROL_TRAVERSE_DATA:
		ctdb->status.controls.traverse_data++;
		return ctdb_control_traverse_data(ctdb, indata, outdata);

	case CTDB_CONTROL_REGISTER_SRVID:
		ctdb->status.controls.register_srvid++;
		return daemon_register_message_handler(ctdb, client_id, srvid);

	case CTDB_CONTROL_DEREGISTER_SRVID:
		ctdb->status.controls.deregister_srvid++;
		return daemon_deregister_message_handler(ctdb, client_id, srvid);

	case CTDB_CONTROL_ENABLE_SEQNUM:
		ctdb->status.controls.enable_seqnum++;
		CHECK_CONTROL_DATA_SIZE(sizeof(uint32_t));
		return ctdb_ltdb_enable_seqnum(ctdb, *(uint32_t *)indata.dptr);

	case CTDB_CONTROL_UPDATE_SEQNUM:
		ctdb->status.controls.update_seqnum++;
		CHECK_CONTROL_DATA_SIZE(sizeof(uint32_t));		
		return ctdb_ltdb_update_seqnum(ctdb, *(uint32_t *)indata.dptr, srcnode);

	case CTDB_CONTROL_SET_SEQNUM_FREQUENCY:
		ctdb->status.controls.set_seqnum_frequency++;
		CHECK_CONTROL_DATA_SIZE(sizeof(uint32_t));		
		return ctdb_ltdb_set_seqnum_frequency(ctdb, *(uint32_t *)indata.dptr);

	case CTDB_CONTROL_FREEZE:
		CHECK_CONTROL_DATA_SIZE(0);
		return ctdb_control_freeze(ctdb, c, async_reply);

	case CTDB_CONTROL_THAW:
		CHECK_CONTROL_DATA_SIZE(0);
		return ctdb_control_thaw(ctdb);

	case CTDB_CONTROL_SET_RECMODE:
		CHECK_CONTROL_DATA_SIZE(sizeof(uint32_t));		
		return ctdb_control_set_recmode(ctdb, indata);

	default:
		DEBUG(0,(__location__ " Unknown CTDB control opcode %u\n", opcode));
		return -1;
	}
}


/*
  send a reply for a ctdb control
 */
void ctdb_request_control_reply(struct ctdb_context *ctdb, struct ctdb_req_control *c,
				TDB_DATA *outdata, int32_t status)
{
	struct ctdb_reply_control *r;
	size_t len;

	/* some controls send no reply */
	if (c->flags & CTDB_CTRL_FLAG_NOREPLY) {
		return;
	}

	len = offsetof(struct ctdb_reply_control, data) + (outdata?outdata->dsize:0);
	r = ctdb_transport_allocate(ctdb, ctdb, CTDB_REPLY_CONTROL, len, struct ctdb_reply_control);
	CTDB_NO_MEMORY_VOID(ctdb, r);

	r->hdr.destnode     = c->hdr.srcnode;
	r->hdr.reqid        = c->hdr.reqid;
	r->status           = status;
	r->datalen          = outdata?outdata->dsize:0;
	if (outdata && outdata->dsize) {
		memcpy(&r->data[0], outdata->dptr, outdata->dsize);
	}
	
	ctdb_queue_packet(ctdb, &r->hdr);	

	talloc_free(r);
}

/*
  called when a CTDB_REQ_CONTROL packet comes in
*/
void ctdb_request_control(struct ctdb_context *ctdb, struct ctdb_req_header *hdr)
{
	struct ctdb_req_control *c = (struct ctdb_req_control *)hdr;
	TDB_DATA data, *outdata;
	int32_t status;
	bool async_reply = False;

	data.dptr = &c->data[0];
	data.dsize = c->datalen;

	outdata = talloc_zero(c, TDB_DATA);

	status = ctdb_control_dispatch(ctdb, c, data, outdata, hdr->srcnode, &async_reply);

	if (!async_reply) {
		ctdb_request_control_reply(ctdb, c, outdata, status);
	}
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

	/* make state a child of the packet, so it goes away when the packet
	   is freed. */
	talloc_steal(hdr, state);

	state->callback(ctdb, c->status, data, state->private_data);
}

static int ctdb_control_destructor(struct ctdb_control_state *state)
{
	ctdb_reqid_remove(state->ctdb, state->reqid);
	return 0;
}

/*
  handle a timeout of a control
 */
static void ctdb_control_timeout(struct event_context *ev, struct timed_event *te, 
		       struct timeval t, void *private_data)
{
	struct ctdb_control_state *state = talloc_get_type(private_data, struct ctdb_control_state);
	TALLOC_CTX *tmp_ctx = talloc_new(ev);

	state->ctdb->status.timeouts.control++;

	talloc_steal(tmp_ctx, state);

	state->callback(state->ctdb, -1, tdb_null, state->private_data);
	talloc_free(tmp_ctx);
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

	if (((destnode == CTDB_BROADCAST_VNNMAP) || (destnode == CTDB_BROADCAST_VNNMAP)) && !(flags & CTDB_CTRL_FLAG_NOREPLY)) {
		DEBUG(0,("Attempt to broadcast control without NOREPLY\n"));
		return -1;
	}

	/* the state is made a child of private_data if possible. This means any reply
	   will be discarded if the private_data goes away */
	state = talloc(private_data?private_data:ctdb, struct ctdb_control_state);
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

#if CTDB_CONTROL_TIMEOUT
	event_add_timed(ctdb->ev, state, timeval_current_ofs(CTDB_CONTROL_TIMEOUT, 0), 
			ctdb_control_timeout, state);
#endif

	talloc_free(c);
	return 0;
}
