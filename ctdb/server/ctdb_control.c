/* 
   ctdb_control protocol code

   Copyright (C) Andrew Tridgell  2007

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
#include "system/wait.h"
#include "../include/ctdb_private.h"
#include "lib/util/dlinklist.h"
#include "db_wrap.h"

struct ctdb_control_state {
	struct ctdb_context *ctdb;
	uint32_t reqid;
	ctdb_control_callback_fn_t callback;
	void *private_data;
	unsigned flags;
};

/*
  process a control request
 */
static int32_t ctdb_control_dispatch(struct ctdb_context *ctdb, 
				     struct ctdb_req_control *c,
				     TDB_DATA indata,
				     TDB_DATA *outdata, uint32_t srcnode,
				     const char **errormsg,
				     bool *async_reply)
{
	uint32_t opcode = c->opcode;
	uint64_t srvid = c->srvid;
	uint32_t client_id = c->client_id;

	switch (opcode) {
	case CTDB_CONTROL_PROCESS_EXISTS: {
		CHECK_CONTROL_DATA_SIZE(sizeof(pid_t));
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

	case CTDB_CONTROL_STATISTICS: {
		CHECK_CONTROL_DATA_SIZE(0);
		ctdb->statistics.memory_used = talloc_total_size(ctdb);
		ctdb->statistics.frozen = (ctdb->freeze_mode == CTDB_FREEZE_FROZEN);
		ctdb->statistics.recovering = (ctdb->recovery_mode == CTDB_RECOVERY_ACTIVE);
		outdata->dptr = (uint8_t *)&ctdb->statistics;
		outdata->dsize = sizeof(ctdb->statistics);
		return 0;
	}

	case CTDB_CONTROL_GET_ALL_TUNABLES: {
		CHECK_CONTROL_DATA_SIZE(0);
		outdata->dptr = (uint8_t *)&ctdb->tunable;
		outdata->dsize = sizeof(ctdb->tunable);
		return 0;
	}

	case CTDB_CONTROL_DUMP_MEMORY: {
		CHECK_CONTROL_DATA_SIZE(0);
		talloc_report_full(ctdb, stdout);
		return 0;
	}

	case CTDB_CONTROL_STATISTICS_RESET: {
		CHECK_CONTROL_DATA_SIZE(0);
		ZERO_STRUCT(ctdb->statistics);
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

	case CTDB_CONTROL_PUSH_DB:
		return ctdb_control_push_db(ctdb, indata);

	case CTDB_CONTROL_GET_RECMODE: {
		return ctdb->recovery_mode;
	}

	case CTDB_CONTROL_SET_RECMASTER: {
		CHECK_CONTROL_DATA_SIZE(sizeof(uint32_t));
		if (ctdb->freeze_mode != CTDB_FREEZE_FROZEN) {
			DEBUG(0,("Attempt to set recmaster when not frozen\n"));
			return -1;
		}
		ctdb->recovery_master = ((uint32_t *)(&indata.dptr[0]))[0];
		return 0;
	}

	case CTDB_CONTROL_GET_RECMASTER:
		return ctdb->recovery_master;

	case CTDB_CONTROL_GET_PID:
		return getpid();

	case CTDB_CONTROL_GET_VNN:
		return ctdb->vnn;

	case CTDB_CONTROL_PING:
		CHECK_CONTROL_DATA_SIZE(0);
		return ctdb->statistics.num_clients;

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

	case CTDB_CONTROL_FREEZE:
		CHECK_CONTROL_DATA_SIZE(0);
		return ctdb_control_freeze(ctdb, c, async_reply);

	case CTDB_CONTROL_THAW:
		CHECK_CONTROL_DATA_SIZE(0);
		return ctdb_control_thaw(ctdb);

	case CTDB_CONTROL_SET_RECMODE:
		CHECK_CONTROL_DATA_SIZE(sizeof(uint32_t));		
		return ctdb_control_set_recmode(ctdb, c, indata, async_reply, errormsg);

	case CTDB_CONTROL_SET_MONMODE:
		CHECK_CONTROL_DATA_SIZE(sizeof(uint32_t));		
		ctdb->monitoring_mode = *(uint32_t *)indata.dptr;
		return 0;

	case CTDB_CONTROL_GET_MONMODE: 
		return ctdb->monitoring_mode;

	case CTDB_CONTROL_SHUTDOWN:
		ctdb_release_all_ips(ctdb);
		ctdb->methods->shutdown(ctdb);
		ctdb_event_script(ctdb, "shutdown");
		DEBUG(0,("shutting down\n"));
		exit(0);

	case CTDB_CONTROL_MAX_RSN: 
		CHECK_CONTROL_DATA_SIZE(sizeof(uint32_t));
		return ctdb_control_max_rsn(ctdb, indata, outdata);

	case CTDB_CONTROL_SET_RSN_NONEMPTY: 
		CHECK_CONTROL_DATA_SIZE(sizeof(struct ctdb_control_set_rsn_nonempty));
		return ctdb_control_set_rsn_nonempty(ctdb, indata, outdata);

	case CTDB_CONTROL_TAKEOVER_IP:
		CHECK_CONTROL_DATA_SIZE(sizeof(struct ctdb_public_ip));
		return ctdb_control_takeover_ip(ctdb, c, indata, async_reply);

	case CTDB_CONTROL_RELEASE_IP:
		CHECK_CONTROL_DATA_SIZE(sizeof(struct ctdb_public_ip));
		return ctdb_control_release_ip(ctdb, c, indata, async_reply);

	case CTDB_CONTROL_GET_PUBLIC_IPS:
		CHECK_CONTROL_DATA_SIZE(0);
		return ctdb_control_get_public_ips(ctdb, c, outdata);

	case CTDB_CONTROL_DELETE_LOW_RSN: 
		CHECK_CONTROL_DATA_SIZE(sizeof(struct ctdb_control_delete_low_rsn));
		return ctdb_control_delete_low_rsn(ctdb, indata, outdata);

	case CTDB_CONTROL_TCP_CLIENT: 
		CHECK_CONTROL_DATA_SIZE(sizeof(struct ctdb_control_tcp));
		return ctdb_control_tcp_client(ctdb, client_id, srcnode, indata);

	case CTDB_CONTROL_STARTUP: 
		CHECK_CONTROL_DATA_SIZE(0);
		return ctdb_control_startup(ctdb, srcnode);

	case CTDB_CONTROL_TCP_ADD: 
		CHECK_CONTROL_DATA_SIZE(sizeof(struct ctdb_control_tcp_vnn));
		return ctdb_control_tcp_add(ctdb, indata);

	case CTDB_CONTROL_TCP_REMOVE: 
		CHECK_CONTROL_DATA_SIZE(sizeof(struct ctdb_control_tcp_vnn));
		return ctdb_control_tcp_remove(ctdb, indata);

	case CTDB_CONTROL_SET_TUNABLE:
		return ctdb_control_set_tunable(ctdb, indata);

	case CTDB_CONTROL_GET_TUNABLE:
		return ctdb_control_get_tunable(ctdb, indata, outdata);

	case CTDB_CONTROL_LIST_TUNABLES:
		return ctdb_control_list_tunables(ctdb, outdata);

	case CTDB_CONTROL_MODIFY_FLAGS:
		CHECK_CONTROL_DATA_SIZE(sizeof(struct ctdb_node_modflags));
		return ctdb_control_modflags(ctdb, indata);

	default:
		DEBUG(0,(__location__ " Unknown CTDB control opcode %u\n", opcode));
		return -1;
	}
}


/*
  send a reply for a ctdb control
 */
void ctdb_request_control_reply(struct ctdb_context *ctdb, struct ctdb_req_control *c,
				TDB_DATA *outdata, int32_t status, const char *errormsg)
{
	struct ctdb_reply_control *r;
	size_t len;
	
	/* some controls send no reply */
	if (c->flags & CTDB_CTRL_FLAG_NOREPLY) {
		return;
	}

	len = offsetof(struct ctdb_reply_control, data) + (outdata?outdata->dsize:0);
	if (errormsg) {
		len += strlen(errormsg);
	}
	r = ctdb_transport_allocate(ctdb, ctdb, CTDB_REPLY_CONTROL, len, struct ctdb_reply_control);
	CTDB_NO_MEMORY_VOID(ctdb, r);

	r->hdr.destnode     = c->hdr.srcnode;
	r->hdr.reqid        = c->hdr.reqid;
	r->status           = status;
	r->datalen          = outdata?outdata->dsize:0;
	if (outdata && outdata->dsize) {
		memcpy(&r->data[0], outdata->dptr, outdata->dsize);
	}
	if (errormsg) {
		r->errorlen = strlen(errormsg);
		memcpy(&r->data[r->datalen], errormsg, r->errorlen);
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
	const char *errormsg = NULL;

	data.dptr = &c->data[0];
	data.dsize = c->datalen;

	outdata = talloc_zero(c, TDB_DATA);

	status = ctdb_control_dispatch(ctdb, c, data, outdata, hdr->srcnode, 
				       &errormsg, &async_reply);

	if (!async_reply) {
		ctdb_request_control_reply(ctdb, c, outdata, status, errormsg);
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
	const char *errormsg = NULL;

	state = ctdb_reqid_find(ctdb, hdr->reqid, struct ctdb_control_state);
	if (state == NULL) {
		DEBUG(0,("vnn %u Invalid reqid %u in ctdb_reply_control\n",
			 ctdb->vnn, hdr->reqid));
		return;
	}

	if (hdr->reqid != state->reqid) {
		/* we found a record  but it was the wrong one */
		DEBUG(0, ("Dropped orphaned control reply with reqid:%u\n", hdr->reqid));
		return;
	}

	data.dptr = &c->data[0];
	data.dsize = c->datalen;
	if (c->errorlen) {
		errormsg = talloc_strndup(state, 
					  (char *)&c->data[c->datalen], c->errorlen);
	}

	/* make state a child of the packet, so it goes away when the packet
	   is freed. */
	talloc_steal(hdr, state);

	state->callback(ctdb, c->status, data, errormsg, state->private_data);
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

	state->ctdb->statistics.timeouts.control++;

	talloc_steal(tmp_ctx, state);

	state->callback(state->ctdb, -1, tdb_null,
			"ctdb_control timed out", 
			state->private_data);
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

	if (((destnode == CTDB_BROADCAST_VNNMAP) || 
	     (destnode == CTDB_BROADCAST_ALL) ||
	     (destnode == CTDB_BROADCAST_CONNECTED)) && 
	    !(flags & CTDB_CTRL_FLAG_NOREPLY)) {
		DEBUG(0,("Attempt to broadcast control without NOREPLY\n"));
		return -1;
	}

	if (destnode != CTDB_BROADCAST_VNNMAP && 
	    destnode != CTDB_BROADCAST_ALL && 
	    destnode != CTDB_BROADCAST_CONNECTED && 
	    (!ctdb_validate_vnn(ctdb, destnode) || 
	     (ctdb->nodes[destnode]->flags & NODE_FLAGS_DISCONNECTED))) {
		if (!(flags & CTDB_CTRL_FLAG_NOREPLY)) {
			callback(ctdb, -1, tdb_null, "ctdb_control to disconnected node", private_data);
		}
		return 0;
	}

	/* the state is made a child of private_data if possible. This means any reply
	   will be discarded if the private_data goes away */
	state = talloc(private_data?private_data:ctdb, struct ctdb_control_state);
	CTDB_NO_MEMORY(ctdb, state);

	state->reqid = ctdb_reqid_new(ctdb, state);
	state->callback = callback;
	state->private_data = private_data;
	state->ctdb = ctdb;
	state->flags = flags;

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

	if (ctdb->tunable.control_timeout) {
		event_add_timed(ctdb->ev, state, 
				timeval_current_ofs(ctdb->tunable.control_timeout, 0), 
				ctdb_control_timeout, state);
	}

	talloc_free(c);
	return 0;
}
