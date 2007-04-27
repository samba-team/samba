/* 
   ctdb daemon code

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
#include "db_wrap.h"
#include "lib/tdb/include/tdb.h"
#include "lib/events/events.h"
#include "lib/util/dlinklist.h"
#include "system/network.h"
#include "system/filesys.h"
#include "../include/ctdb.h"
#include "../include/ctdb_private.h"

/*
  queue a packet for sending from client to daemon
*/
static int ctdb_client_queue_pkt(struct ctdb_context *ctdb, struct ctdb_req_header *hdr)
{
	return ctdb_queue_send(ctdb->daemon.queue, (uint8_t *)hdr, hdr->length);
}


/*
  handle a connect wait reply packet
 */
static void ctdb_reply_connect_wait(struct ctdb_context *ctdb, 
				    struct ctdb_req_header *hdr)
{
	struct ctdb_reply_connect_wait *r = (struct ctdb_reply_connect_wait *)hdr;
	ctdb->vnn = r->vnn;
	ctdb->num_connected = r->num_connected;
}

/*
  state of a in-progress ctdb call in client
*/
struct ctdb_client_call_state {
	enum call_state state;
	uint32_t reqid;
	struct ctdb_db_context *ctdb_db;
	struct ctdb_call call;
};

/*
  called when a CTDB_REPLY_CALL packet comes in in the client

  This packet comes in response to a CTDB_REQ_CALL request packet. It
  contains any reply data from the call
*/
static void ctdb_client_reply_call(struct ctdb_context *ctdb, struct ctdb_req_header *hdr)
{
	struct ctdb_reply_call *c = (struct ctdb_reply_call *)hdr;
	struct ctdb_client_call_state *state;

	state = ctdb_reqid_find(ctdb, hdr->reqid, struct ctdb_client_call_state);
	if (state == NULL) {
		DEBUG(0,(__location__ " reqid %d not found\n", hdr->reqid));
		return;
	}

	if (hdr->reqid != state->reqid) {
		/* we found a record  but it was the wrong one */
		DEBUG(0, ("Dropped orphaned reply with reqid:%d\n",hdr->reqid));
		return;
	}

	state->call.reply_data.dptr = c->data;
	state->call.reply_data.dsize = c->datalen;
	state->call.status = c->status;

	talloc_steal(state, c);

	state->state = CTDB_CALL_DONE;
}

static void ctdb_client_reply_control(struct ctdb_context *ctdb, struct ctdb_req_header *hdr);

/*
  this is called in the client, when data comes in from the daemon
 */
static void ctdb_client_read_cb(uint8_t *data, size_t cnt, void *args)
{
	struct ctdb_context *ctdb = talloc_get_type(args, struct ctdb_context);
	struct ctdb_req_header *hdr = (struct ctdb_req_header *)data;
	TALLOC_CTX *tmp_ctx;

	/* place the packet as a child of a tmp_ctx. We then use
	   talloc_free() below to free it. If any of the calls want
	   to keep it, then they will steal it somewhere else, and the
	   talloc_free() will be a no-op */
	tmp_ctx = talloc_new(ctdb);
	talloc_steal(tmp_ctx, hdr);

	if (cnt == 0) {
		DEBUG(2,("Daemon has exited - shutting down client\n"));
		exit(0);
	}

	if (cnt < sizeof(*hdr)) {
		DEBUG(0,("Bad packet length %d in client\n", cnt));
		goto done;
	}
	if (cnt != hdr->length) {
		ctdb_set_error(ctdb, "Bad header length %d expected %d in client\n", 
			       hdr->length, cnt);
		goto done;
	}

	if (hdr->ctdb_magic != CTDB_MAGIC) {
		ctdb_set_error(ctdb, "Non CTDB packet rejected in client\n");
		goto done;
	}

	if (hdr->ctdb_version != CTDB_VERSION) {
		ctdb_set_error(ctdb, "Bad CTDB version 0x%x rejected in client\n", hdr->ctdb_version);
		goto done;
	}

	switch (hdr->operation) {
	case CTDB_REPLY_CALL:
		ctdb_client_reply_call(ctdb, hdr);
		break;

	case CTDB_REQ_MESSAGE:
		ctdb_request_message(ctdb, hdr);
		break;

	case CTDB_REPLY_CONNECT_WAIT:
		ctdb_reply_connect_wait(ctdb, hdr);
		break;

	case CTDB_REPLY_CONTROL:
		ctdb_client_reply_control(ctdb, hdr);
		break;

	default:
		DEBUG(0,("bogus operation code:%d\n",hdr->operation));
	}

done:
	talloc_free(tmp_ctx);
}

/*
  connect to a unix domain socket
*/
int ctdb_socket_connect(struct ctdb_context *ctdb)
{
	struct sockaddr_un addr;

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, ctdb->daemon.name, sizeof(addr.sun_path));

	ctdb->daemon.sd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (ctdb->daemon.sd == -1) {
		return -1;
	}
	
	if (connect(ctdb->daemon.sd, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
		close(ctdb->daemon.sd);
		ctdb->daemon.sd = -1;
		return -1;
	}

	ctdb->daemon.queue = ctdb_queue_setup(ctdb, ctdb, ctdb->daemon.sd, 
					      CTDB_DS_ALIGNMENT, 
					      ctdb_client_read_cb, ctdb);
	return 0;
}


struct ctdb_record_handle {
	struct ctdb_db_context *ctdb_db;
	TDB_DATA key;
	TDB_DATA *data;
	struct ctdb_ltdb_header header;
};


/*
  make a recv call to the local ctdb daemon - called from client context

  This is called when the program wants to wait for a ctdb_call to complete and get the 
  results. This call will block unless the call has already completed.
*/
int ctdb_call_recv(struct ctdb_client_call_state *state, struct ctdb_call *call)
{
	while (state->state < CTDB_CALL_DONE) {
		event_loop_once(state->ctdb_db->ctdb->ev);
	}
	if (state->state != CTDB_CALL_DONE) {
		DEBUG(0,(__location__ " ctdb_call_recv failed\n"));
		talloc_free(state);
		return -1;
	}

	if (state->call.reply_data.dsize) {
		call->reply_data.dptr = talloc_memdup(state->ctdb_db,
						      state->call.reply_data.dptr,
						      state->call.reply_data.dsize);
		call->reply_data.dsize = state->call.reply_data.dsize;
	} else {
		call->reply_data.dptr = NULL;
		call->reply_data.dsize = 0;
	}
	call->status = state->call.status;
	talloc_free(state);

	return 0;
}




/*
  destroy a ctdb_call in client
*/
static int ctdb_client_call_destructor(struct ctdb_client_call_state *state)	
{
	ctdb_reqid_remove(state->ctdb_db->ctdb, state->reqid);
	return 0;
}

/*
  construct an event driven local ctdb_call

  this is used so that locally processed ctdb_call requests are processed
  in an event driven manner
*/
static struct ctdb_client_call_state *ctdb_client_call_local_send(struct ctdb_db_context *ctdb_db, 
								  struct ctdb_call *call,
								  struct ctdb_ltdb_header *header,
								  TDB_DATA *data)
{
	struct ctdb_client_call_state *state;
	struct ctdb_context *ctdb = ctdb_db->ctdb;
	int ret;

	state = talloc_zero(ctdb_db, struct ctdb_client_call_state);
	CTDB_NO_MEMORY_NULL(ctdb, state);

	talloc_steal(state, data->dptr);

	state->state = CTDB_CALL_DONE;
	state->call = *call;
	state->ctdb_db = ctdb_db;

	ret = ctdb_call_local(ctdb_db, &state->call, header, data, ctdb->vnn);
	talloc_steal(state, state->call.reply_data.dptr);

	return state;
}

/*
  make a ctdb call to the local daemon - async send. Called from client context.

  This constructs a ctdb_call request and queues it for processing. 
  This call never blocks.
*/
struct ctdb_client_call_state *ctdb_call_send(struct ctdb_db_context *ctdb_db, 
				       struct ctdb_call *call)
{
	struct ctdb_client_call_state *state;
	struct ctdb_context *ctdb = ctdb_db->ctdb;
	struct ctdb_ltdb_header header;
	TDB_DATA data;
	int ret;
	size_t len;
	struct ctdb_req_call *c;

	/* if the domain socket is not yet open, open it */
	if (ctdb->daemon.sd==-1) {
		ctdb_socket_connect(ctdb);
	}

	ret = ctdb_ltdb_lock(ctdb_db, call->key);
	if (ret != 0) {
		DEBUG(0,(__location__ " Failed to get chainlock\n"));
		return NULL;
	}

	ret = ctdb_ltdb_fetch(ctdb_db, call->key, &header, ctdb_db, &data);
	if (ret != 0) {
		ctdb_ltdb_unlock(ctdb_db, call->key);
		DEBUG(0,(__location__ " Failed to fetch record\n"));
		return NULL;
	}

	if (header.dmaster == ctdb->vnn && !(ctdb->flags & CTDB_FLAG_SELF_CONNECT)) {
		state = ctdb_client_call_local_send(ctdb_db, call, &header, &data);
		talloc_free(data.dptr);
		ctdb_ltdb_unlock(ctdb_db, call->key);
		return state;
	}

	ctdb_ltdb_unlock(ctdb_db, call->key);
	talloc_free(data.dptr);

	state = talloc_zero(ctdb_db, struct ctdb_client_call_state);
	if (state == NULL) {
		DEBUG(0, (__location__ " failed to allocate state\n"));
		return NULL;
	}

	len = offsetof(struct ctdb_req_call, data) + call->key.dsize + call->call_data.dsize;
	c = ctdbd_allocate_pkt(state, len);
	if (c == NULL) {
		DEBUG(0, (__location__ " failed to allocate packet\n"));
		return NULL;
	}
	talloc_set_name_const(c, "ctdb client req_call packet");
	memset(c, 0, offsetof(struct ctdb_req_call, data));

	c->hdr.length    = len;
	c->hdr.ctdb_magic = CTDB_MAGIC;
	c->hdr.ctdb_version = CTDB_VERSION;
	c->hdr.operation = CTDB_REQ_CALL;
	/* this limits us to 16k outstanding messages - not unreasonable */
	c->hdr.reqid     = ctdb_reqid_new(ctdb, state);
	c->flags         = call->flags;
	c->db_id         = ctdb_db->db_id;
	c->callid        = call->call_id;
	c->keylen        = call->key.dsize;
	c->calldatalen   = call->call_data.dsize;
	memcpy(&c->data[0], call->key.dptr, call->key.dsize);
	memcpy(&c->data[call->key.dsize], 
	       call->call_data.dptr, call->call_data.dsize);
	state->call                = *call;
	state->call.call_data.dptr = &c->data[call->key.dsize];
	state->call.key.dptr       = &c->data[0];

	state->state  = CTDB_CALL_WAIT;
	state->ctdb_db = ctdb_db;
	state->reqid = c->hdr.reqid;

	talloc_set_destructor(state, ctdb_client_call_destructor);

	ctdb_client_queue_pkt(ctdb, &c->hdr);

	return state;
}


/*
  full ctdb_call. Equivalent to a ctdb_call_send() followed by a ctdb_call_recv()
*/
int ctdb_call(struct ctdb_db_context *ctdb_db, struct ctdb_call *call)
{
	struct ctdb_client_call_state *state;

	state = ctdb_call_send(ctdb_db, call);
	return ctdb_call_recv(state, call);
}


/*
  tell the daemon what messaging srvid we will use, and register the message
  handler function in the client
*/
int ctdb_set_message_handler(struct ctdb_context *ctdb, uint64_t srvid, 
			     ctdb_message_fn_t handler,
			     void *private_data)
				    
{
	struct ctdb_req_register *c;
	int res;

	/* if the domain socket is not yet open, open it */
	if (ctdb->daemon.sd==-1) {
		ctdb_socket_connect(ctdb);
	}

	c = ctdbd_allocate_pkt(ctdb, sizeof(*c));
	c->hdr.length       = sizeof(*c);
	c->hdr.ctdb_magic   = CTDB_MAGIC;
	c->hdr.ctdb_version = CTDB_VERSION;
	c->hdr.operation    = CTDB_REQ_REGISTER;
	c->srvid            = srvid;

	res = ctdb_client_queue_pkt(ctdb, &c->hdr);
	talloc_free(c);
	if (res != 0) {
		return res;
	}

	/* also need to register the handler with our ctdb structure */
	return ctdb_register_message_handler(ctdb, ctdb, srvid, handler, private_data);
}


/*
  send a message - from client context
 */
int ctdb_send_message(struct ctdb_context *ctdb, uint32_t vnn,
		      uint64_t srvid, TDB_DATA data)
{
	struct ctdb_req_message *r;
	int len, res;

	len = offsetof(struct ctdb_req_message, data) + data.dsize;
	r = ctdbd_allocate_pkt(ctdb, len);
	CTDB_NO_MEMORY(ctdb, r);
	talloc_set_name_const(r, "req_message packet");

	r->hdr.length    = len;
	r->hdr.ctdb_magic = CTDB_MAGIC;
	r->hdr.ctdb_version = CTDB_VERSION;
	r->hdr.operation = CTDB_REQ_MESSAGE;
	r->hdr.destnode  = vnn;
	r->hdr.srcnode   = ctdb->vnn;
	r->hdr.reqid     = 0;
	r->srvid         = srvid;
	r->datalen       = data.dsize;
	memcpy(&r->data[0], data.dptr, data.dsize);
	
	res = ctdb_client_queue_pkt(ctdb, &r->hdr);
	if (res != 0) {
		return res;
	}

	talloc_free(r);
	return 0;
}

/*
  wait for all nodes to be connected - from client
 */
void ctdb_connect_wait(struct ctdb_context *ctdb)
{
	struct ctdb_req_connect_wait *r;
	int res;

	r = ctdbd_allocate_pkt(ctdb, sizeof(*r));
	r->hdr.length     = sizeof(*r);
	r->hdr.ctdb_magic = CTDB_MAGIC;
	r->hdr.ctdb_version = CTDB_VERSION;
	r->hdr.operation = CTDB_REQ_CONNECT_WAIT;

	DEBUG(3,("ctdb_connect_wait: sending to ctdbd\n"));

	/* if the domain socket is not yet open, open it */
	if (ctdb->daemon.sd==-1) {
		ctdb_socket_connect(ctdb);
	}
	
	res = ctdb_queue_send(ctdb->daemon.queue, (uint8_t *)&r->hdr, r->hdr.length);
	talloc_free(r);
	if (res != 0) {
		DEBUG(0,(__location__ " Failed to queue a connect wait request\n"));
		return;
	}

	DEBUG(3,("ctdb_connect_wait: waiting\n"));

	/* now we can go into the normal wait routine, as the reply packet
	   will update the ctdb->num_connected variable */
	ctdb_daemon_connect_wait(ctdb);

	/* get other config variables */
	ctdb_get_config(ctdb);
}

/*
  cancel a ctdb_fetch_lock operation, releasing the lock
 */
static int fetch_lock_destructor(struct ctdb_record_handle *h)
{
	ctdb_ltdb_unlock(h->ctdb_db, h->key);
	return 0;
}

/*
  force the migration of a record to this node
 */
static int ctdb_client_force_migration(struct ctdb_db_context *ctdb_db, TDB_DATA key)
{
	struct ctdb_call call;
	ZERO_STRUCT(call);
	call.call_id = CTDB_NULL_FUNC;
	call.key = key;
	call.flags = CTDB_IMMEDIATE_MIGRATION;
	return ctdb_call(ctdb_db, &call);
}

/*
  get a lock on a record, and return the records data. Blocks until it gets the lock
 */
struct ctdb_record_handle *ctdb_fetch_lock(struct ctdb_db_context *ctdb_db, TALLOC_CTX *mem_ctx, 
					   TDB_DATA key, TDB_DATA *data)
{
	int ret;
	struct ctdb_record_handle *h;

	/*
	  procedure is as follows:

	  1) get the chain lock. 
	  2) check if we are dmaster
	  3) if we are the dmaster then return handle 
	  4) if not dmaster then ask ctdb daemon to make us dmaster, and wait for
	     reply from ctdbd
	  5) when we get the reply, goto (1)
	 */

	h = talloc_zero(mem_ctx, struct ctdb_record_handle);
	if (h == NULL) {
		return NULL;
	}

	h->ctdb_db = ctdb_db;
	h->key     = key;
	h->key.dptr = talloc_memdup(h, key.dptr, key.dsize);
	if (h->key.dptr == NULL) {
		talloc_free(h);
		return NULL;
	}
	h->data    = data;

	DEBUG(3,("ctdb_fetch_lock: key=%*.*s\n", key.dsize, key.dsize, 
		 (const char *)key.dptr));

again:
	/* step 1 - get the chain lock */
	ret = ctdb_ltdb_lock(ctdb_db, key);
	if (ret != 0) {
		DEBUG(0, (__location__ " failed to lock ltdb record\n"));
		talloc_free(h);
		return NULL;
	}

	DEBUG(4,("ctdb_fetch_lock: got chain lock\n"));

	talloc_set_destructor(h, fetch_lock_destructor);

	ret = ctdb_ltdb_fetch(ctdb_db, key, &h->header, h, data);
	if (ret != 0) {
		ctdb_ltdb_unlock(ctdb_db, key);
		talloc_free(h);
		return NULL;
	}

	/* when torturing, ensure we test the remote path */
	if ((ctdb_db->ctdb->flags & CTDB_FLAG_TORTURE) &&
	    random() % 5 == 0) {
		h->header.dmaster = (uint32_t)-1;
	}


	DEBUG(4,("ctdb_fetch_lock: done local fetch\n"));

	if (h->header.dmaster != ctdb_db->ctdb->vnn) {
		ctdb_ltdb_unlock(ctdb_db, key);
		ret = ctdb_client_force_migration(ctdb_db, key);
		if (ret != 0) {
			DEBUG(4,("ctdb_fetch_lock: force_migration failed\n"));
			talloc_free(h);
			return NULL;
		}
		goto again;
	}

	DEBUG(4,("ctdb_fetch_lock: we are dmaster - done\n"));
	return h;
}

/*
  store some data to the record that was locked with ctdb_fetch_lock()
*/
int ctdb_record_store(struct ctdb_record_handle *h, TDB_DATA data)
{
	return ctdb_ltdb_store(h->ctdb_db, h->key, &h->header, data);
}

/*
  wait until we're the only node left.
  this function never returns
*/
void ctdb_shutdown(struct ctdb_context *ctdb)
{
	struct ctdb_req_shutdown *r;

	/* if the domain socket is not yet open, open it */
	if (ctdb->daemon.sd==-1) {
		ctdb_socket_connect(ctdb);
	}

	r = ctdbd_allocate_pkt(ctdb, sizeof(*r));
	ZERO_STRUCT(*r);
	r->hdr.length       = sizeof(*r);
	r->hdr.ctdb_magic   = CTDB_MAGIC;
	r->hdr.ctdb_version = CTDB_VERSION;
	r->hdr.operation    = CTDB_REQ_SHUTDOWN;
	r->hdr.reqid        = 0;

	ctdb_client_queue_pkt(ctdb, &(r->hdr));

	talloc_free(r);

	/* this event loop will terminate once we receive the reply */
	while (1) {
		event_loop_once(ctdb->ev);
	}
}


struct ctdb_client_control_state {
	uint32_t reqid;
	int32_t status;
	TDB_DATA outdata;
	enum call_state state;
};

/*
  called when a CTDB_REPLY_CONTROL packet comes in in the client

  This packet comes in response to a CTDB_REQ_CONTROL request packet. It
  contains any reply data from the control
*/
static void ctdb_client_reply_control(struct ctdb_context *ctdb, 
				      struct ctdb_req_header *hdr)
{
	struct ctdb_reply_control *c = (struct ctdb_reply_control *)hdr;
	struct ctdb_client_control_state *state;

	state = ctdb_reqid_find(ctdb, hdr->reqid, struct ctdb_client_control_state);
	if (state == NULL) {
		DEBUG(0,(__location__ " reqid %d not found\n", hdr->reqid));
		return;
	}

	if (hdr->reqid != state->reqid) {
		/* we found a record  but it was the wrong one */
		DEBUG(0, ("Dropped orphaned reply control with reqid:%d\n",hdr->reqid));
		return;
	}

	state->outdata.dptr = c->data;
	state->outdata.dsize = c->datalen;
	state->status = c->status;

	talloc_steal(state, c);

	state->state = CTDB_CALL_DONE;
}


/*
  send a ctdb control message
 */
int ctdb_control(struct ctdb_context *ctdb, uint32_t destnode, uint64_t srvid, 
		 uint32_t opcode, TDB_DATA data, 
		 TALLOC_CTX *mem_ctx, TDB_DATA *outdata, int32_t *status)
{
	struct ctdb_client_control_state *state;
	struct ctdb_req_control *c;
	size_t len;
	int ret;

	/* if the domain socket is not yet open, open it */
	if (ctdb->daemon.sd==-1) {
		ctdb_socket_connect(ctdb);
	}

	state = talloc_zero(ctdb, struct ctdb_client_control_state);
	CTDB_NO_MEMORY(ctdb, state);

	state->reqid = ctdb_reqid_new(ctdb, state);
	state->state = CTDB_CALL_WAIT;

	len = offsetof(struct ctdb_req_control, data) + data.dsize;
	c = ctdbd_allocate_pkt(state, len);
	
	memset(c, 0, len);
	c->hdr.length       = len;
	c->hdr.ctdb_magic   = CTDB_MAGIC;
	c->hdr.ctdb_version = CTDB_VERSION;
	c->hdr.operation    = CTDB_REQ_CONTROL;
	c->hdr.reqid        = state->reqid;
	c->hdr.destnode     = destnode;
	c->hdr.srcnode      = ctdb->vnn;
	c->hdr.reqid        = state->reqid;
	c->opcode           = opcode;
	c->srvid            = srvid;
	c->datalen          = data.dsize;
	if (data.dsize) {
		memcpy(&c->data[0], data.dptr, data.dsize);
	}

	ret = ctdb_client_queue_pkt(ctdb, &(c->hdr));
	if (ret != 0) {
		talloc_free(state);
		return -1;
	}

	/* semi-async operation */
	while (state->state == CTDB_CALL_WAIT) {
		event_loop_once(ctdb->ev);
	}

	if (outdata) {
		*outdata = state->outdata;
		outdata->dptr = talloc_memdup(mem_ctx, outdata->dptr, outdata->dsize);
	}

	*status = state->status;

	talloc_free(state);

	return 0;	
}



/*
  a process exists call. Returns 0 if process exists, -1 otherwise
 */
int ctdb_process_exists(struct ctdb_context *ctdb, uint32_t destnode, pid_t pid)
{
	int ret;
	TDB_DATA data;
	int32_t status;

	data.dptr = (uint8_t*)&pid;
	data.dsize = sizeof(pid);

	ret = ctdb_control(ctdb, destnode, 0, 
			   CTDB_CONTROL_PROCESS_EXISTS, data, 
			   NULL, NULL, &status);
	if (ret != 0) {
		DEBUG(0,(__location__ " ctdb_control for process_exists failed\n"));
		return -1;
	}

	return status;
}

/*
  get remote status
 */
int ctdb_status(struct ctdb_context *ctdb, uint32_t destnode, struct ctdb_status *status)
{
	int ret;
	TDB_DATA data;
	int32_t res;

	ZERO_STRUCT(data);
	ret = ctdb_control(ctdb, destnode, 0, 
			   CTDB_CONTROL_STATUS, data, 
			   ctdb, &data, &res);
	if (ret != 0 || res != 0) {
		DEBUG(0,(__location__ " ctdb_control for status failed\n"));
		return -1;
	}

	if (data.dsize != sizeof(struct ctdb_status)) {
		DEBUG(0,(__location__ " Wrong status size %u - expected %u\n",
			 data.dsize, sizeof(struct ctdb_status)));
		      return -1;
	}

	*status = *(struct ctdb_status *)data.dptr;
	talloc_free(data.dptr);
			
	return 0;
}

/*
  get vnn map from a remote node
 */
int ctdb_getvnnmap(struct ctdb_context *ctdb, uint32_t destnode, struct ctdb_vnn_map *vnnmap)
{
	int ret;
	TDB_DATA data, outdata;
	int32_t i, res;

	ZERO_STRUCT(data);
	ret = ctdb_control(ctdb, destnode, 0, 
			   CTDB_CONTROL_GETVNNMAP, data, 
			   ctdb, &outdata, &res);
	if (ret != 0 || res != 0) {
		DEBUG(0,(__location__ " ctdb_control for getvnnmap failed\n"));
		return -1;
	}

	vnnmap->generation = ((uint32_t *)outdata.dptr)[0];
	vnnmap->size = ((uint32_t *)outdata.dptr)[1];
	if (vnnmap->map) {
		talloc_free(vnnmap->map);
		vnnmap->map = NULL;
	}
	vnnmap->map = talloc_array(vnnmap, uint32_t, vnnmap->size);
	for (i=0;i<vnnmap->size;i++) {
		vnnmap->map[i] = ((uint32_t *)outdata.dptr)[i+2];
	}
		    
	return 0;
}


/*
  set vnn map on a node
 */
int ctdb_setvnnmap(struct ctdb_context *ctdb, uint32_t destnode, struct ctdb_vnn_map *vnnmap)
{
	int ret;
	TDB_DATA *data, outdata;
	int32_t i, res;

	data = talloc_zero(ctdb, TDB_DATA);
	data->dsize = (vnnmap->size+2)*sizeof(uint32_t);
	data->dptr = (unsigned char *)talloc_array(data, uint32_t, vnnmap->size+2);

	((uint32_t *)&data->dptr[0])[0] = vnnmap->generation;
	((uint32_t *)&data->dptr[0])[1] = vnnmap->size;
	for (i=0;i<vnnmap->size;i++) {
		((uint32_t *)&data->dptr[0])[i+2] = vnnmap->map[i];
	}

	ret = ctdb_control(ctdb, destnode, 0, 
			   CTDB_CONTROL_SETVNNMAP, *data, 
			   ctdb, &outdata, &res);
	if (ret != 0 || res != 0) {
		DEBUG(0,(__location__ " ctdb_control for setvnnmap failed\n"));
		return -1;
	}

	talloc_free(data);		    
	return 0;
}

/*
  ping a node
 */
int ctdb_ping(struct ctdb_context *ctdb, uint32_t destnode)
{
	int ret;
	int32_t res;
	TDB_DATA data;

	ZERO_STRUCT(data);
	ret = ctdb_control(ctdb, destnode, 0, CTDB_CONTROL_PING, data, NULL, NULL, &res);
	if (ret != 0 || res != 0) {
		return -1;
	}
	return 0;
}

/*
  get ctdb config
 */
int ctdb_get_config(struct ctdb_context *ctdb)
{
	int ret;
	int32_t res;
	TDB_DATA data;
	struct ctdb_context c;

	ZERO_STRUCT(data);
	ret = ctdb_control(ctdb, CTDB_CURRENT_NODE, 0, CTDB_CONTROL_CONFIG, data, 
			   ctdb, &data, &res);
	if (ret != 0 || res != 0) {
		return -1;
	}
	if (data.dsize != sizeof(c)) {
		DEBUG(0,("Bad config size %u - expected %u\n", data.dsize, sizeof(c)));
		return -1;
	}

	c = *(struct ctdb_context *)data.dptr;
	talloc_free(data.dptr);

	ctdb->num_nodes = c.num_nodes;
	ctdb->num_connected = c.num_connected;
	ctdb->vnn = c.vnn;
	ctdb->max_lacount = c.max_lacount;
	
	return 0;
}

/*
  find the real path to a ltdb 
 */
int ctdb_getdbpath(struct ctdb_db_context *ctdb_db, TALLOC_CTX *mem_ctx, 
		   const char **path)
{
	int ret;
	int32_t res;
	TDB_DATA data;

	data.dptr = (uint8_t *)&ctdb_db->db_id;
	data.dsize = sizeof(ctdb_db->db_id);

	ret = ctdb_control(ctdb_db->ctdb, CTDB_CURRENT_NODE, 0, 
			   CTDB_CONTROL_GETDBPATH, data, 
			   ctdb_db, &data, &res);
	if (ret != 0 || res != 0) {
		return -1;
	}

	(*path) = talloc_strndup(mem_ctx, (const char *)data.dptr, data.dsize);
	if ((*path) == NULL) {
		return -1;
	}

	talloc_free(data.dptr);

	return 0;
}

/*
  get debug level on a node
 */
int ctdb_get_debuglevel(struct ctdb_context *ctdb, uint32_t destnode, uint32_t *level)
{
	int ret;
	int32_t res;
	TDB_DATA data;

	ZERO_STRUCT(data);
	ret = ctdb_control(ctdb, destnode, 0, CTDB_CONTROL_GET_DEBUG, data, 
			   ctdb, &data, &res);
	if (ret != 0 || res != 0) {
		return -1;
	}
	if (data.dsize != sizeof(uint32_t)) {
		DEBUG(0,("Bad control reply size in ctdb_get_debuglevel (got %u)\n",
			      data.dsize));
		return -1;
	}
	*level = *(uint32_t *)data.dptr;
	talloc_free(data.dptr);
	return 0;
}

/*
  set debug level on a node
 */
int ctdb_set_debuglevel(struct ctdb_context *ctdb, uint32_t destnode, uint32_t level)
{
	int ret;
	int32_t res;
	TDB_DATA data;

	data.dptr = (uint8_t *)&level;
	data.dsize = sizeof(level);

	ret = ctdb_control(ctdb, destnode, 0, CTDB_CONTROL_SET_DEBUG, data, 
			   NULL, NULL, &res);
	if (ret != 0 || res != 0) {
		return -1;
	}
	return 0;
}
