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
		DEBUG(0, ("Dropped client call reply with reqid:%d\n",hdr->reqid));
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
		ctdb_set_error(ctdb, "Bad header length %u expected %u in client\n", 
			       (unsigned)hdr->length, (unsigned)cnt);
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
	c = ctdbd_allocate_pkt(ctdb, state, CTDB_REQ_CALL, len, struct ctdb_req_call);
	if (c == NULL) {
		DEBUG(0, (__location__ " failed to allocate packet\n"));
		return NULL;
	}

	/* this limits us to 16k outstanding messages - not unreasonable */
	c->hdr.reqid     = ctdb_reqid_new(ctdb, state);
	c->flags         = call->flags;
	c->db_id         = ctdb_db->db_id;
	c->callid        = call->call_id;
	c->hopcount      = 0;
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
	int res;
	int32_t status;
	
	res = ctdb_control(ctdb, CTDB_CURRENT_NODE, srvid, CTDB_CONTROL_REGISTER_SRVID, 0, 
			   tdb_null, NULL, NULL, &status, NULL);
	if (res != 0 || status != 0) {
		DEBUG(0,("Failed to register srvid %llu\n", (unsigned long long)srvid));
		return -1;
	}

	/* also need to register the handler with our own ctdb structure */
	return ctdb_register_message_handler(ctdb, ctdb, srvid, handler, private_data);
}

/*
  tell the daemon we no longer want a srvid
*/
int ctdb_remove_message_handler(struct ctdb_context *ctdb, uint64_t srvid, void *private_data)
{
	int res;
	int32_t status;
	
	res = ctdb_control(ctdb, CTDB_CURRENT_NODE, srvid, CTDB_CONTROL_DEREGISTER_SRVID, 0, 
			   tdb_null, NULL, NULL, &status, NULL);
	if (res != 0 || status != 0) {
		DEBUG(0,("Failed to deregister srvid %llu\n", (unsigned long long)srvid));
		return -1;
	}

	/* also need to register the handler with our own ctdb structure */
	ctdb_deregister_message_handler(ctdb, srvid, private_data);
	return 0;
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
	r = ctdbd_allocate_pkt(ctdb, ctdb, CTDB_REQ_MESSAGE, 
			       len, struct ctdb_req_message);
	CTDB_NO_MEMORY(ctdb, r);

	r->hdr.destnode  = vnn;
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

	r = ctdbd_allocate_pkt(ctdb, ctdb, CTDB_REQ_CONNECT_WAIT, sizeof(*r), 
			       struct ctdb_req_connect_wait);
	CTDB_NO_MEMORY_VOID(ctdb, r);

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
	ctdb_ctrl_get_config(ctdb);
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

	r = ctdbd_allocate_pkt(ctdb, ctdb, CTDB_REQ_SHUTDOWN, sizeof(*r), 
			       struct ctdb_req_shutdown);
	CTDB_NO_MEMORY_VOID(ctdb, r);

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


/* time out handler for ctdb_control */
static void timeout_func(struct event_context *ev, struct timed_event *te, 
	struct timeval t, void *private_data)
{
	uint32_t *timed_out = (uint32_t *)private_data;

	*timed_out = 1;
}

/*
  send a ctdb control message
  timeout specifies how long we should wait for a reply.
  if timeout is NULL we wait indefinitely
 */
int ctdb_control(struct ctdb_context *ctdb, uint32_t destnode, uint64_t srvid, 
		 uint32_t opcode, uint32_t flags, TDB_DATA data, 
		 TALLOC_CTX *mem_ctx, TDB_DATA *outdata, int32_t *status,
		 struct timeval *timeout)
{
	struct ctdb_client_control_state *state;
	struct ctdb_req_control *c;
	size_t len;
	int ret;
	uint32_t timed_out;

	/* if the domain socket is not yet open, open it */
	if (ctdb->daemon.sd==-1) {
		ctdb_socket_connect(ctdb);
	}

	state = talloc_zero(ctdb, struct ctdb_client_control_state);
	CTDB_NO_MEMORY(ctdb, state);

	state->reqid = ctdb_reqid_new(ctdb, state);
	state->state = CTDB_CALL_WAIT;

	len = offsetof(struct ctdb_req_control, data) + data.dsize;
	c = ctdbd_allocate_pkt(ctdb, state, CTDB_REQ_CONTROL, 
			       len, struct ctdb_req_control);
	CTDB_NO_MEMORY(ctdb, c);
	
	c->hdr.reqid        = state->reqid;
	c->hdr.destnode     = destnode;
	c->hdr.reqid        = state->reqid;
	c->opcode           = opcode;
	c->client_id        = 0;
	c->flags            = flags;
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

	if (flags & CTDB_CTRL_FLAG_NOREPLY) {
		talloc_free(state);
		return 0;
	}

	/* semi-async operation */
	timed_out = 0;
	if (timeout) {
		event_add_timed(ctdb->ev, state, *timeout, timeout_func, &timed_out);
	}
	while ((state->state == CTDB_CALL_WAIT)
	&&	(timed_out == 0) ){
		event_loop_once(ctdb->ev);
	}
	if (timed_out) {
		talloc_free(state);
		return -1;
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
int ctdb_ctrl_process_exists(struct ctdb_context *ctdb, uint32_t destnode, pid_t pid)
{
	int ret;
	TDB_DATA data;
	int32_t status;

	data.dptr = (uint8_t*)&pid;
	data.dsize = sizeof(pid);

	ret = ctdb_control(ctdb, destnode, 0, 
			   CTDB_CONTROL_PROCESS_EXISTS, 0, data, 
			   NULL, NULL, &status, NULL);
	if (ret != 0) {
		DEBUG(0,(__location__ " ctdb_control for process_exists failed\n"));
		return -1;
	}

	return status;
}

/*
  get remote status
 */
int ctdb_ctrl_status(struct ctdb_context *ctdb, uint32_t destnode, struct ctdb_status *status)
{
	int ret;
	TDB_DATA data;
	int32_t res;

	ZERO_STRUCT(data);
	ret = ctdb_control(ctdb, destnode, 0, 
			   CTDB_CONTROL_STATUS, 0, data, 
			   ctdb, &data, &res, NULL);
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
int ctdb_ctrl_getvnnmap(struct ctdb_context *ctdb, struct timeval timeout, uint32_t destnode, TALLOC_CTX *mem_ctx, struct ctdb_vnn_map **vnnmap)
{
	int ret;
	TDB_DATA data, outdata;
	int32_t res;

	ZERO_STRUCT(data);
	ret = ctdb_control(ctdb, destnode, 0, 
			   CTDB_CONTROL_GETVNNMAP, 0, data, 
			   mem_ctx, &outdata, &res, &timeout);
	if (ret != 0 || res != 0) {
		DEBUG(0,(__location__ " ctdb_control for getvnnmap failed\n"));
		return -1;
	}

	*vnnmap = (struct ctdb_vnn_map *)talloc_memdup(mem_ctx, outdata.dptr, outdata.dsize);
		    
	return 0;
}

/*
  get the recovery mode of a remote node
 */
int ctdb_ctrl_getrecmode(struct ctdb_context *ctdb, struct timeval timeout, uint32_t destnode, uint32_t *recmode)
{
	int ret;
	TDB_DATA data, outdata;
	int32_t res;

	ZERO_STRUCT(data);
	ret = ctdb_control(ctdb, destnode, 0, 
			   CTDB_CONTROL_GET_RECMODE, 0, data, 
			   ctdb, &outdata, &res, &timeout);
	if (ret != 0) {
		DEBUG(0,(__location__ " ctdb_control for getrecmode failed\n"));
		return -1;
	}

	*recmode = res;

	return 0;
}

/*
  set the recovery mode of a remote node
 */
int ctdb_ctrl_setrecmode(struct ctdb_context *ctdb, struct timeval timeout, uint32_t destnode, uint32_t recmode)
{
	int ret;
	TDB_DATA data, outdata;
	int32_t res;

	ZERO_STRUCT(data);
	data.dsize = sizeof(uint32_t);
	data.dptr = (unsigned char *)&recmode;

	ret = ctdb_control(ctdb, destnode, 0, 
			   CTDB_CONTROL_SET_RECMODE, 0, data, 
			   ctdb, &outdata, &res, &timeout);
	if (ret != 0 || res != 0) {
		DEBUG(0,(__location__ " ctdb_control for getrecmode failed\n"));
		return -1;
	}

	return 0;
}

/*
  get the recovery master of a remote node
 */
int ctdb_ctrl_getrecmaster(struct ctdb_context *ctdb, struct timeval timeout, uint32_t destnode, uint32_t *recmaster)
{
	int ret;
	TDB_DATA data, outdata;
	int32_t res;

	ZERO_STRUCT(data);
	ret = ctdb_control(ctdb, destnode, 0, 
			   CTDB_CONTROL_GET_RECMASTER, 0, data, 
			   ctdb, &outdata, &res, &timeout);
	if (ret != 0) {
		DEBUG(0,(__location__ " ctdb_control for getrecmaster failed\n"));
		return -1;
	}

	*recmaster = res;

	return 0;
}

/*
  set the recovery master of a remote node
 */
int ctdb_ctrl_setrecmaster(struct ctdb_context *ctdb, struct timeval timeout, uint32_t destnode, uint32_t recmaster)
{
	int ret;
	TDB_DATA data, outdata;
	int32_t res;

	ZERO_STRUCT(data);
	data.dsize = sizeof(uint32_t);
	data.dptr = (unsigned char *)&recmaster;

	ret = ctdb_control(ctdb, destnode, 0, 
			   CTDB_CONTROL_SET_RECMASTER, 0, data, 
			   ctdb, &outdata, &res, &timeout);
	if (ret != 0 || res != 0) {
		DEBUG(0,(__location__ " ctdb_control for getrecmode failed\n"));
		return -1;
	}

	return 0;
}


/*
  get a list of databases off a remote node
 */
int ctdb_ctrl_getdbmap(struct ctdb_context *ctdb, struct timeval timeout, uint32_t destnode, TALLOC_CTX *mem_ctx, struct ctdb_dbid_map **dbmap)
{
	int ret;
	TDB_DATA data, outdata;
	int32_t res;

	ZERO_STRUCT(data);
	ret = ctdb_control(ctdb, destnode, 0, 
			   CTDB_CONTROL_GET_DBMAP, 0, data, 
			   mem_ctx, &outdata, &res, &timeout);
	if (ret != 0 || res != 0) {
		DEBUG(0,(__location__ " ctdb_control for getdbmap failed\n"));
		return -1;
	}

	*dbmap = (struct ctdb_dbid_map *)talloc_memdup(mem_ctx, outdata.dptr, outdata.dsize);
		    
	return 0;
}


/*
  get a list of nodes (vnn and flags ) from a remote node
 */
int ctdb_ctrl_getnodemap(struct ctdb_context *ctdb, 
		struct timeval timeout, uint32_t destnode, 
		TALLOC_CTX *mem_ctx, struct ctdb_node_map **nodemap)
{
	int ret;
	TDB_DATA data, outdata;
	int32_t res;

	ZERO_STRUCT(data);
	ret = ctdb_control(ctdb, destnode, 0, 
			   CTDB_CONTROL_GET_NODEMAP, 0, data, 
			   mem_ctx, &outdata, &res, &timeout);
	if (ret != 0 || res != 0) {
		DEBUG(0,(__location__ " ctdb_control for getnodes failed\n"));
		return -1;
	}

	*nodemap = (struct ctdb_node_map *)talloc_memdup(mem_ctx, outdata.dptr, outdata.dsize);
		    
	return 0;
}

/*
  set vnn map on a node
 */
int ctdb_ctrl_setvnnmap(struct ctdb_context *ctdb, struct timeval timeout, uint32_t destnode, TALLOC_CTX *mem_ctx, struct ctdb_vnn_map *vnnmap)
{
	int ret;
	TDB_DATA data, outdata;
	int32_t res;

	data.dsize = offsetof(struct ctdb_vnn_map, map) + 4*vnnmap->size;
	data.dptr  = (unsigned char *)vnnmap;

	ret = ctdb_control(ctdb, destnode, 0, 
			   CTDB_CONTROL_SETVNNMAP, 0, data, 
			   mem_ctx, &outdata, &res, &timeout);
	if (ret != 0 || res != 0) {
		DEBUG(0,(__location__ " ctdb_control for setvnnmap failed\n"));
		return -1;
	}

	return 0;
}

/*
  get all keys and records for a specific database
 */
int ctdb_ctrl_pulldb(struct ctdb_context *ctdb, uint32_t destnode, uint32_t dbid, uint32_t lmaster, TALLOC_CTX *mem_ctx, struct ctdb_key_list *keys)
{
	int i, ret;
	TDB_DATA indata, outdata;
	int32_t res;
	unsigned char *ptr;

	indata.dsize = 2*sizeof(uint32_t);
	indata.dptr  = (unsigned char *)talloc_array(mem_ctx, uint32_t, 2);

	((uint32_t *)(&indata.dptr[0]))[0] = dbid;
	((uint32_t *)(&indata.dptr[0]))[1] = lmaster;

	ret = ctdb_control(ctdb, destnode, 0, 
			   CTDB_CONTROL_PULL_DB, 0, indata, 
			   mem_ctx, &outdata, &res, NULL);
	if (ret != 0 || res != 0) {
		DEBUG(0,(__location__ " ctdb_control for pulldb failed\n"));
		return -1;
	}


	keys->dbid   = ((uint32_t *)(&outdata.dptr[0]))[0];
	keys->num    = ((uint32_t *)(&outdata.dptr[0]))[1];
	keys->keys   =talloc_array(mem_ctx, TDB_DATA, keys->num);
	keys->headers=talloc_array(mem_ctx, struct ctdb_ltdb_header, keys->num);
	keys->lmasters=talloc_array(mem_ctx, uint32_t, keys->num);
	keys->data=talloc_array(mem_ctx, TDB_DATA, keys->num);

	/* loop over all key/data pairs */
	ptr=&outdata.dptr[8];
	for(i=0;i<keys->num;i++){
		TDB_DATA *key, *data;

		keys->lmasters[i] = *((uint32_t *)ptr);
		ptr += 4;

		key = &keys->keys[i];
		key->dsize = *((uint32_t *)ptr);
		key->dptr = talloc_size(mem_ctx, key->dsize);
		ptr += 4;

		data = &keys->data[i];
		data->dsize = *((uint32_t *)ptr);
		data->dptr = talloc_size(mem_ctx, data->dsize);
		ptr += 4;

		ptr = outdata.dptr+(((ptr-outdata.dptr)+CTDB_DS_ALIGNMENT-1)& ~(CTDB_DS_ALIGNMENT-1));
		memcpy(key->dptr, ptr, key->dsize);
		ptr += key->dsize;

		ptr = outdata.dptr+(((ptr-outdata.dptr)+CTDB_DS_ALIGNMENT-1)& ~(CTDB_DS_ALIGNMENT-1));
		memcpy(&keys->headers[i], ptr, sizeof(struct ctdb_ltdb_header));
		ptr += sizeof(struct ctdb_ltdb_header);

		ptr = outdata.dptr+(((ptr-outdata.dptr)+CTDB_DS_ALIGNMENT-1)& ~(CTDB_DS_ALIGNMENT-1));
		memcpy(data->dptr, ptr, data->dsize);
		ptr += data->dsize;

		ptr = outdata.dptr+(((ptr-outdata.dptr)+CTDB_DS_ALIGNMENT-1)& ~(CTDB_DS_ALIGNMENT-1));
	}

	return 0;
}

/*
  copy a tdb from one node to another node
 */
int ctdb_ctrl_copydb(struct ctdb_context *ctdb, struct timeval timeout, uint32_t sourcenode, uint32_t destnode, uint32_t dbid, uint32_t lmaster, TALLOC_CTX *mem_ctx)
{
	int ret;
	TDB_DATA indata, outdata;
	int32_t res;

	indata.dsize = 2*sizeof(uint32_t);
	indata.dptr  = (unsigned char *)talloc_array(mem_ctx, uint32_t, 2);

	((uint32_t *)(&indata.dptr[0]))[0] = dbid;
	((uint32_t *)(&indata.dptr[0]))[1] = lmaster;

	ret = ctdb_control(ctdb, sourcenode, 0, 
			   CTDB_CONTROL_PULL_DB, 0, indata, 
			   mem_ctx, &outdata, &res, &timeout);
	if (ret != 0 || res != 0) {
		DEBUG(0,(__location__ " ctdb_control for pulldb failed\n"));
		return -1;
	}

	ret = ctdb_control(ctdb, destnode, 0, 
			   CTDB_CONTROL_PUSH_DB, 0, outdata, 
			   mem_ctx, NULL, &res, &timeout);
	if (ret != 0 || res != 0) {
		DEBUG(0,(__location__ " ctdb_control for pushdb failed\n"));
		return -1;
	}

	return 0;
}

/*
  change dmaster for all keys in the database to the new value
 */
int ctdb_ctrl_setdmaster(struct ctdb_context *ctdb, struct timeval timeout, uint32_t destnode, TALLOC_CTX *mem_ctx, uint32_t dbid, uint32_t dmaster)
{
	int ret;
	TDB_DATA indata, outdata;
	int32_t res;

	indata.dsize = 2*sizeof(uint32_t);
	indata.dptr = (unsigned char *)talloc_array(mem_ctx, uint32_t, 2);

	((uint32_t *)(&indata.dptr[0]))[0] = dbid;
	((uint32_t *)(&indata.dptr[0]))[1] = dmaster;

	ret = ctdb_control(ctdb, destnode, 0, 
			   CTDB_CONTROL_SET_DMASTER, 0, indata, 
			   mem_ctx, &outdata, &res, &timeout);
	if (ret != 0 || res != 0) {
		DEBUG(0,(__location__ " ctdb_control for setdmaster failed\n"));
		return -1;
	}

	return 0;
}

/*
  delete all records from a tdb
 */
int ctdb_ctrl_cleardb(struct ctdb_context *ctdb, uint32_t destnode, TALLOC_CTX *mem_ctx, uint32_t dbid)
{
	int ret;
	TDB_DATA indata, outdata;
	int32_t res;

	indata.dsize = sizeof(uint32_t);
	indata.dptr = (unsigned char *)talloc_array(mem_ctx, uint32_t, 1);

	((uint32_t *)(&indata.dptr[0]))[0] = dbid;

	ret = ctdb_control(ctdb, destnode, 0, 
			   CTDB_CONTROL_CLEAR_DB, 0, indata, 
			   mem_ctx, &outdata, &res, NULL);
	if (ret != 0 || res != 0) {
		DEBUG(0,(__location__ " ctdb_control for cleardb failed\n"));
		return -1;
	}

	return 0;
}

int ctdb_ctrl_write_record(struct ctdb_context *ctdb, uint32_t destnode, TALLOC_CTX *mem_ctx, uint32_t dbid, TDB_DATA key, TDB_DATA data)
{
	struct ctdb_write_record *wr;
	TDB_DATA indata, outdata;
	int32_t res;
	int ret, len;

	len = offsetof(struct ctdb_write_record, blob)+key.dsize+data.dsize;
	wr = (struct ctdb_write_record *)talloc_zero_size(mem_ctx, len);
	wr->dbid    = dbid;
	wr->keylen  = key.dsize;
	wr->datalen = data.dsize;
	memcpy(&wr->blob[0], &key.dptr[0], key.dsize);
	memcpy(&wr->blob[key.dsize], &data.dptr[0], data.dsize);


	indata.dsize = len;
	indata.dptr = (unsigned char *)wr;

	ret = ctdb_control(ctdb, destnode, 0, 
			   CTDB_CONTROL_WRITE_RECORD, 0, indata, 
			   mem_ctx, &outdata, &res, NULL);
	if (ret != 0 || res != 0) {
		DEBUG(0,(__location__ " ctdb_control for write record failed\n"));
		return -1;
	}

	return 0;
}

/*
  ping a node, return number of clients connected
 */
int ctdb_ctrl_ping(struct ctdb_context *ctdb, uint32_t destnode)
{
	int ret;
	int32_t res;
	TDB_DATA data;

	ZERO_STRUCT(data);
	ret = ctdb_control(ctdb, destnode, 0, CTDB_CONTROL_PING, 0, 
			   data, NULL, NULL, &res, NULL);
	if (ret != 0) {
		return -1;
	}
	return res;
}

/*
  get ctdb config
 */
int ctdb_ctrl_get_config(struct ctdb_context *ctdb)
{
	int ret;
	int32_t res;
	TDB_DATA data;
	struct ctdb_context c;

	ZERO_STRUCT(data);
	ret = ctdb_control(ctdb, CTDB_CURRENT_NODE, 0, CTDB_CONTROL_CONFIG, 0,
			   data, ctdb, &data, &res, NULL);
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
int ctdb_ctrl_getdbpath(struct ctdb_context *ctdb, struct timeval timeout, uint32_t destnode, uint32_t dbid, TALLOC_CTX *mem_ctx, 
		   const char **path)
{
	int ret;
	int32_t res;
	TDB_DATA data;

	data.dptr = (uint8_t *)&dbid;
	data.dsize = sizeof(dbid);

	ret = ctdb_control(ctdb, destnode, 0, 
			   CTDB_CONTROL_GETDBPATH, 0, data, 
			   mem_ctx, &data, &res, &timeout);
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
  find the name of a db 
 */
int ctdb_ctrl_getdbname(struct ctdb_context *ctdb, struct timeval timeout, uint32_t destnode, uint32_t dbid, TALLOC_CTX *mem_ctx, 
		   const char **name)
{
	int ret;
	int32_t res;
	TDB_DATA data;

	data.dptr = (uint8_t *)&dbid;
	data.dsize = sizeof(dbid);

	ret = ctdb_control(ctdb, destnode, 0, 
			   CTDB_CONTROL_GET_DBNAME, 0, data, 
			   mem_ctx, &data, &res, &timeout);
	if (ret != 0 || res != 0) {
		return -1;
	}

	(*name) = talloc_strndup(mem_ctx, (const char *)data.dptr, data.dsize);
	if ((*name) == NULL) {
		return -1;
	}

	talloc_free(data.dptr);

	return 0;
}

/*
  create a database
 */
int ctdb_ctrl_createdb(struct ctdb_context *ctdb, struct timeval timeout, uint32_t destnode, TALLOC_CTX *mem_ctx, const char *name)
{
	int ret;
	int32_t res;
	TDB_DATA data;

	data.dptr = discard_const(name);
	data.dsize = strlen(name)+1;

	ret = ctdb_control(ctdb, destnode, 0, 
			   CTDB_CONTROL_DB_ATTACH, 0, data, 
			   mem_ctx, &data, &res, &timeout);

	if (ret != 0 || res != 0) {
		return -1;
	}

	return 0;
}

/*
  get debug level on a node
 */
int ctdb_ctrl_get_debuglevel(struct ctdb_context *ctdb, uint32_t destnode, uint32_t *level)
{
	int ret;
	int32_t res;
	TDB_DATA data;

	ZERO_STRUCT(data);
	ret = ctdb_control(ctdb, destnode, 0, CTDB_CONTROL_GET_DEBUG, 0, data, 
			   ctdb, &data, &res, NULL);
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
int ctdb_ctrl_set_debuglevel(struct ctdb_context *ctdb, uint32_t destnode, uint32_t level)
{
	int ret;
	int32_t res;
	TDB_DATA data;

	data.dptr = (uint8_t *)&level;
	data.dsize = sizeof(level);

	ret = ctdb_control(ctdb, destnode, 0, CTDB_CONTROL_SET_DEBUG, 0, data, 
			   NULL, NULL, &res, NULL);
	if (ret != 0 || res != 0) {
		return -1;
	}
	return 0;
}


/*
  get a list of connected nodes
 */
uint32_t *ctdb_get_connected_nodes(struct ctdb_context *ctdb, 
				struct timeval timeout,
				TALLOC_CTX *mem_ctx,
				uint32_t *num_nodes)
{
	struct ctdb_node_map *map=NULL;
	int ret, i;
	uint32_t *nodes;

	*num_nodes = 0;

	ret = ctdb_ctrl_getnodemap(ctdb, timeout, CTDB_CURRENT_NODE, mem_ctx, &map);
	if (ret != 0) {
		return NULL;
	}

	nodes = talloc_array(mem_ctx, uint32_t, map->num);
	if (nodes == NULL) {
		return NULL;
	}

	for (i=0;i<map->num;i++) {
		if (map->nodes[i].flags & NODE_FLAGS_CONNECTED) {
			nodes[*num_nodes] = map->nodes[i].vnn;
			(*num_nodes)++;
		}
	}

	return nodes;
}


/*
  reset remote status
 */
int ctdb_status_reset(struct ctdb_context *ctdb, uint32_t destnode)
{
	int ret;
	TDB_DATA data;
	int32_t res;

	ZERO_STRUCT(data);
	ret = ctdb_control(ctdb, destnode, 0, 
			   CTDB_CONTROL_STATUS_RESET, 0, data, 
			   NULL, NULL, &res, NULL);
	if (ret != 0 || res != 0) {
		DEBUG(0,(__location__ " ctdb_control for reset status failed\n"));
		return -1;
	}
	return 0;
}


/*
  attach to a specific database - client call
*/
struct ctdb_db_context *ctdb_attach(struct ctdb_context *ctdb, const char *name)
{
	struct ctdb_db_context *ctdb_db;
	TDB_DATA data;
	int ret;
	int32_t res;

	ctdb_db = talloc_zero(ctdb, struct ctdb_db_context);
	CTDB_NO_MEMORY_NULL(ctdb, ctdb_db);

	ctdb_db->ctdb = ctdb;
	ctdb_db->db_name = talloc_strdup(ctdb_db, name);
	CTDB_NO_MEMORY_NULL(ctdb, ctdb_db->db_name);

	data.dptr = discard_const(name);
	data.dsize = strlen(name)+1;

	/* tell ctdb daemon to attach */
	ret = ctdb_control(ctdb, CTDB_CURRENT_NODE, 0, CTDB_CONTROL_DB_ATTACH,
			   0, data, ctdb_db, &data, &res, NULL);
	if (ret != 0 || res != 0 || data.dsize != sizeof(uint32_t)) {
		DEBUG(0,("Failed to attach to database '%s'\n", name));
		talloc_free(ctdb_db);
		return NULL;
	}
	
	ctdb_db->db_id = *(uint32_t *)data.dptr;

	ret = ctdb_ctrl_getdbpath(ctdb, timeval_current_ofs(1, 0), CTDB_CURRENT_NODE, ctdb_db->db_id, ctdb_db, &ctdb_db->db_path);
	if (ret != 0) {
		DEBUG(0,("Failed to get dbpath for database '%s'\n", name));
		talloc_free(ctdb_db);
		return NULL;
	}

	ctdb_db->ltdb = tdb_wrap_open(ctdb, ctdb_db->db_path, 0, 0, O_RDWR, 0);
	if (ctdb_db->ltdb == NULL) {
		ctdb_set_error(ctdb, "Failed to open tdb '%s'\n", ctdb_db->db_path);
		talloc_free(ctdb_db);
		return NULL;
	}

	DLIST_ADD(ctdb->db_list, ctdb_db);

	return ctdb_db;
}


/*
  setup a call for a database
 */
int ctdb_set_call(struct ctdb_db_context *ctdb_db, ctdb_fn_t fn, uint32_t id)
{
	TDB_DATA data;
	int32_t status;
	struct ctdb_control_set_call c;
	int ret;
	struct ctdb_registered_call *call;

	c.db_id = ctdb_db->db_id;
	c.fn    = fn;
	c.id    = id;

	data.dptr = (uint8_t *)&c;
	data.dsize = sizeof(c);

	ret = ctdb_control(ctdb_db->ctdb, CTDB_CURRENT_NODE, 0, CTDB_CONTROL_SET_CALL, 0,
			   data, NULL, NULL, &status, NULL);
	if (ret != 0 || status != 0) {
		DEBUG(0,("ctdb_set_call failed for call %u\n", id));
		return -1;
	}

	/* also register locally */
	call = talloc(ctdb_db, struct ctdb_registered_call);
	call->fn = fn;
	call->id = id;

	DLIST_ADD(ctdb_db->calls, call);	
	return 0;
}


struct traverse_state {
	bool done;
	uint32_t count;
	ctdb_traverse_func fn;
	void *private_data;
};

/*
  called on each key during a ctdb_traverse
 */
static void traverse_handler(struct ctdb_context *ctdb, uint64_t srvid, TDB_DATA data, void *p)
{
	struct traverse_state *state = (struct traverse_state *)p;
	struct ctdb_traverse_data *d = (struct ctdb_traverse_data *)data.dptr;
	TDB_DATA key;

	if (data.dsize < sizeof(uint32_t) ||
	    d->length != data.dsize) {
		DEBUG(0,("Bad data size %u in traverse_handler\n", data.dsize));
		state->done = True;
		return;
	}

	key.dsize = d->keylen;
	key.dptr  = &d->data[0];
	data.dsize = d->datalen;
	data.dptr = &d->data[d->keylen];

	if (key.dsize == 0 && data.dsize == 0) {
		/* end of traverse */
		state->done = True;
		return;
	}

	if (state->fn(ctdb, key, data, state->private_data) != 0) {
		state->done = True;
	}

	state->count++;
}


/*
  start a cluster wide traverse, calling the supplied fn on each record
  return the number of records traversed, or -1 on error
 */
int ctdb_traverse(struct ctdb_db_context *ctdb_db, ctdb_traverse_func fn, void *private_data)
{
	TDB_DATA data;
	struct ctdb_traverse_start t;
	int32_t status;
	int ret;
	uint64_t srvid = (getpid() | 0xFLL<<60);
	struct traverse_state state;

	state.done = False;
	state.count = 0;
	state.private_data = private_data;
	state.fn = fn;

	ret = ctdb_set_message_handler(ctdb_db->ctdb, srvid, traverse_handler, &state);
	if (ret != 0) {
		DEBUG(0,("Failed to setup traverse handler\n"));
		return -1;
	}

	t.db_id = ctdb_db->db_id;
	t.srvid = srvid;
	t.reqid = 0;

	data.dptr = (uint8_t *)&t;
	data.dsize = sizeof(t);

	ret = ctdb_control(ctdb_db->ctdb, CTDB_CURRENT_NODE, 0, CTDB_CONTROL_TRAVERSE_START, 0,
			   data, NULL, NULL, &status, NULL);
	if (ret != 0 || status != 0) {
		DEBUG(0,("ctdb_traverse_all failed\n"));
		ctdb_remove_message_handler(ctdb_db->ctdb, srvid, &state);
		return -1;
	}

	while (!state.done) {
		event_loop_once(ctdb_db->ctdb->ev);
	}

	ret = ctdb_remove_message_handler(ctdb_db->ctdb, srvid, &state);
	if (ret != 0) {
		DEBUG(0,("Failed to remove ctdb_traverse handler\n"));
		return -1;
	}

	return state.count;
}

/*
  called on each key during a catdb
 */
static int dumpdb_fn(struct ctdb_context *ctdb, TDB_DATA key, TDB_DATA data, void *p)
{
	FILE *f = (FILE *)p;
	char *keystr, *datastr;
	struct ctdb_ltdb_header *h = (struct ctdb_ltdb_header *)data.dptr;

	keystr  = hex_encode(ctdb, key.dptr, key.dsize);
	datastr = hex_encode(ctdb, data.dptr+sizeof(*h), data.dsize-sizeof(*h));

	fprintf(f, "dmaster: %u\n", h->dmaster);
	fprintf(f, "rsn: %llu\n", (unsigned long long)h->rsn);
	fprintf(f, "key: %s\ndata: %s\n", keystr, datastr);

	talloc_free(keystr);
	talloc_free(datastr);
	return 0;
}

/*
  convenience function to list all keys to stdout
 */
int ctdb_dump_db(struct ctdb_db_context *ctdb_db, FILE *f)
{
	return ctdb_traverse(ctdb_db, dumpdb_fn, f);
}

/*
  get the pid of a ctdb daemon
 */
int ctdb_ctrl_getpid(struct ctdb_context *ctdb, struct timeval timeout, uint32_t destnode, uint32_t *pid)
{
	int ret;
	TDB_DATA data, outdata;
	int32_t res;

	ZERO_STRUCT(data);
	ret = ctdb_control(ctdb, destnode, 0, 
			   CTDB_CONTROL_GET_PID, 0, data, 
			   ctdb, &outdata, &res, &timeout);
	if (ret != 0) {
		DEBUG(0,(__location__ " ctdb_control for getpid failed\n"));
		return -1;
	}

	*pid = res;

	return 0;
}

