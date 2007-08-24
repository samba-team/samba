/* 
   ctdb daemon code

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

#include "includes.h"
#include "db_wrap.h"
#include "lib/tdb/include/tdb.h"
#include "lib/util/dlinklist.h"
#include "lib/events/events.h"
#include "system/network.h"
#include "system/filesys.h"
#include "../include/ctdb_private.h"
#include "lib/util/dlinklist.h"

/*
  allocate a packet for use in client<->daemon communication
 */
struct ctdb_req_header *_ctdbd_allocate_pkt(struct ctdb_context *ctdb,
					    TALLOC_CTX *mem_ctx, 
					    enum ctdb_operation operation, 
					    size_t length, size_t slength,
					    const char *type)
{
	int size;
	struct ctdb_req_header *hdr;

	length = MAX(length, slength);
	size = (length+(CTDB_DS_ALIGNMENT-1)) & ~(CTDB_DS_ALIGNMENT-1);

	hdr = (struct ctdb_req_header *)talloc_size(mem_ctx, size);
	if (hdr == NULL) {
		DEBUG(0,("Unable to allocate packet for operation %u of length %u\n",
			 operation, (unsigned)length));
		return NULL;
	}
	talloc_set_name_const(hdr, type);
	memset(hdr, 0, slength);
	hdr->length       = length;
	hdr->operation    = operation;
	hdr->ctdb_magic   = CTDB_MAGIC;
	hdr->ctdb_version = CTDB_VERSION;
	hdr->srcnode      = ctdb->vnn;
	if (ctdb->vnn_map) {
		hdr->generation = ctdb->vnn_map->generation;
	}

	return hdr;
}

/*
  local version of ctdb_call
*/
int ctdb_call_local(struct ctdb_db_context *ctdb_db, struct ctdb_call *call,
		    struct ctdb_ltdb_header *header, TALLOC_CTX *mem_ctx,
		    TDB_DATA *data, uint32_t caller)
{
	struct ctdb_call_info *c;
	struct ctdb_registered_call *fn;
	struct ctdb_context *ctdb = ctdb_db->ctdb;
	
	c = talloc(ctdb, struct ctdb_call_info);
	CTDB_NO_MEMORY(ctdb, c);

	c->key = call->key;
	c->call_data = &call->call_data;
	c->record_data.dptr = talloc_memdup(c, data->dptr, data->dsize);
	c->record_data.dsize = data->dsize;
	CTDB_NO_MEMORY(ctdb, c->record_data.dptr);
	c->new_data = NULL;
	c->reply_data = NULL;
	c->status = 0;

	for (fn=ctdb_db->calls;fn;fn=fn->next) {
		if (fn->id == call->call_id) break;
	}
	if (fn == NULL) {
		ctdb_set_error(ctdb, "Unknown call id %u\n", call->call_id);
		talloc_free(c);
		return -1;
	}

	if (fn->fn(c) != 0) {
		ctdb_set_error(ctdb, "ctdb_call %u failed\n", call->call_id);
		talloc_free(c);
		return -1;
	}

	if (header->laccessor != caller) {
		header->lacount = 0;
	}
	header->laccessor = caller;
	header->lacount++;

	/* we need to force the record to be written out if this was a remote access,
	   so that the lacount is updated */
	if (c->new_data == NULL && header->laccessor != ctdb->vnn) {
		c->new_data = &c->record_data;
	}

	if (c->new_data) {
		/* XXX check that we always have the lock here? */
		if (ctdb_ltdb_store(ctdb_db, call->key, header, *c->new_data) != 0) {
			ctdb_set_error(ctdb, "ctdb_call tdb_store failed\n");
			talloc_free(c);
			return -1;
		}
	}

	if (c->reply_data) {
		call->reply_data = *c->reply_data;
		talloc_steal(ctdb, call->reply_data.dptr);
		talloc_set_name_const(call->reply_data.dptr, __location__);
	} else {
		call->reply_data.dptr = NULL;
		call->reply_data.dsize = 0;
	}
	call->status = c->status;

	talloc_free(c);

	return 0;
}


/*
  queue a packet for sending from client to daemon
*/
static int ctdb_client_queue_pkt(struct ctdb_context *ctdb, struct ctdb_req_header *hdr)
{
	return ctdb_queue_send(ctdb->daemon.queue, (uint8_t *)hdr, hdr->length);
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
		DEBUG(0,(__location__ " reqid %u not found\n", hdr->reqid));
		return;
	}

	if (hdr->reqid != state->reqid) {
		/* we found a record  but it was the wrong one */
		DEBUG(0, ("Dropped client call reply with reqid:%u\n",hdr->reqid));
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
		DEBUG(0,("Bad packet length %u in client\n", (unsigned)cnt));
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

	case CTDB_REPLY_CONTROL:
		ctdb_client_reply_control(ctdb, hdr);
		break;

	default:
		DEBUG(0,("bogus operation code:%u\n",hdr->operation));
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

	set_nonblocking(ctdb->daemon.sd);
	set_close_on_exec(ctdb->daemon.sd);
	
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

	ret = ctdb_call_local(ctdb_db, &state->call, header, state, data, ctdb->vnn);

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

	if (ret == 0 && header.dmaster == ctdb->vnn) {
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

	state->reqid     = ctdb_reqid_new(ctdb, state);
	state->ctdb_db = ctdb_db;
	talloc_set_destructor(state, ctdb_client_call_destructor);

	c->hdr.reqid     = state->reqid;
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
			   tdb_null, NULL, NULL, &status, NULL, NULL);
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
			   tdb_null, NULL, NULL, &status, NULL, NULL);
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

	DEBUG(3,("ctdb_fetch_lock: key=%*.*s\n", (int)key.dsize, (int)key.dsize, 
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

	/* when torturing, ensure we test the remote path */
	if ((ctdb_db->ctdb->flags & CTDB_FLAG_TORTURE) &&
	    random() % 5 == 0) {
		h->header.dmaster = (uint32_t)-1;
	}


	DEBUG(4,("ctdb_fetch_lock: done local fetch\n"));

	if (ret != 0 || h->header.dmaster != ctdb_db->ctdb->vnn) {
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
  non-locking fetch of a record
 */
int ctdb_fetch(struct ctdb_db_context *ctdb_db, TALLOC_CTX *mem_ctx, 
	       TDB_DATA key, TDB_DATA *data)
{
	struct ctdb_call call;
	int ret;

	call.call_id = CTDB_FETCH_FUNC;
	call.call_data.dptr = NULL;
	call.call_data.dsize = 0;

	ret = ctdb_call(ctdb_db, &call);

	if (ret == 0) {
		*data = call.reply_data;
		talloc_steal(mem_ctx, data->dptr);
	}

	return ret;
}


struct ctdb_client_control_state {
	struct ctdb_context *ctdb;
	uint32_t reqid;
	int32_t status;
	TDB_DATA outdata;
	enum call_state state;
	char *errormsg;
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
		DEBUG(0,(__location__ " reqid %u not found\n", hdr->reqid));
		return;
	}

	if (hdr->reqid != state->reqid) {
		/* we found a record  but it was the wrong one */
		DEBUG(0, ("Dropped orphaned reply control with reqid:%u\n",hdr->reqid));
		return;
	}

	state->outdata.dptr = c->data;
	state->outdata.dsize = c->datalen;
	state->status = c->status;
	if (c->errorlen) {
		state->errormsg = talloc_strndup(state, 
						 (char *)&c->data[c->datalen], 
						 c->errorlen);
	}

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
  destroy a ctdb_control in client
*/
static int ctdb_control_destructor(struct ctdb_client_control_state *state)	
{
	ctdb_reqid_remove(state->ctdb, state->reqid);
	return 0;
}

/*
  send a ctdb control message
  timeout specifies how long we should wait for a reply.
  if timeout is NULL we wait indefinitely
 */
int ctdb_control(struct ctdb_context *ctdb, uint32_t destnode, uint64_t srvid, 
		 uint32_t opcode, uint32_t flags, TDB_DATA data, 
		 TALLOC_CTX *mem_ctx, TDB_DATA *outdata, int32_t *status,
		 struct timeval *timeout,
		 char **errormsg)
{
	struct ctdb_client_control_state *state;
	struct ctdb_req_control *c;
	size_t len;
	int ret;
	uint32_t timed_out;

	if (errormsg) {
		*errormsg = NULL;
	}

	/* if the domain socket is not yet open, open it */
	if (ctdb->daemon.sd==-1) {
		ctdb_socket_connect(ctdb);
	}

	state = talloc_zero(ctdb, struct ctdb_client_control_state);
	CTDB_NO_MEMORY(ctdb, state);

	state->ctdb  = ctdb;
	state->reqid = ctdb_reqid_new(ctdb, state);
	state->state = CTDB_CALL_WAIT;
	state->errormsg = NULL;

	talloc_set_destructor(state, ctdb_control_destructor);

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
	if (timeout && !timeval_is_zero(timeout)) {
		event_add_timed(ctdb->ev, state, *timeout, timeout_func, &timed_out);
	}
	while ((state->state == CTDB_CALL_WAIT)
	&&	(timed_out == 0) ){
		event_loop_once(ctdb->ev);
	}
	if (timed_out) {
		talloc_free(state);
		if (errormsg) {
			(*errormsg) = talloc_strdup(mem_ctx, "control timed out");
		} else {
			DEBUG(0,("ctdb_control timed out\n"));
		}
		return -1;
	}

	if (outdata) {
		*outdata = state->outdata;
		outdata->dptr = talloc_memdup(mem_ctx, outdata->dptr, outdata->dsize);
	}

	*status = state->status;

	if (!errormsg && state->errormsg) {
		DEBUG(0,("ctdb_control error: '%s'\n", state->errormsg));
	}

	if (errormsg && state->errormsg) {
		(*errormsg) = talloc_move(mem_ctx, &state->errormsg);
	}

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
			   NULL, NULL, &status, NULL, NULL);
	if (ret != 0) {
		DEBUG(0,(__location__ " ctdb_control for process_exists failed\n"));
		return -1;
	}

	return status;
}

/*
  get remote statistics
 */
int ctdb_ctrl_statistics(struct ctdb_context *ctdb, uint32_t destnode, struct ctdb_statistics *status)
{
	int ret;
	TDB_DATA data;
	int32_t res;

	ret = ctdb_control(ctdb, destnode, 0, 
			   CTDB_CONTROL_STATISTICS, 0, tdb_null, 
			   ctdb, &data, &res, NULL, NULL);
	if (ret != 0 || res != 0) {
		DEBUG(0,(__location__ " ctdb_control for statistics failed\n"));
		return -1;
	}

	if (data.dsize != sizeof(struct ctdb_statistics)) {
		DEBUG(0,(__location__ " Wrong statistics size %u - expected %u\n",
			 (unsigned)data.dsize, (unsigned)sizeof(struct ctdb_statistics)));
		      return -1;
	}

	*status = *(struct ctdb_statistics *)data.dptr;
	talloc_free(data.dptr);
			
	return 0;
}

/*
  shutdown a remote ctdb node
 */
int ctdb_ctrl_shutdown(struct ctdb_context *ctdb, struct timeval timeout, uint32_t destnode)
{
	int ret;
	int32_t res;

	ret = ctdb_control(ctdb, destnode, 0, 
			   CTDB_CONTROL_SHUTDOWN, CTDB_CTRL_FLAG_NOREPLY, tdb_null, 
			   NULL, NULL, &res, &timeout, NULL);
	if (ret != 0) {
		DEBUG(0,(__location__ " ctdb_control for shutdown failed\n"));
		return -1;
	}

	return 0;
}

/*
  get vnn map from a remote node
 */
int ctdb_ctrl_getvnnmap(struct ctdb_context *ctdb, struct timeval timeout, uint32_t destnode, TALLOC_CTX *mem_ctx, struct ctdb_vnn_map **vnnmap)
{
	int ret;
	TDB_DATA outdata;
	int32_t res;
	struct ctdb_vnn_map_wire *map;

	ret = ctdb_control(ctdb, destnode, 0, 
			   CTDB_CONTROL_GETVNNMAP, 0, tdb_null, 
			   mem_ctx, &outdata, &res, &timeout, NULL);
	if (ret != 0 || res != 0) {
		DEBUG(0,(__location__ " ctdb_control for getvnnmap failed\n"));
		return -1;
	}
	
	map = (struct ctdb_vnn_map_wire *)outdata.dptr;
	if (outdata.dsize < offsetof(struct ctdb_vnn_map_wire, map) ||
	    outdata.dsize != map->size*sizeof(uint32_t) + offsetof(struct ctdb_vnn_map_wire, map)) {
		DEBUG(0,("Bad vnn map size received in ctdb_ctrl_getvnnmap\n"));
		return -1;
	}

	(*vnnmap) = talloc(mem_ctx, struct ctdb_vnn_map);
	CTDB_NO_MEMORY(ctdb, *vnnmap);
	(*vnnmap)->generation = map->generation;
	(*vnnmap)->size       = map->size;
	(*vnnmap)->map        = talloc_array(*vnnmap, uint32_t, map->size);

	CTDB_NO_MEMORY(ctdb, (*vnnmap)->map);
	memcpy((*vnnmap)->map, map->map, sizeof(uint32_t)*map->size);
	talloc_free(outdata.dptr);
		    
	return 0;
}

/*
  get the recovery mode of a remote node
 */
int ctdb_ctrl_getrecmode(struct ctdb_context *ctdb, struct timeval timeout, uint32_t destnode, uint32_t *recmode)
{
	int ret;
	int32_t res;

	ret = ctdb_control(ctdb, destnode, 0, 
			   CTDB_CONTROL_GET_RECMODE, 0, tdb_null, 
			   NULL, NULL, &res, &timeout, NULL);
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
	TDB_DATA data;
	int32_t res;

	data.dsize = sizeof(uint32_t);
	data.dptr = (unsigned char *)&recmode;

	ret = ctdb_control(ctdb, destnode, 0, 
			   CTDB_CONTROL_SET_RECMODE, 0, data, 
			   NULL, NULL, &res, &timeout, NULL);
	if (ret != 0 || res != 0) {
		DEBUG(0,(__location__ " ctdb_control for setrecmode failed\n"));
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
	int32_t res;

	ret = ctdb_control(ctdb, destnode, 0, 
			   CTDB_CONTROL_GET_RECMASTER, 0, tdb_null, 
			   NULL, NULL, &res, &timeout, NULL);
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
	TDB_DATA data;
	int32_t res;

	ZERO_STRUCT(data);
	data.dsize = sizeof(uint32_t);
	data.dptr = (unsigned char *)&recmaster;

	ret = ctdb_control(ctdb, destnode, 0, 
			   CTDB_CONTROL_SET_RECMASTER, 0, data, 
			   NULL, NULL, &res, &timeout, NULL);
	if (ret != 0 || res != 0) {
		DEBUG(0,(__location__ " ctdb_control for setrecmaster failed\n"));
		return -1;
	}

	return 0;
}


/*
  get a list of databases off a remote node
 */
int ctdb_ctrl_getdbmap(struct ctdb_context *ctdb, struct timeval timeout, uint32_t destnode, 
		       TALLOC_CTX *mem_ctx, struct ctdb_dbid_map **dbmap)
{
	int ret;
	TDB_DATA outdata;
	int32_t res;

	ret = ctdb_control(ctdb, destnode, 0, 
			   CTDB_CONTROL_GET_DBMAP, 0, tdb_null, 
			   mem_ctx, &outdata, &res, &timeout, NULL);
	if (ret != 0 || res != 0) {
		DEBUG(0,(__location__ " ctdb_control for getdbmap failed\n"));
		return -1;
	}

	*dbmap = (struct ctdb_dbid_map *)talloc_memdup(mem_ctx, outdata.dptr, outdata.dsize);
	talloc_free(outdata.dptr);
		    
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
	TDB_DATA outdata;
	int32_t res;

	ret = ctdb_control(ctdb, destnode, 0, 
			   CTDB_CONTROL_GET_NODEMAP, 0, tdb_null, 
			   mem_ctx, &outdata, &res, &timeout, NULL);
	if (ret != 0 || res != 0) {
		DEBUG(0,(__location__ " ctdb_control for getnodes failed\n"));
		return -1;
	}

	*nodemap = (struct ctdb_node_map *)talloc_memdup(mem_ctx, outdata.dptr, outdata.dsize);
	talloc_free(outdata.dptr);
		    
	return 0;
}

/*
  set vnn map on a node
 */
int ctdb_ctrl_setvnnmap(struct ctdb_context *ctdb, struct timeval timeout, uint32_t destnode, 
			TALLOC_CTX *mem_ctx, struct ctdb_vnn_map *vnnmap)
{
	int ret;
	TDB_DATA data;
	int32_t res;
	struct ctdb_vnn_map_wire *map;
	size_t len;

	len = offsetof(struct ctdb_vnn_map_wire, map) + sizeof(uint32_t)*vnnmap->size;
	map = talloc_size(mem_ctx, len);
	CTDB_NO_MEMORY_VOID(ctdb, map);

	map->generation = vnnmap->generation;
	map->size = vnnmap->size;
	memcpy(map->map, vnnmap->map, sizeof(uint32_t)*map->size);
	
	data.dsize = len;
	data.dptr  = (uint8_t *)map;

	ret = ctdb_control(ctdb, destnode, 0, 
			   CTDB_CONTROL_SETVNNMAP, 0, data, 
			   NULL, NULL, &res, &timeout, NULL);
	if (ret != 0 || res != 0) {
		DEBUG(0,(__location__ " ctdb_control for setvnnmap failed\n"));
		return -1;
	}

	talloc_free(map);

	return 0;
}

/*
  get all keys and records for a specific database
 */
int ctdb_ctrl_pulldb(struct ctdb_context *ctdb, uint32_t destnode, uint32_t dbid, uint32_t lmaster, 
		     TALLOC_CTX *mem_ctx, struct ctdb_key_list *keys)
{
	int i, ret;
	TDB_DATA indata, outdata;
	struct ctdb_control_pulldb pull;
	struct ctdb_control_pulldb_reply *reply;
	struct ctdb_rec_data *rec;
	int32_t res;

	pull.db_id   = dbid;
	pull.lmaster = lmaster;

	indata.dsize = sizeof(struct ctdb_control_pulldb);
	indata.dptr  = (unsigned char *)&pull;

	ret = ctdb_control(ctdb, destnode, 0, 
			   CTDB_CONTROL_PULL_DB, 0, indata, 
			   mem_ctx, &outdata, &res, NULL, NULL);
	if (ret != 0 || res != 0) {
		DEBUG(0,(__location__ " ctdb_control for pulldb failed\n"));
		return -1;
	}


	reply = (struct ctdb_control_pulldb_reply *)outdata.dptr;
	keys->dbid     = reply->db_id;
	keys->num      = reply->count;
	
	keys->keys     = talloc_array(mem_ctx, TDB_DATA, keys->num);
	keys->headers  = talloc_array(mem_ctx, struct ctdb_ltdb_header, keys->num);
	keys->data     = talloc_array(mem_ctx, TDB_DATA, keys->num);

	rec = (struct ctdb_rec_data *)&reply->data[0];

	for (i=0;i<reply->count;i++) {
		keys->keys[i].dptr = talloc_memdup(mem_ctx, &rec->data[0], rec->keylen);
		keys->keys[i].dsize = rec->keylen;
		
		keys->data[i].dptr = talloc_memdup(mem_ctx, &rec->data[keys->keys[i].dsize], rec->datalen);
		keys->data[i].dsize = rec->datalen;

		if (keys->data[i].dsize < sizeof(struct ctdb_ltdb_header)) {
			DEBUG(0,(__location__ " bad ltdb record\n"));
			return -1;
		}
		memcpy(&keys->headers[i], keys->data[i].dptr, sizeof(struct ctdb_ltdb_header));
		keys->data[i].dptr += sizeof(struct ctdb_ltdb_header);
		keys->data[i].dsize -= sizeof(struct ctdb_ltdb_header);

		rec = (struct ctdb_rec_data *)(rec->length + (uint8_t *)rec);
	}	    

	talloc_free(outdata.dptr);

	return 0;
}

/*
  copy a tdb from one node to another node
 */
int ctdb_ctrl_copydb(struct ctdb_context *ctdb, struct timeval timeout, uint32_t sourcenode, 
		     uint32_t destnode, uint32_t dbid, uint32_t lmaster, TALLOC_CTX *mem_ctx)
{
	int ret;
	TDB_DATA indata, outdata;
	int32_t res;

	indata.dsize = 2*sizeof(uint32_t);
	indata.dptr  = (unsigned char *)talloc_array(mem_ctx, uint32_t, 2);

	((uint32_t *)(&indata.dptr[0]))[0] = dbid;
	((uint32_t *)(&indata.dptr[0]))[1] = lmaster;

	DEBUG(3,("pulling dbid 0x%x from %u\n", dbid, sourcenode));

	ret = ctdb_control(ctdb, sourcenode, 0, 
			   CTDB_CONTROL_PULL_DB, 0, indata, 
			   mem_ctx, &outdata, &res, &timeout, NULL);
	if (ret != 0 || res != 0) {
		DEBUG(0,(__location__ " ctdb_control for pulldb failed\n"));
		return -1;
	}

	DEBUG(3,("pushing dbid 0x%x to %u\n", dbid, destnode));

	ret = ctdb_control(ctdb, destnode, 0, 
			   CTDB_CONTROL_PUSH_DB, 0, outdata, 
			   mem_ctx, NULL, &res, &timeout, NULL);
	talloc_free(outdata.dptr);
	if (ret != 0 || res != 0) {
		DEBUG(0,(__location__ " ctdb_control for pushdb failed\n"));
		return -1;
	}

	DEBUG(3,("copydb for dbid 0x%x done for %u to %u\n", 
		 dbid, sourcenode, destnode));

	return 0;
}

/*
  change dmaster for all keys in the database to the new value
 */
int ctdb_ctrl_setdmaster(struct ctdb_context *ctdb, struct timeval timeout, uint32_t destnode, 
			 TALLOC_CTX *mem_ctx, uint32_t dbid, uint32_t dmaster)
{
	int ret;
	TDB_DATA indata;
	int32_t res;

	indata.dsize = 2*sizeof(uint32_t);
	indata.dptr = (unsigned char *)talloc_array(mem_ctx, uint32_t, 2);

	((uint32_t *)(&indata.dptr[0]))[0] = dbid;
	((uint32_t *)(&indata.dptr[0]))[1] = dmaster;

	ret = ctdb_control(ctdb, destnode, 0, 
			   CTDB_CONTROL_SET_DMASTER, 0, indata, 
			   NULL, NULL, &res, &timeout, NULL);
	if (ret != 0 || res != 0) {
		DEBUG(0,(__location__ " ctdb_control for setdmaster failed\n"));
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

	ret = ctdb_control(ctdb, destnode, 0, CTDB_CONTROL_PING, 0, 
			   tdb_null, NULL, NULL, &res, NULL, NULL);
	if (ret != 0) {
		return -1;
	}
	return res;
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
			   mem_ctx, &data, &res, &timeout, NULL);
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
			   mem_ctx, &data, &res, &timeout, NULL);
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
			   mem_ctx, &data, &res, &timeout, NULL);

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

	ret = ctdb_control(ctdb, destnode, 0, CTDB_CONTROL_GET_DEBUG, 0, tdb_null, 
			   ctdb, &data, &res, NULL, NULL);
	if (ret != 0 || res != 0) {
		return -1;
	}
	if (data.dsize != sizeof(uint32_t)) {
		DEBUG(0,("Bad control reply size in ctdb_get_debuglevel (got %u)\n",
			 (unsigned)data.dsize));
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
			   NULL, NULL, &res, NULL, NULL);
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
		if (!(map->nodes[i].flags & NODE_FLAGS_DISCONNECTED)) {
			nodes[*num_nodes] = map->nodes[i].vnn;
			(*num_nodes)++;
		}
	}

	return nodes;
}


/*
  reset remote status
 */
int ctdb_statistics_reset(struct ctdb_context *ctdb, uint32_t destnode)
{
	int ret;
	int32_t res;

	ret = ctdb_control(ctdb, destnode, 0, 
			   CTDB_CONTROL_STATISTICS_RESET, 0, tdb_null, 
			   NULL, NULL, &res, NULL, NULL);
	if (ret != 0 || res != 0) {
		DEBUG(0,(__location__ " ctdb_control for reset statistics failed\n"));
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

	ctdb_db = ctdb_db_handle(ctdb, name);
	if (ctdb_db) {
		return ctdb_db;
	}

	ctdb_db = talloc_zero(ctdb, struct ctdb_db_context);
	CTDB_NO_MEMORY_NULL(ctdb, ctdb_db);

	ctdb_db->ctdb = ctdb;
	ctdb_db->db_name = talloc_strdup(ctdb_db, name);
	CTDB_NO_MEMORY_NULL(ctdb, ctdb_db->db_name);

	data.dptr = discard_const(name);
	data.dsize = strlen(name)+1;

	/* tell ctdb daemon to attach */
	ret = ctdb_control(ctdb, CTDB_CURRENT_NODE, 0, CTDB_CONTROL_DB_ATTACH,
			   0, data, ctdb_db, &data, &res, NULL, NULL);
	if (ret != 0 || res != 0 || data.dsize != sizeof(uint32_t)) {
		DEBUG(0,("Failed to attach to database '%s'\n", name));
		talloc_free(ctdb_db);
		return NULL;
	}
	
	ctdb_db->db_id = *(uint32_t *)data.dptr;
	talloc_free(data.dptr);

	ret = ctdb_ctrl_getdbpath(ctdb, timeval_current_ofs(2, 0), CTDB_CURRENT_NODE, ctdb_db->db_id, ctdb_db, &ctdb_db->db_path);
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
			   data, NULL, NULL, &status, NULL, NULL);
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
	struct ctdb_rec_data *d = (struct ctdb_rec_data *)data.dptr;
	TDB_DATA key;

	if (data.dsize < sizeof(uint32_t) ||
	    d->length != data.dsize) {
		DEBUG(0,("Bad data size %u in traverse_handler\n", (unsigned)data.dsize));
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
			   data, NULL, NULL, &status, NULL, NULL);
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

	keystr  = hex_encode_talloc(ctdb, key.dptr, key.dsize);
	datastr = hex_encode_talloc(ctdb, data.dptr+sizeof(*h), data.dsize-sizeof(*h));

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
	int32_t res;

	ret = ctdb_control(ctdb, destnode, 0, 
			   CTDB_CONTROL_GET_PID, 0, tdb_null, 
			   NULL, NULL, &res, &timeout, NULL);
	if (ret != 0) {
		DEBUG(0,(__location__ " ctdb_control for getpid failed\n"));
		return -1;
	}

	*pid = res;

	return 0;
}


/*
  freeze a node
 */
int ctdb_ctrl_freeze(struct ctdb_context *ctdb, struct timeval timeout, uint32_t destnode)
{
	int ret;
	int32_t res;

	ret = ctdb_control(ctdb, destnode, 0, 
			   CTDB_CONTROL_FREEZE, 0, tdb_null, 
			   NULL, NULL, &res, &timeout, NULL);
	if (ret != 0 || res != 0) {
		DEBUG(0,(__location__ " ctdb_control freeze failed\n"));
		return -1;
	}

	return 0;
}

/*
  thaw a node
 */
int ctdb_ctrl_thaw(struct ctdb_context *ctdb, struct timeval timeout, uint32_t destnode)
{
	int ret;
	int32_t res;

	ret = ctdb_control(ctdb, destnode, 0, 
			   CTDB_CONTROL_THAW, 0, tdb_null, 
			   NULL, NULL, &res, &timeout, NULL);
	if (ret != 0 || res != 0) {
		DEBUG(0,(__location__ " ctdb_control thaw failed\n"));
		return -1;
	}

	return 0;
}

/*
  get vnn of a node, or -1
 */
int ctdb_ctrl_getvnn(struct ctdb_context *ctdb, struct timeval timeout, uint32_t destnode)
{
	int ret;
	int32_t res;

	ret = ctdb_control(ctdb, destnode, 0, 
			   CTDB_CONTROL_GET_VNN, 0, tdb_null, 
			   NULL, NULL, &res, &timeout, NULL);
	if (ret != 0) {
		DEBUG(0,(__location__ " ctdb_control for getvnn failed\n"));
		return -1;
	}

	return res;
}

/*
  set the monitoring mode of a remote node
 */
int ctdb_ctrl_setmonmode(struct ctdb_context *ctdb, struct timeval timeout, uint32_t destnode, uint32_t monmode)
{
	int ret;
	TDB_DATA data;
	int32_t res;

	data.dsize = sizeof(uint32_t);
	data.dptr = (uint8_t *)&monmode;

	ret = ctdb_control(ctdb, destnode, 0, 
			   CTDB_CONTROL_SET_MONMODE, 0, data, 
			   NULL, NULL, &res, &timeout, NULL);
	if (ret != 0 || res != 0) {
		DEBUG(0,(__location__ " ctdb_control for setmonmode failed\n"));
		return -1;
	}

	return 0;
}

/*
  get the monitoring mode of a remote node
 */
int ctdb_ctrl_getmonmode(struct ctdb_context *ctdb, struct timeval timeout, uint32_t destnode, uint32_t *monmode)
{
	int ret;
	int32_t res;

	ret = ctdb_control(ctdb, destnode, 0, 
			   CTDB_CONTROL_GET_MONMODE, 0, tdb_null, 
			   NULL, NULL, &res, &timeout, NULL);
	if (ret != 0) {
		DEBUG(0,(__location__ " ctdb_control for getrecmode failed\n"));
		return -1;
	}

	*monmode = res;

	return 0;
}


/*
  get maximum rsn for a db on a node
 */
int ctdb_ctrl_get_max_rsn(struct ctdb_context *ctdb, struct timeval timeout, 
			  uint32_t destnode, uint32_t db_id, uint64_t *max_rsn)
{
	TDB_DATA data, outdata;
	int ret;
	int32_t res;

	data.dptr = (uint8_t *)&db_id;
	data.dsize = sizeof(db_id);

	ret = ctdb_control(ctdb, destnode, 0, CTDB_CONTROL_MAX_RSN, 0, data, ctdb,
			   &outdata, &res, &timeout, NULL);
	if (ret != 0 || res != 0 || outdata.dsize != sizeof(uint64_t)) {
		DEBUG(0,(__location__ " ctdb_control for get_max_rsn failed\n"));
		return -1;
	}

	*max_rsn = *(uint64_t *)outdata.dptr;
	talloc_free(outdata.dptr);

	return 0;	
}

/*
  set the rsn on non-empty records to the given rsn
 */
int ctdb_ctrl_set_rsn_nonempty(struct ctdb_context *ctdb, struct timeval timeout, 
			       uint32_t destnode, uint32_t db_id, uint64_t rsn)
{
	TDB_DATA data;
	int ret;
	int32_t res;
	struct ctdb_control_set_rsn_nonempty p;

	p.db_id = db_id;
	p.rsn = rsn;

	data.dptr = (uint8_t *)&p;
	data.dsize = sizeof(p);

	ret = ctdb_control(ctdb, destnode, 0, CTDB_CONTROL_SET_RSN_NONEMPTY, 0, data, NULL,
			   NULL, &res, &timeout, NULL);
	if (ret != 0 || res != 0) {
		DEBUG(0,(__location__ " ctdb_control for set_rsn_nonempty failed\n"));
		return -1;
	}

	return 0;	
}

/*
  delete records which have a rsn below the given rsn
 */
int ctdb_ctrl_delete_low_rsn(struct ctdb_context *ctdb, struct timeval timeout, 
			     uint32_t destnode, uint32_t db_id, uint64_t rsn)
{
	TDB_DATA data;
	int ret;
	int32_t res;
	struct ctdb_control_delete_low_rsn p;

	p.db_id = db_id;
	p.rsn = rsn;

	data.dptr = (uint8_t *)&p;
	data.dsize = sizeof(p);

	ret = ctdb_control(ctdb, destnode, 0, CTDB_CONTROL_DELETE_LOW_RSN, 0, data, NULL,
			   NULL, &res, &timeout, NULL);
	if (ret != 0 || res != 0) {
		DEBUG(0,(__location__ " ctdb_control for delete_low_rsn failed\n"));
		return -1;
	}

	return 0;	
}

/* 
  sent to a node to make it take over an ip address
*/
int ctdb_ctrl_takeover_ip(struct ctdb_context *ctdb, struct timeval timeout, 
			  uint32_t destnode, struct ctdb_public_ip *ip)
{
	TDB_DATA data;
	int ret;
	int32_t res;

	data.dsize = sizeof(*ip);
	data.dptr  = (uint8_t *)ip;

	ret = ctdb_control(ctdb, destnode, 0, CTDB_CONTROL_TAKEOVER_IP, 0, data, NULL,
			   NULL, &res, &timeout, NULL);

	if (ret != 0 || res != 0) {
		DEBUG(0,(__location__ " ctdb_control for takeover_ip failed\n"));
		return -1;
	}

	return 0;	
}


/* 
  sent to a node to make it release an ip address
*/
int ctdb_ctrl_release_ip(struct ctdb_context *ctdb, struct timeval timeout, 
			 uint32_t destnode, struct ctdb_public_ip *ip)
{
	TDB_DATA data;
	int ret;
	int32_t res;

	data.dsize = sizeof(*ip);
	data.dptr  = (uint8_t *)ip;

	ret = ctdb_control(ctdb, destnode, 0, CTDB_CONTROL_RELEASE_IP, 0, data, NULL,
			   NULL, &res, &timeout, NULL);

	if (ret != 0 || res != 0) {
		DEBUG(0,(__location__ " ctdb_control for release_ip failed\n"));
		return -1;
	}

	return 0;	
}


/*
  get a tunable
 */
int ctdb_ctrl_get_tunable(struct ctdb_context *ctdb, 
			  struct timeval timeout, 
			  uint32_t destnode,
			  const char *name, uint32_t *value)
{
	struct ctdb_control_get_tunable *t;
	TDB_DATA data, outdata;
	int32_t res;
	int ret;

	data.dsize = offsetof(struct ctdb_control_get_tunable, name) + strlen(name) + 1;
	data.dptr  = talloc_size(ctdb, data.dsize);
	CTDB_NO_MEMORY(ctdb, data.dptr);

	t = (struct ctdb_control_get_tunable *)data.dptr;
	t->length = strlen(name)+1;
	memcpy(t->name, name, t->length);

	ret = ctdb_control(ctdb, destnode, 0, CTDB_CONTROL_GET_TUNABLE, 0, data, ctdb,
			   &outdata, &res, &timeout, NULL);
	talloc_free(data.dptr);
	if (ret != 0 || res != 0) {
		DEBUG(0,(__location__ " ctdb_control for get_tunable failed\n"));
		return -1;
	}

	if (outdata.dsize != sizeof(uint32_t)) {
		DEBUG(0,("Invalid return data in get_tunable\n"));
		talloc_free(outdata.dptr);
		return -1;
	}
	
	*value = *(uint32_t *)outdata.dptr;
	talloc_free(outdata.dptr);

	return 0;
}

/*
  set a tunable
 */
int ctdb_ctrl_set_tunable(struct ctdb_context *ctdb, 
			  struct timeval timeout, 
			  uint32_t destnode,
			  const char *name, uint32_t value)
{
	struct ctdb_control_set_tunable *t;
	TDB_DATA data;
	int32_t res;
	int ret;

	data.dsize = offsetof(struct ctdb_control_set_tunable, name) + strlen(name) + 1;
	data.dptr  = talloc_size(ctdb, data.dsize);
	CTDB_NO_MEMORY(ctdb, data.dptr);

	t = (struct ctdb_control_set_tunable *)data.dptr;
	t->length = strlen(name)+1;
	memcpy(t->name, name, t->length);
	t->value = value;

	ret = ctdb_control(ctdb, destnode, 0, CTDB_CONTROL_SET_TUNABLE, 0, data, NULL,
			   NULL, &res, &timeout, NULL);
	talloc_free(data.dptr);
	if (ret != 0 || res != 0) {
		DEBUG(0,(__location__ " ctdb_control for set_tunable failed\n"));
		return -1;
	}

	return 0;
}

/*
  list tunables
 */
int ctdb_ctrl_list_tunables(struct ctdb_context *ctdb, 
			    struct timeval timeout, 
			    uint32_t destnode,
			    TALLOC_CTX *mem_ctx,
			    const char ***list, uint32_t *count)
{
	TDB_DATA outdata;
	int32_t res;
	int ret;
	struct ctdb_control_list_tunable *t;
	char *p, *s, *ptr;

	ret = ctdb_control(ctdb, destnode, 0, CTDB_CONTROL_LIST_TUNABLES, 0, tdb_null, 
			   mem_ctx, &outdata, &res, &timeout, NULL);
	if (ret != 0 || res != 0) {
		DEBUG(0,(__location__ " ctdb_control for list_tunables failed\n"));
		return -1;
	}

	t = (struct ctdb_control_list_tunable *)outdata.dptr;
	if (outdata.dsize < offsetof(struct ctdb_control_list_tunable, data) ||
	    t->length > outdata.dsize-offsetof(struct ctdb_control_list_tunable, data)) {
		DEBUG(0,("Invalid data in list_tunables reply\n"));
		talloc_free(outdata.dptr);
		return -1;		
	}
	
	p = talloc_strndup(mem_ctx, (char *)t->data, t->length);
	CTDB_NO_MEMORY(ctdb, p);

	talloc_free(outdata.dptr);
	
	(*list) = NULL;
	(*count) = 0;

	for (s=strtok_r(p, ":", &ptr); s; s=strtok_r(NULL, ":", &ptr)) {
		(*list) = talloc_realloc(mem_ctx, *list, const char *, 1+(*count));
		CTDB_NO_MEMORY(ctdb, *list);
		(*list)[*count] = talloc_strdup(*list, s);
		CTDB_NO_MEMORY(ctdb, (*list)[*count]);
		(*count)++;
	}

	talloc_free(p);

	return 0;
}


int ctdb_ctrl_get_public_ips(struct ctdb_context *ctdb, 
			struct timeval timeout, uint32_t destnode, 
			TALLOC_CTX *mem_ctx, struct ctdb_all_public_ips **ips)
{
	int ret;
	TDB_DATA outdata;
	int32_t res;

	ret = ctdb_control(ctdb, destnode, 0, 
			   CTDB_CONTROL_GET_PUBLIC_IPS, 0, tdb_null, 
			   mem_ctx, &outdata, &res, &timeout, NULL);
	if (ret != 0 || res != 0) {
		DEBUG(0,(__location__ " ctdb_control for getpublicips failed\n"));
		return -1;
	}

	*ips = (struct ctdb_all_public_ips *)talloc_memdup(mem_ctx, outdata.dptr, outdata.dsize);
	talloc_free(outdata.dptr);
		    
	return 0;
}

/*
  set/clear the permanent disabled bit on a remote node
 */
int ctdb_ctrl_modflags(struct ctdb_context *ctdb, struct timeval timeout, uint32_t destnode, 
		       uint32_t set, uint32_t clear)
{
	int ret;
	TDB_DATA data;
	struct ctdb_node_modflags m;
	int32_t res;

	m.set = set;
	m.clear = clear;

	data.dsize = sizeof(m);
	data.dptr = (unsigned char *)&m;

	ret = ctdb_control(ctdb, destnode, 0, 
			   CTDB_CONTROL_MODIFY_FLAGS, 0, data, 
			   NULL, NULL, &res, &timeout, NULL);
	if (ret != 0 || res != 0) {
		DEBUG(0,(__location__ " ctdb_control for modflags failed\n"));
		return -1;
	}

	return 0;
}


/*
  get all tunables
 */
int ctdb_ctrl_get_all_tunables(struct ctdb_context *ctdb, 
			       struct timeval timeout, 
			       uint32_t destnode,
			       struct ctdb_tunable *tunables)
{
	TDB_DATA outdata;
	int ret;
	int32_t res;

	ret = ctdb_control(ctdb, destnode, 0, CTDB_CONTROL_GET_ALL_TUNABLES, 0, tdb_null, ctdb,
			   &outdata, &res, &timeout, NULL);
	if (ret != 0 || res != 0) {
		DEBUG(0,(__location__ " ctdb_control for get all tunables failed\n"));
		return -1;
	}

	if (outdata.dsize != sizeof(*tunables)) {
		DEBUG(0,(__location__ " bad data size %u in ctdb_ctrl_get_all_tunables should be %u\n",
			 (unsigned)outdata.dsize, (unsigned)sizeof(*tunables)));
		return -1;		
	}

	*tunables = *(struct ctdb_tunable *)outdata.dptr;
	talloc_free(outdata.dptr);
	return 0;
}


/*
  kill a tcp connection
 */
int ctdb_ctrl_killtcp(struct ctdb_context *ctdb, 
		      struct timeval timeout, 
		      uint32_t destnode,
		      struct ctdb_control_killtcp *killtcp)
{
	TDB_DATA data;
	int32_t res;
	int ret;

	data.dsize = sizeof(struct ctdb_control_killtcp);
	data.dptr  = (unsigned char *)killtcp;

	ret = ctdb_control(ctdb, destnode, 0, CTDB_CONTROL_KILL_TCP, 0, data, NULL,
			   NULL, &res, &timeout, NULL);
	if (ret != 0 || res != 0) {
		DEBUG(0,(__location__ " ctdb_control for killtcp failed\n"));
		return -1;
	}

	return 0;
}

/*
  get a list of all tcp tickles that a node knows about for a particular vnn
 */
int ctdb_ctrl_get_tcp_tickles(struct ctdb_context *ctdb, 
			      struct timeval timeout, uint32_t destnode, 
			      TALLOC_CTX *mem_ctx, uint32_t vnn,
			      struct ctdb_control_tcp_tickle_list **list)
{
	int ret;
	TDB_DATA data, outdata;
	int32_t status;

	data.dptr = (uint8_t*)&vnn;
	data.dsize = sizeof(vnn);

	ret = ctdb_control(ctdb, destnode, 0, 
			   CTDB_CONTROL_GET_TCP_TICKLE_LIST, 0, data, 
			   mem_ctx, &outdata, &status, NULL, NULL);
	if (ret != 0) {
		DEBUG(0,(__location__ " ctdb_control for get tcp tickles failed\n"));
		return -1;
	}

	*list = (struct ctdb_control_tcp_tickle_list *)outdata.dptr;

	return status;
}

/*
  initialise the ctdb daemon for client applications

  NOTE: In current code the daemon does not fork. This is for testing purposes only
  and to simplify the code.
*/
struct ctdb_context *ctdb_init(struct event_context *ev)
{
	struct ctdb_context *ctdb;

	ctdb = talloc_zero(ev, struct ctdb_context);
	ctdb->ev  = ev;
	ctdb->idr = idr_init(ctdb);
	CTDB_NO_MEMORY_NULL(ctdb, ctdb->idr);

	ctdb_set_socketname(ctdb, CTDB_PATH);

	return ctdb;
}


/*
  set some ctdb flags
*/
void ctdb_set_flags(struct ctdb_context *ctdb, unsigned flags)
{
	ctdb->flags |= flags;
}

/*
  setup the local socket name
*/
int ctdb_set_socketname(struct ctdb_context *ctdb, const char *socketname)
{
	ctdb->daemon.name = talloc_strdup(ctdb, socketname);
	return 0;
}

/*
  return the vnn of this node
*/
uint32_t ctdb_get_vnn(struct ctdb_context *ctdb)
{
	return ctdb->vnn;
}

