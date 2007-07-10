/* 
   ctdb daemon code

   Copyright (C) Andrew Tridgell  2007
   Copyright (C) Ronnie Sahlberg  2007

   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 3 of the License, or (at your option) any later version.

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

	state = idr_find_type(ctdb->idr, hdr->reqid, struct ctdb_client_call_state);
	if (state == NULL) {
		DEBUG(0, ("reqid %d not found\n", hdr->reqid));
		return;
	}

	state->call.reply_data.dptr = c->data;
	state->call.reply_data.dsize = c->datalen;
	state->call.status = c->status;

	talloc_steal(state, c);

	state->state = CTDB_CALL_DONE;
}

static void ctdb_reply_status(struct ctdb_context *ctdb, struct ctdb_req_header *hdr);

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

	case CTDB_REPLY_STATUS:
		ctdb_reply_status(ctdb, hdr);
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
	idr_remove(state->ctdb_db->ctdb->idr, state->reqid);
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
	c->hdr.reqid     = idr_get_new(ctdb->idr, state, 0xFFFF);
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
int ctdb_set_message_handler(struct ctdb_context *ctdb, uint32_t srvid, 
			     ctdb_message_fn_t handler,
			     void *private_data)
				    
{
	struct ctdb_req_register c;
	int res;

	/* if the domain socket is not yet open, open it */
	if (ctdb->daemon.sd==-1) {
		ctdb_socket_connect(ctdb);
	}

	ZERO_STRUCT(c);

	c.hdr.length       = sizeof(c);
	c.hdr.ctdb_magic   = CTDB_MAGIC;
	c.hdr.ctdb_version = CTDB_VERSION;
	c.hdr.operation    = CTDB_REQ_REGISTER;
	c.srvid            = srvid;

	res = ctdb_client_queue_pkt(ctdb, &c.hdr);
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
		      uint32_t srvid, TDB_DATA data)
{
	struct ctdb_req_message *r;
	int len, res;

	len = offsetof(struct ctdb_req_message, data) + data.dsize;
	r = ctdb->methods->allocate_pkt(ctdb, len);
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
	struct ctdb_req_connect_wait r;
	int res;

	ZERO_STRUCT(r);

	r.hdr.length     = sizeof(r);
	r.hdr.ctdb_magic = CTDB_MAGIC;
	r.hdr.ctdb_version = CTDB_VERSION;
	r.hdr.operation = CTDB_REQ_CONNECT_WAIT;

	DEBUG(3,("ctdb_connect_wait: sending to ctdbd\n"));

	/* if the domain socket is not yet open, open it */
	if (ctdb->daemon.sd==-1) {
		ctdb_socket_connect(ctdb);
	}
	
	res = ctdb_queue_send(ctdb->daemon.queue, (uint8_t *)&r.hdr, r.hdr.length);
	if (res != 0) {
		DEBUG(0,(__location__ " Failed to queue a connect wait request\n"));
		return;
	}

	DEBUG(3,("ctdb_connect_wait: waiting\n"));

	/* now we can go into the normal wait routine, as the reply packet
	   will update the ctdb->num_connected variable */
	ctdb_daemon_connect_wait(ctdb);
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
	struct ctdb_req_shutdown r;
	int len;

	/* if the domain socket is not yet open, open it */
	if (ctdb->daemon.sd==-1) {
		ctdb_socket_connect(ctdb);
	}

	len = sizeof(struct ctdb_req_shutdown);
	ZERO_STRUCT(r);
	r.hdr.length       = len;
	r.hdr.ctdb_magic   = CTDB_MAGIC;
	r.hdr.ctdb_version = CTDB_VERSION;
	r.hdr.operation    = CTDB_REQ_SHUTDOWN;
	r.hdr.reqid        = 0;

	ctdb_client_queue_pkt(ctdb, &(r.hdr));

	/* this event loop will terminate once we receive the reply */
	while (1) {
		event_loop_once(ctdb->ev);
	}
}

enum ctdb_status_states {CTDB_STATUS_WAIT, CTDB_STATUS_DONE};

struct ctdb_status_state {
	uint32_t reqid;
	struct ctdb_status *status;
	enum ctdb_status_states state;
};

/*
  handle a ctdb_reply_status reply
 */
static void ctdb_reply_status(struct ctdb_context *ctdb, struct ctdb_req_header *hdr)
{
	struct ctdb_reply_status *r = (struct ctdb_reply_status *)hdr;
	struct ctdb_status_state *state;

	state = idr_find_type(ctdb->idr, hdr->reqid, struct ctdb_status_state);
	if (state == NULL) {
		DEBUG(0, ("reqid %d not found\n", hdr->reqid));
		return;
	}

	*state->status = r->status;
	state->state = CTDB_STATUS_DONE;
}

/*
  wait until we're the only node left.
  this function never returns
*/
int ctdb_status(struct ctdb_context *ctdb, struct ctdb_status *status)
{
	struct ctdb_req_status r;
	int ret;
	struct ctdb_status_state *state;

	/* if the domain socket is not yet open, open it */
	if (ctdb->daemon.sd==-1) {
		ctdb_socket_connect(ctdb);
	}

	state = talloc(ctdb, struct ctdb_status_state);
	CTDB_NO_MEMORY(ctdb, state);

	state->reqid = idr_get_new(ctdb->idr, state, 0xFFFF);
	state->status = status;
	state->state = CTDB_STATUS_WAIT;
	
	ZERO_STRUCT(r);
	r.hdr.length       = sizeof(r);
	r.hdr.ctdb_magic   = CTDB_MAGIC;
	r.hdr.ctdb_version = CTDB_VERSION;
	r.hdr.operation    = CTDB_REQ_STATUS;
	r.hdr.reqid        = state->reqid;

	ret = ctdb_client_queue_pkt(ctdb, &(r.hdr));
	if (ret != 0) {
		talloc_free(state);
		return -1;
	}
	
	while (state->state == CTDB_STATUS_WAIT) {
		event_loop_once(ctdb->ev);
	}

	talloc_free(state);

	return 0;
}

