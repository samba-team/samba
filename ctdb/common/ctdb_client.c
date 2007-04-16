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
	ctdb->num_connected = r->num_connected;
}

/*
  called in the client when we receive a CTDB_REPLY_FETCH_LOCK from the daemon

  This packet comes in response to a CTDB_REQ_FETCH_LOCK request packet. It
  contains any reply data from the call
*/
void ctdb_reply_fetch_lock(struct ctdb_context *ctdb, struct ctdb_req_header *hdr)
{
	struct ctdb_reply_fetch_lock *c = (struct ctdb_reply_fetch_lock *)hdr;
	struct ctdb_call_state *state;

	state = idr_find(ctdb->idr, hdr->reqid);
	if (state == NULL) return;

	state->call.reply_data.dptr = c->data;
	state->call.reply_data.dsize = c->datalen;
	state->call.status = c->state;

	talloc_steal(state, c);

	/* get an extra reference here - this prevents the free in ctdb_recv_pkt()
	   from freeing the data */
	(void)talloc_reference(state, c);

	state->state = CTDB_CALL_DONE;
	if (state->async.fn) {
		state->async.fn(state);
	}
}

/*
  called in the client when we receive a CTDB_REPLY_STORE_UNLOCK from the daemon

  This packet comes in response to a CTDB_REQ_STORE_UNLOCK request packet. It
  contains any reply data from the call
*/
void ctdb_reply_store_unlock(struct ctdb_context *ctdb, struct ctdb_req_header *hdr)
{
	struct ctdb_reply_store_unlock *c = (struct ctdb_reply_store_unlock *)hdr;
	struct ctdb_call_state *state;

	state = idr_find(ctdb->idr, hdr->reqid);
	if (state == NULL) return;

	state->call.status = c->state;

	talloc_steal(state, c);

	/* get an extra reference here - this prevents the free in ctdb_recv_pkt()
	   from freeing the data */
	(void)talloc_reference(state, c);

	state->state = CTDB_CALL_DONE;
	if (state->async.fn) {
		state->async.fn(state);
	}
}
/*
  this is called in the client, when data comes in from the daemon
 */
static void ctdb_client_read_cb(uint8_t *data, size_t cnt, void *args)
{
	struct ctdb_context *ctdb = talloc_get_type(args, struct ctdb_context);
	struct ctdb_req_header *hdr;

	if (cnt < sizeof(*hdr)) {
		ctdb_set_error(ctdb, "Bad packet length %d\n", cnt);
		return;
	}
	hdr = (struct ctdb_req_header *)data;
	if (cnt != hdr->length) {
		ctdb_set_error(ctdb, "Bad header length %d expected %d\n", 
			       hdr->length, cnt);
		return;
	}

	if (hdr->ctdb_magic != CTDB_MAGIC) {
		ctdb_set_error(ctdb, "Non CTDB packet rejected\n");
		return;
	}

	if (hdr->ctdb_version != CTDB_VERSION) {
		ctdb_set_error(ctdb, "Bad CTDB version 0x%x rejected\n", hdr->ctdb_version);
		return;
	}

	switch (hdr->operation) {
	case CTDB_REPLY_CALL:
		ctdb_reply_call(ctdb, hdr);
		break;

	case CTDB_REQ_MESSAGE:
		ctdb_request_message(ctdb, hdr);
		break;

	case CTDB_REPLY_CONNECT_WAIT:
		ctdb_reply_connect_wait(ctdb, hdr);
		break;

	case CTDB_REPLY_FETCH_LOCK:
		ctdb_reply_fetch_lock(ctdb, hdr);
		break;

	case CTDB_REPLY_STORE_UNLOCK:
		ctdb_reply_store_unlock(ctdb, hdr);
		break;

	default:
		printf("bogus operation code:%d\n",hdr->operation);
	}
}

/*
  connect to a unix domain socket
*/
static int ux_socket_connect(struct ctdb_context *ctdb)
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



/*
  make a recv call to the local ctdb daemon - called from client context

  This is called when the program wants to wait for a ctdb_call to complete and get the 
  results. This call will block unless the call has already completed.
*/
int ctdb_client_call_recv(struct ctdb_call_state *state, struct ctdb_call *call)
{
	struct ctdb_record_handle *rec;

	while (state->state < CTDB_CALL_DONE) {
		event_loop_once(state->node->ctdb->ev);
	}
	if (state->state != CTDB_CALL_DONE) {
		ctdb_set_error(state->node->ctdb, "%s", state->errmsg);
		talloc_free(state);
		return -1;
	}

	rec = state->fetch_private;

	/* ugly hack to manage forced migration */
	if (rec != NULL) {
		rec->data->dptr = talloc_steal(rec, state->call.reply_data.dptr);
		rec->data->dsize = state->call.reply_data.dsize;
		talloc_free(state);
		return 0;
	}

	if (state->call.reply_data.dsize) {
		call->reply_data.dptr = talloc_memdup(state->node->ctdb,
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
static int ctdb_client_call_destructor(struct ctdb_call_state *state)	
{
	idr_remove(state->node->ctdb->idr, state->c->hdr.reqid);
	return 0;
}



/*
  make a ctdb call to the local daemon - async send. Called from client context.

  This constructs a ctdb_call request and queues it for processing. 
  This call never blocks.
*/
struct ctdb_call_state *ctdb_client_call_send(struct ctdb_db_context *ctdb_db, 
					      struct ctdb_call *call)
{
	struct ctdb_call_state *state;
	struct ctdb_context *ctdb = ctdb_db->ctdb;
	struct ctdb_ltdb_header header;
	TDB_DATA data;
	int ret;
	size_t len;

	/* if the domain socket is not yet open, open it */
	if (ctdb->daemon.sd==-1) {
		ux_socket_connect(ctdb);
	}

	ret = ctdb_ltdb_lock(ctdb_db, call->key);
	if (ret != 0) {
		printf("failed to lock ltdb record\n");
		return NULL;
	}

	ret = ctdb_ltdb_fetch(ctdb_db, call->key, &header, ctdb_db, &data);
	if (ret != 0) {
		ctdb_ltdb_unlock(ctdb_db, call->key);
		return NULL;
	}

#if 0
	if (header.dmaster == ctdb->vnn && !(ctdb->flags & CTDB_FLAG_SELF_CONNECT)) {
		state = ctdb_call_local_send(ctdb_db, call, &header, &data);
		ctdb_ltdb_unlock(ctdb_db, call->key);
		return state;
	}
#endif

	state = talloc_zero(ctdb_db, struct ctdb_call_state);
	if (state == NULL) {
		printf("failed to allocate state\n");
		ctdb_ltdb_unlock(ctdb_db, call->key);
		return NULL;
	}

	talloc_steal(state, data.dptr);

	len = offsetof(struct ctdb_req_call, data) + call->key.dsize + call->call_data.dsize;
	state->c = ctdbd_allocate_pkt(ctdb, len);
	if (state->c == NULL) {
		printf("failed to allocate packet\n");
		ctdb_ltdb_unlock(ctdb_db, call->key);
		return NULL;
	}
	talloc_set_name_const(state->c, "ctdbd req_call packet");
	talloc_steal(state, state->c);

	state->c->hdr.length    = len;
	state->c->hdr.ctdb_magic = CTDB_MAGIC;
	state->c->hdr.ctdb_version = CTDB_VERSION;
	state->c->hdr.operation = CTDB_REQ_CALL;
	state->c->hdr.destnode  = header.dmaster;
	state->c->hdr.srcnode   = ctdb->vnn;
	/* this limits us to 16k outstanding messages - not unreasonable */
	state->c->hdr.reqid     = idr_get_new(ctdb->idr, state, 0xFFFF);
	state->c->flags         = call->flags;
	state->c->db_id         = ctdb_db->db_id;
	state->c->callid        = call->call_id;
	state->c->keylen        = call->key.dsize;
	state->c->calldatalen   = call->call_data.dsize;
	memcpy(&state->c->data[0], call->key.dptr, call->key.dsize);
	memcpy(&state->c->data[call->key.dsize], 
	       call->call_data.dptr, call->call_data.dsize);
	state->call                = *call;
	state->call.call_data.dptr = &state->c->data[call->key.dsize];
	state->call.key.dptr       = &state->c->data[0];

	state->node   = ctdb->nodes[header.dmaster];
	state->state  = CTDB_CALL_WAIT;
	state->header = header;
	state->ctdb_db = ctdb_db;

	talloc_set_destructor(state, ctdb_client_call_destructor);

	ctdb_client_queue_pkt(ctdb, &state->c->hdr);

/*XXX set up timeout to cleanup if server doesnt respond
	event_add_timed(ctdb->ev, state, timeval_current_ofs(CTDB_REQ_TIMEOUT, 0), 
			ctdb_call_timeout, state);
*/

	ctdb_ltdb_unlock(ctdb_db, call->key);
	return state;
}



/*
  tell the daemon what messaging srvid we will use, and register the message
  handler function in the client
*/
int ctdb_client_set_message_handler(struct ctdb_context *ctdb, uint32_t srvid, 
				    ctdb_message_fn_t handler,
				    void *private_data)
				    
{
	struct ctdb_req_register c;
	int res;

	/* if the domain socket is not yet open, open it */
	if (ctdb->daemon.sd==-1) {
		ux_socket_connect(ctdb);
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
  setup handler for receipt of ctdb messages from ctdb_send_message()
*/
int ctdb_set_message_handler(struct ctdb_context *ctdb, 
			     uint32_t srvid, 
			     ctdb_message_fn_t handler,
			     void *private_data)
{
	if (ctdb->flags & CTDB_FLAG_DAEMON_MODE) {
		return ctdb_client_set_message_handler(ctdb, srvid, handler, private_data);
	}
	return ctdb_daemon_set_message_handler(ctdb, srvid, handler, private_data);
}


/*
  send a message - from client context
 */
int ctdb_client_send_message(struct ctdb_context *ctdb, uint32_t vnn,
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
static void ctdb_client_connect_wait(struct ctdb_context *ctdb)
{
	struct ctdb_req_connect_wait r;
	int res;

	ZERO_STRUCT(r);

	r.hdr.length     = sizeof(r);
	r.hdr.ctdb_magic = CTDB_MAGIC;
	r.hdr.ctdb_version = CTDB_VERSION;
	r.hdr.operation = CTDB_REQ_CONNECT_WAIT;
	
	res = ctdb_queue_send(ctdb->daemon.queue, (uint8_t *)&r.hdr, r.hdr.length);
	if (res != 0) {
		printf("Failed to queue a connect wait request\n");
		return;
	}

	/* now we can go into the normal wait routine, as the reply packet
	   will update the ctdb->num_connected variable */
	ctdb_daemon_connect_wait(ctdb);
}

/*
  wait for all nodes to be connected
*/
void ctdb_connect_wait(struct ctdb_context *ctdb)
{
	if (!(ctdb->flags & CTDB_FLAG_DAEMON_MODE)) {
		ctdb_daemon_connect_wait(ctdb);
		return;
	}

	ctdb_client_connect_wait(ctdb);
}


struct ctdb_call_state *ctdb_client_fetch_lock_send(struct ctdb_db_context *ctdb_db, 
						  TALLOC_CTX *mem_ctx, 
						  TDB_DATA key)
{
	struct ctdb_call_state *state;
	struct ctdb_context *ctdb = ctdb_db->ctdb;
	struct ctdb_req_fetch_lock *req;
	int len, res;

	/* if the domain socket is not yet open, open it */
	if (ctdb->daemon.sd==-1) {
		ux_socket_connect(ctdb);
	}

	state = talloc_zero(ctdb_db, struct ctdb_call_state);
	if (state == NULL) {
		printf("failed to allocate state\n");
		return NULL;
	}
	state->state   = CTDB_CALL_WAIT;
	state->ctdb_db = ctdb_db;
	len = offsetof(struct ctdb_req_fetch_lock, key) + key.dsize;
	state->c = ctdbd_allocate_pkt(ctdb, len);
	if (state->c == NULL) {
		printf("failed to allocate packet\n");
		return NULL;
	}
	ZERO_STRUCT(*state->c);
	talloc_set_name_const(state->c, "ctdbd req_fetch_lock packet");
	talloc_steal(state, state->c);

	req = (struct ctdb_req_fetch_lock *)state->c;
	req->hdr.length      = len;
	req->hdr.ctdb_magic  = CTDB_MAGIC;
	req->hdr.ctdb_version = CTDB_VERSION;
	req->hdr.operation   = CTDB_REQ_FETCH_LOCK;
	req->hdr.reqid       = idr_get_new(ctdb->idr, state, 0xFFFF);
	req->db_id           = ctdb_db->db_id;
	req->keylen          = key.dsize;
	memcpy(&req->key[0], key.dptr, key.dsize);
	
	res = ctdb_client_queue_pkt(ctdb, &req->hdr);
	if (res != 0) {
		return NULL;
	}

	talloc_free(req);

	return state;
}


struct ctdb_call_state *ctdb_client_store_unlock_send(
					struct ctdb_record_handle *rh,
					TALLOC_CTX *mem_ctx,
					TDB_DATA data)
{
	struct ctdb_call_state *state;
	struct ctdb_db_context *ctdb_db = talloc_get_type(rh->ctdb_db, struct ctdb_db_context);
	struct ctdb_context *ctdb = ctdb_db->ctdb;
	struct ctdb_req_store_unlock *req;
	int len, res;

	/* if the domain socket is not yet open, open it */
	if (ctdb->daemon.sd==-1) {
		ux_socket_connect(ctdb);
	}

	state = talloc_zero(ctdb_db, struct ctdb_call_state);
	if (state == NULL) {
		printf("failed to allocate state\n");
		return NULL;
	}
	state->state   = CTDB_CALL_WAIT;
	state->ctdb_db = ctdb_db;
	len = offsetof(struct ctdb_req_store_unlock, data) + rh->key.dsize + data.dsize;
	state->c = ctdbd_allocate_pkt(ctdb, len);
	if (state->c == NULL) {
		printf("failed to allocate packet\n");
		return NULL;
	}
	ZERO_STRUCT(*state->c);
	talloc_set_name_const(state->c, "ctdbd req_store_unlock packet");
	talloc_steal(state, state->c);

	req = (struct ctdb_req_store_unlock *)state->c;
	req->hdr.length      = len;
	req->hdr.ctdb_magic  = CTDB_MAGIC;
	req->hdr.ctdb_version = CTDB_VERSION;
	req->hdr.operation   = CTDB_REQ_STORE_UNLOCK;
	req->hdr.reqid       = idr_get_new(ctdb->idr, state, 0xFFFF);
	req->db_id           = ctdb_db->db_id;
	req->keylen          = rh->key.dsize;
	req->datalen         = data.dsize;
	memcpy(&req->data[0], rh->key.dptr, rh->key.dsize);
	memcpy(&req->data[req->keylen], data.dptr, data.dsize);
	
	res = ctdb_client_queue_pkt(ctdb, &req->hdr);
	if (res != 0) {
		return NULL;
	}

	talloc_free(req);

	return state;
}

/*
  make a recv call to the local ctdb daemon - called from client context

  This is called when the program wants to wait for a ctdb_fetch_lock to complete and get the 
  results. This call will block unless the call has already completed.
*/
struct ctdb_record_handle *ctdb_client_fetch_lock_recv(struct ctdb_call_state *state, TALLOC_CTX *mem_ctx, TDB_DATA key, TDB_DATA *data)
{
	struct ctdb_record_handle *rec;

	while (state->state < CTDB_CALL_DONE) {
		event_loop_once(state->ctdb_db->ctdb->ev);
	}
	if (state->state != CTDB_CALL_DONE) {
		ctdb_set_error(state->node->ctdb, "%s", state->errmsg);
		talloc_free(state);
		return NULL;
	}

	rec = talloc(mem_ctx, struct ctdb_record_handle);
	CTDB_NO_MEMORY_NULL(state->ctdb_db->ctdb, rec);

	rec->ctdb_db     = state->ctdb_db;
	rec->key         = key;
	rec->key.dptr    = talloc_memdup(rec, key.dptr, key.dsize);
	rec->data        = talloc(rec, TDB_DATA);
	rec->data->dsize = state->call.reply_data.dsize;
	rec->data->dptr  = talloc_memdup(rec, state->call.reply_data.dptr, rec->data->dsize);

	if (data) {
		*data = *rec->data;
	}
	return rec;
}

/*
  make a recv call to the local ctdb daemon - called from client context

  This is called when the program wants to wait for a ctdb_store_unlock to complete and get the 
  results. This call will block unless the call has already completed.
*/
int ctdb_client_store_unlock_recv(struct ctdb_call_state *state, struct ctdb_record_handle *rec)
{
	while (state->state < CTDB_CALL_DONE) {
		event_loop_once(state->ctdb_db->ctdb->ev);
	}
	if (state->state != CTDB_CALL_DONE) {
		ctdb_set_error(state->node->ctdb, "%s", state->errmsg);
	}

	talloc_free(state);
	return state->state;
}

struct ctdb_record_handle *ctdb_client_fetch_lock(struct ctdb_db_context *ctdb_db, 
						  TALLOC_CTX *mem_ctx, 
						  TDB_DATA key,
						  TDB_DATA *data)
{
	struct ctdb_call_state *state;
	struct ctdb_record_handle *rec;

	state = ctdb_client_fetch_lock_send(ctdb_db, mem_ctx, key);
	rec = ctdb_client_fetch_lock_recv(state, mem_ctx, key, data);

	return rec;
}

int ctdb_client_store_unlock(struct ctdb_record_handle *rec, TDB_DATA data)
{
	struct ctdb_call_state *state;
	int res;

	state = ctdb_client_store_unlock_send(rec, rec, data);
	res = ctdb_client_store_unlock_recv(state, rec);

	talloc_free(rec);

	return res;
}
