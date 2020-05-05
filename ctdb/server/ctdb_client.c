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

#include "replace.h"
#include "system/network.h"
#include "system/filesys.h"
#include "system/locale.h"

#include <talloc.h>
#include <tevent.h>
#include <tdb.h>

#include "lib/tdb_wrap/tdb_wrap.h"
#include "lib/util/dlinklist.h"
#include "lib/util/time.h"
#include "lib/util/debug.h"
#include "lib/util/samba_util.h"

#include "ctdb_private.h"
#include "ctdb_client.h"

#include "common/reqid.h"
#include "common/system.h"
#include "common/common.h"
#include "common/logging.h"

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

	hdr = (struct ctdb_req_header *)talloc_zero_size(mem_ctx, size);
	if (hdr == NULL) {
		DEBUG(DEBUG_ERR,("Unable to allocate packet for operation %u of length %u\n",
			 operation, (unsigned)length));
		return NULL;
	}
	talloc_set_name_const(hdr, type);
	hdr->length       = length;
	hdr->operation    = operation;
	hdr->ctdb_magic   = CTDB_MAGIC;
	hdr->ctdb_version = CTDB_PROTOCOL;
	hdr->srcnode      = ctdb->pnn;
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
		    TDB_DATA *data, bool updatetdb)
{
	struct ctdb_call_info *c;
	struct ctdb_registered_call *fn;
	struct ctdb_context *ctdb = ctdb_db->ctdb;

	c = talloc_zero(mem_ctx, struct ctdb_call_info);
	CTDB_NO_MEMORY(ctdb, c);

	c->key = call->key;
	c->call_data = &call->call_data;
	c->record_data.dptr = talloc_memdup(c, data->dptr, data->dsize);
	c->record_data.dsize = data->dsize;
	CTDB_NO_MEMORY(ctdb, c->record_data.dptr);
	c->header = header;

	for (fn=ctdb_db->calls;fn;fn=fn->next) {
		if (fn->id == (uint32_t)call->call_id) {
			break;
		}
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

	/* we need to force the record to be written out if this was a remote access */
	if (c->new_data == NULL) {
		c->new_data = &c->record_data;
	}

	if (c->new_data && updatetdb) {
		/* XXX check that we always have the lock here? */
		if (ctdb_ltdb_store(ctdb_db, call->key, header, *c->new_data) != 0) {
			ctdb_set_error(ctdb, "ctdb_call tdb_store failed\n");
			talloc_free(c);
			return -1;
		}
	}

	if (c->reply_data) {
		call->reply_data = *c->reply_data;

		talloc_steal(call, call->reply_data.dptr);
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
  called when a CTDB_REPLY_CALL packet comes in in the client

  This packet comes in response to a CTDB_REQ_CALL request packet. It
  contains any reply data from the call
*/
static void ctdb_client_reply_call(struct ctdb_context *ctdb, struct ctdb_req_header *hdr)
{
	struct ctdb_reply_call_old *c = (struct ctdb_reply_call_old *)hdr;
	struct ctdb_client_call_state *state;

	state = reqid_find(ctdb->idr, hdr->reqid, struct ctdb_client_call_state);
	if (state == NULL) {
		DEBUG(DEBUG_ERR,(__location__ " reqid %u not found\n", hdr->reqid));
		return;
	}

	if (hdr->reqid != state->reqid) {
		/* we found a record  but it was the wrong one */
		DEBUG(DEBUG_ERR, ("Dropped client call reply with reqid:%u\n",hdr->reqid));
		return;
	}

	state->call->reply_data.dptr = c->data;
	state->call->reply_data.dsize = c->datalen;
	state->call->status = c->status;

	talloc_steal(state, c);

	state->state = CTDB_CALL_DONE;

	if (state->async.fn) {
		state->async.fn(state);
	}
}

void ctdb_request_message(struct ctdb_context *ctdb,
			  struct ctdb_req_header *hdr)
{
	struct ctdb_req_message_old *c = (struct ctdb_req_message_old *)hdr;
	TDB_DATA data;

	data.dsize = c->datalen;
	data.dptr = talloc_memdup(c, &c->data[0], c->datalen);
	if (data.dptr == NULL) {
		DEBUG(DEBUG_ERR, (__location__ " Memory allocation failure\n"));
		return;
	}

	srvid_dispatch(ctdb->srv, c->srvid, CTDB_SRVID_ALL, data);
}

static void ctdb_client_reply_control(struct ctdb_context *ctdb, struct ctdb_req_header *hdr);

/*
  this is called in the client, when data comes in from the daemon
 */
void ctdb_client_read_cb(uint8_t *data, size_t cnt, void *args)
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
		DEBUG(DEBUG_CRIT,("Daemon has exited - shutting down client\n"));
		exit(1);
	}

	if (cnt < sizeof(*hdr)) {
		DEBUG(DEBUG_CRIT,("Bad packet length %u in client\n", (unsigned)cnt));
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

	if (hdr->ctdb_version != CTDB_PROTOCOL) {
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
		DEBUG(DEBUG_CRIT,("bogus operation code:%u\n",hdr->operation));
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
	int ret;

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, ctdb->daemon.name, sizeof(addr.sun_path)-1);

	ctdb->daemon.sd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (ctdb->daemon.sd == -1) {
		DEBUG(DEBUG_ERR,(__location__ " Failed to open client socket. Errno:%s(%d)\n", strerror(errno), errno));
		return -1;
	}

	if (connect(ctdb->daemon.sd, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
		DEBUG(DEBUG_ERR,
		      (__location__
		       "Failed to connect client socket to daemon (%s)\n",
		       strerror(errno)));
		close(ctdb->daemon.sd);
		ctdb->daemon.sd = -1;
		return -1;
	}

	ret = set_blocking(ctdb->daemon.sd, false);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,
		      (__location__
		       " failed to set socket non-blocking (%s)\n",
		       strerror(errno)));
		close(ctdb->daemon.sd);
		ctdb->daemon.sd = -1;
		return -1;
	}

	set_close_on_exec(ctdb->daemon.sd);

	ctdb->daemon.queue = ctdb_queue_setup(ctdb, ctdb, ctdb->daemon.sd,
					      CTDB_DS_ALIGNMENT,
					      ctdb_client_read_cb, ctdb, "to-ctdbd");
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
	if (state == NULL) {
		return -1;
	}

	while (state->state < CTDB_CALL_DONE) {
		tevent_loop_once(state->ctdb_db->ctdb->ev);
	}
	if (state->state != CTDB_CALL_DONE) {
		DEBUG(DEBUG_ERR,(__location__ " ctdb_call_recv failed\n"));
		talloc_free(state);
		return -1;
	}

	if (state->call->reply_data.dsize) {
		call->reply_data.dptr = talloc_memdup(state->ctdb_db,
						      state->call->reply_data.dptr,
						      state->call->reply_data.dsize);
		call->reply_data.dsize = state->call->reply_data.dsize;
	} else {
		call->reply_data.dptr = NULL;
		call->reply_data.dsize = 0;
	}
	call->status = state->call->status;
	talloc_free(state);

	return call->status;
}




/*
  destroy a ctdb_call in client
*/
static int ctdb_client_call_destructor(struct ctdb_client_call_state *state)
{
	reqid_remove(state->ctdb_db->ctdb->idr, state->reqid);
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
	state->call = talloc_zero(state, struct ctdb_call);
	CTDB_NO_MEMORY_NULL(ctdb, state->call);

	talloc_steal(state, data->dptr);

	state->state   = CTDB_CALL_DONE;
	*(state->call) = *call;
	state->ctdb_db = ctdb_db;

	ret = ctdb_call_local(ctdb_db, state->call, header, state, data, true);
	if (ret != 0) {
		DEBUG(DEBUG_DEBUG,("ctdb_call_local() failed, ignoring return code %d\n", ret));
	}

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
	struct ctdb_req_call_old *c;

	/* if the domain socket is not yet open, open it */
	if (ctdb->daemon.sd==-1) {
		ctdb_socket_connect(ctdb);
	}

	ret = ctdb_ltdb_lock(ctdb_db, call->key);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,(__location__ " Failed to get chainlock\n"));
		return NULL;
	}

	ret = ctdb_ltdb_fetch(ctdb_db, call->key, &header, ctdb_db, &data);

	if ((call->flags & CTDB_IMMEDIATE_MIGRATION) && (header.flags & CTDB_REC_RO_HAVE_DELEGATIONS)) {
		ret = -1;
	}

	if (ret == 0 && header.dmaster == ctdb->pnn) {
		state = ctdb_client_call_local_send(ctdb_db, call, &header, &data);
		talloc_free(data.dptr);
		ctdb_ltdb_unlock(ctdb_db, call->key);
		return state;
	}

	ctdb_ltdb_unlock(ctdb_db, call->key);
	talloc_free(data.dptr);

	state = talloc_zero(ctdb_db, struct ctdb_client_call_state);
	if (state == NULL) {
		DEBUG(DEBUG_ERR, (__location__ " failed to allocate state\n"));
		return NULL;
	}
	state->call = talloc_zero(state, struct ctdb_call);
	if (state->call == NULL) {
		DEBUG(DEBUG_ERR, (__location__ " failed to allocate state->call\n"));
		return NULL;
	}

	len = offsetof(struct ctdb_req_call_old, data) + call->key.dsize + call->call_data.dsize;
	c = ctdbd_allocate_pkt(ctdb, state, CTDB_REQ_CALL, len, struct ctdb_req_call_old);
	if (c == NULL) {
		DEBUG(DEBUG_ERR, (__location__ " failed to allocate packet\n"));
		return NULL;
	}

	state->reqid     = reqid_new(ctdb->idr, state);
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
	*(state->call)              = *call;
	state->call->call_data.dptr = &c->data[call->key.dsize];
	state->call->key.dptr       = &c->data[0];

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
int ctdb_client_set_message_handler(struct ctdb_context *ctdb, uint64_t srvid,
				    srvid_handler_fn handler,
				    void *private_data)
{
	int res;
	int32_t status;

	res = ctdb_control(ctdb, CTDB_CURRENT_NODE, srvid,
			   CTDB_CONTROL_REGISTER_SRVID, 0,
			   tdb_null, NULL, NULL, &status, NULL, NULL);
	if (res != 0 || status != 0) {
		DEBUG(DEBUG_ERR,
		      ("Failed to register srvid %llu\n",
		       (unsigned long long)srvid));
		return -1;
	}

	/* also need to register the handler with our own ctdb structure */
	return srvid_register(ctdb->srv, ctdb, srvid, handler, private_data);
}

/*
  tell the daemon we no longer want a srvid
*/
int ctdb_client_remove_message_handler(struct ctdb_context *ctdb,
				       uint64_t srvid, void *private_data)
{
	int res;
	int32_t status;

	res = ctdb_control(ctdb, CTDB_CURRENT_NODE, srvid,
			   CTDB_CONTROL_DEREGISTER_SRVID, 0,
			   tdb_null, NULL, NULL, &status, NULL, NULL);
	if (res != 0 || status != 0) {
		DEBUG(DEBUG_ERR,
		      ("Failed to deregister srvid %llu\n",
		       (unsigned long long)srvid));
		return -1;
	}

	/* also need to register the handler with our own ctdb structure */
	srvid_deregister(ctdb->srv, srvid, private_data);
	return 0;
}

/*
  send a message - from client context
 */
int ctdb_client_send_message(struct ctdb_context *ctdb, uint32_t pnn,
		      uint64_t srvid, TDB_DATA data)
{
	struct ctdb_req_message_old *r;
	int len, res;

	len = offsetof(struct ctdb_req_message_old, data) + data.dsize;
	r = ctdbd_allocate_pkt(ctdb, ctdb, CTDB_REQ_MESSAGE,
			       len, struct ctdb_req_message_old);
	CTDB_NO_MEMORY(ctdb, r);

	r->hdr.destnode  = pnn;
	r->srvid         = srvid;
	r->datalen       = data.dsize;
	memcpy(&r->data[0], data.dptr, data.dsize);

	res = ctdb_client_queue_pkt(ctdb, &r->hdr);
	talloc_free(r);
	return res;
}


/*
   called when a control completes or timesout to invoke the callback
   function the user provided
*/
static void invoke_control_callback(struct tevent_context *ev,
				    struct tevent_timer *te,
				    struct timeval t, void *private_data)
{
	struct ctdb_client_control_state *state;
	TALLOC_CTX *tmp_ctx = talloc_new(NULL);
	int ret;

	state = talloc_get_type(private_data, struct ctdb_client_control_state);
	talloc_steal(tmp_ctx, state);

	ret = ctdb_control_recv(state->ctdb, state, state,
			NULL,
			NULL,
			NULL);
	if (ret != 0) {
		DEBUG(DEBUG_DEBUG,("ctdb_control_recv() failed, ignoring return code %d\n", ret));
	}

	talloc_free(tmp_ctx);
}

/*
  called when a CTDB_REPLY_CONTROL packet comes in in the client

  This packet comes in response to a CTDB_REQ_CONTROL request packet. It
  contains any reply data from the control
*/
static void ctdb_client_reply_control(struct ctdb_context *ctdb,
				      struct ctdb_req_header *hdr)
{
	struct ctdb_reply_control_old *c = (struct ctdb_reply_control_old *)hdr;
	struct ctdb_client_control_state *state;

	state = reqid_find(ctdb->idr, hdr->reqid, struct ctdb_client_control_state);
	if (state == NULL) {
		DEBUG(DEBUG_ERR,(__location__ " reqid %u not found\n", hdr->reqid));
		return;
	}

	if (hdr->reqid != state->reqid) {
		/* we found a record  but it was the wrong one */
		DEBUG(DEBUG_ERR, ("Dropped orphaned reply control with reqid:%u\n",hdr->reqid));
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

	/* state->outdata now uses resources from c so we don't want c
	   to just disappear from under us while state is still alive
	*/
	talloc_steal(state, c);

	state->state = CTDB_CONTROL_DONE;

	/* if we had a callback registered for this control, pull the response
	   and call the callback.
	*/
	if (state->async.fn) {
		tevent_add_timer(ctdb->ev, state, timeval_zero(),
				 invoke_control_callback, state);
	}
}


/*
  destroy a ctdb_control in client
*/
static int ctdb_client_control_destructor(struct ctdb_client_control_state *state)
{
	reqid_remove(state->ctdb->idr, state->reqid);
	return 0;
}


/* time out handler for ctdb_control */
static void control_timeout_func(struct tevent_context *ev,
				 struct tevent_timer *te,
				 struct timeval t, void *private_data)
{
	struct ctdb_client_control_state *state = talloc_get_type(private_data, struct ctdb_client_control_state);

	DEBUG(DEBUG_ERR,(__location__ " control timed out. reqid:%u opcode:%u "
			 "dstnode:%u\n", state->reqid, state->c->opcode,
			 state->c->hdr.destnode));

	state->state = CTDB_CONTROL_TIMEOUT;

	/* if we had a callback registered for this control, pull the response
	   and call the callback.
	*/
	if (state->async.fn) {
		tevent_add_timer(state->ctdb->ev, state, timeval_zero(),
				 invoke_control_callback, state);
	}
}

/* async version of send control request */
struct ctdb_client_control_state *ctdb_control_send(struct ctdb_context *ctdb,
		uint32_t destnode, uint64_t srvid,
		uint32_t opcode, uint32_t flags, TDB_DATA data,
		TALLOC_CTX *mem_ctx,
		struct timeval *timeout,
		char **errormsg)
{
	struct ctdb_client_control_state *state;
	size_t len;
	struct ctdb_req_control_old *c;
	int ret;

	if (errormsg) {
		*errormsg = NULL;
	}

	/* if the domain socket is not yet open, open it */
	if (ctdb->daemon.sd==-1) {
		ctdb_socket_connect(ctdb);
	}

	state = talloc_zero(mem_ctx, struct ctdb_client_control_state);
	CTDB_NO_MEMORY_NULL(ctdb, state);

	state->ctdb       = ctdb;
	state->reqid      = reqid_new(ctdb->idr, state);
	state->state      = CTDB_CONTROL_WAIT;
	state->errormsg   = NULL;

	talloc_set_destructor(state, ctdb_client_control_destructor);

	len = offsetof(struct ctdb_req_control_old, data) + data.dsize;
	c = ctdbd_allocate_pkt(ctdb, state, CTDB_REQ_CONTROL,
			       len, struct ctdb_req_control_old);
	state->c            = c;
	CTDB_NO_MEMORY_NULL(ctdb, c);
	c->hdr.reqid        = state->reqid;
	c->hdr.destnode     = destnode;
	c->opcode           = opcode;
	c->client_id        = 0;
	c->flags            = flags;
	c->srvid            = srvid;
	c->datalen          = data.dsize;
	if (data.dsize) {
		memcpy(&c->data[0], data.dptr, data.dsize);
	}

	/* timeout */
	if (timeout && !timeval_is_zero(timeout)) {
		tevent_add_timer(ctdb->ev, state, *timeout,
				 control_timeout_func, state);
	}

	ret = ctdb_client_queue_pkt(ctdb, &(c->hdr));
	if (ret != 0) {
		talloc_free(state);
		return NULL;
	}

	if (flags & CTDB_CTRL_FLAG_NOREPLY) {
		talloc_free(state);
		return NULL;
	}

	return state;
}


/* async version of receive control reply */
int ctdb_control_recv(struct ctdb_context *ctdb,
		struct ctdb_client_control_state *state,
		TALLOC_CTX *mem_ctx,
		TDB_DATA *outdata, int32_t *status, char **errormsg)
{
	TALLOC_CTX *tmp_ctx;

	if (status != NULL) {
		*status = -1;
	}
	if (errormsg != NULL) {
		*errormsg = NULL;
	}

	if (state == NULL) {
		return -1;
	}

	/* prevent double free of state */
	tmp_ctx = talloc_new(ctdb);
	talloc_steal(tmp_ctx, state);

	/* loop one event at a time until we either timeout or the control
	   completes.
	*/
	while (state->state == CTDB_CONTROL_WAIT) {
		tevent_loop_once(ctdb->ev);
	}

	if (state->state != CTDB_CONTROL_DONE) {
		DEBUG(DEBUG_ERR,(__location__ " ctdb_control_recv failed\n"));
		if (state->async.fn) {
			state->async.fn(state);
		}
		talloc_free(tmp_ctx);
		return -1;
	}

	if (state->errormsg) {
		int s = (state->status == 0 ? -1 : state->status);
		DEBUG(DEBUG_ERR,("ctdb_control error: '%s'\n", state->errormsg));
		if (errormsg) {
			(*errormsg) = talloc_move(mem_ctx, &state->errormsg);
		}
		if (state->async.fn) {
			state->async.fn(state);
		}
		talloc_free(tmp_ctx);
		return s;
	}

	if (outdata) {
		*outdata = state->outdata;
		outdata->dptr = talloc_memdup(mem_ctx, outdata->dptr, outdata->dsize);
	}

	if (status) {
		*status = state->status;
	}

	if (state->async.fn) {
		state->async.fn(state);
	}

	talloc_free(tmp_ctx);
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

	state = ctdb_control_send(ctdb, destnode, srvid, opcode,
			flags, data, mem_ctx,
			timeout, errormsg);

	/* FIXME: Error conditions in ctdb_control_send return NULL without
	 * setting errormsg.  So, there is no way to distinguish between success
	 * and failure when CTDB_CTRL_FLAG_NOREPLY is set */
	if (flags & CTDB_CTRL_FLAG_NOREPLY) {
		if (status != NULL) {
			*status = 0;
		}
		return 0;
	}

	return ctdb_control_recv(ctdb, state, mem_ctx, outdata, status,
			errormsg);
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
		DEBUG(DEBUG_ERR,(__location__ " ctdb_control for getvnnmap failed\n"));
		return -1;
	}

	map = (struct ctdb_vnn_map_wire *)outdata.dptr;
	if (outdata.dsize < offsetof(struct ctdb_vnn_map_wire, map) ||
	    outdata.dsize != map->size*sizeof(uint32_t) + offsetof(struct ctdb_vnn_map_wire, map)) {
		DEBUG(DEBUG_ERR,("Bad vnn map size received in ctdb_ctrl_getvnnmap\n"));
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
struct ctdb_client_control_state *
ctdb_ctrl_getrecmode_send(struct ctdb_context *ctdb, TALLOC_CTX *mem_ctx, struct timeval timeout, uint32_t destnode)
{
	return ctdb_control_send(ctdb, destnode, 0,
			   CTDB_CONTROL_GET_RECMODE, 0, tdb_null,
			   mem_ctx, &timeout, NULL);
}

int ctdb_ctrl_getrecmode_recv(struct ctdb_context *ctdb, TALLOC_CTX *mem_ctx, struct ctdb_client_control_state *state, uint32_t *recmode)
{
	int ret;
	int32_t res;

	ret = ctdb_control_recv(ctdb, state, mem_ctx, NULL, &res, NULL);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,(__location__ " ctdb_ctrl_getrecmode_recv failed\n"));
		return -1;
	}

	if (recmode) {
		*recmode = (uint32_t)res;
	}

	return 0;
}

int ctdb_ctrl_getrecmode(struct ctdb_context *ctdb, TALLOC_CTX *mem_ctx, struct timeval timeout, uint32_t destnode, uint32_t *recmode)
{
	struct ctdb_client_control_state *state;

	state = ctdb_ctrl_getrecmode_send(ctdb, mem_ctx, timeout, destnode);
	return ctdb_ctrl_getrecmode_recv(ctdb, mem_ctx, state, recmode);
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
		DEBUG(DEBUG_ERR,(__location__ " ctdb_control for setrecmode failed\n"));
		return -1;
	}

	return 0;
}



/*
  get the recovery master of a remote node
 */
struct ctdb_client_control_state *
ctdb_ctrl_getrecmaster_send(struct ctdb_context *ctdb, TALLOC_CTX *mem_ctx,
			struct timeval timeout, uint32_t destnode)
{
	return ctdb_control_send(ctdb, destnode, 0,
			   CTDB_CONTROL_GET_RECMASTER, 0, tdb_null,
			   mem_ctx, &timeout, NULL);
}

int ctdb_ctrl_getrecmaster_recv(struct ctdb_context *ctdb, TALLOC_CTX *mem_ctx, struct ctdb_client_control_state *state, uint32_t *recmaster)
{
	int ret;
	int32_t res;

	ret = ctdb_control_recv(ctdb, state, mem_ctx, NULL, &res, NULL);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,(__location__ " ctdb_ctrl_getrecmaster_recv failed\n"));
		return -1;
	}

	if (recmaster) {
		*recmaster = (uint32_t)res;
	}

	return 0;
}

int ctdb_ctrl_getrecmaster(struct ctdb_context *ctdb, TALLOC_CTX *mem_ctx, struct timeval timeout, uint32_t destnode, uint32_t *recmaster)
{
	struct ctdb_client_control_state *state;

	state = ctdb_ctrl_getrecmaster_send(ctdb, mem_ctx, timeout, destnode);
	return ctdb_ctrl_getrecmaster_recv(ctdb, mem_ctx, state, recmaster);
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
		DEBUG(DEBUG_ERR,(__location__ " ctdb_control for setrecmaster failed\n"));
		return -1;
	}

	return 0;
}


/*
  get a list of nodes (vnn and flags ) from a remote node
 */
int ctdb_ctrl_getnodemap(struct ctdb_context *ctdb,
		struct timeval timeout, uint32_t destnode,
		TALLOC_CTX *mem_ctx, struct ctdb_node_map_old **nodemap)
{
	int ret;
	TDB_DATA outdata;
	int32_t res;

	ret = ctdb_control(ctdb, destnode, 0,
			   CTDB_CONTROL_GET_NODEMAP, 0, tdb_null,
			   mem_ctx, &outdata, &res, &timeout, NULL);
	if (ret != 0 || res != 0 || outdata.dsize == 0) {
		DEBUG(DEBUG_ERR,(__location__ " ctdb_control for getnodes failed ret:%d res:%d\n", ret, res));
		return -1;
	}

	*nodemap = (struct ctdb_node_map_old *)talloc_memdup(mem_ctx, outdata.dptr, outdata.dsize);
	talloc_free(outdata.dptr);
	return 0;
}

int ctdb_ctrl_get_runstate(struct ctdb_context *ctdb,
			   struct timeval timeout,
			   uint32_t destnode,
			   uint32_t *runstate)
{
	TDB_DATA outdata;
	int32_t res;
	int ret;

	ret = ctdb_control(ctdb, destnode, 0, CTDB_CONTROL_GET_RUNSTATE, 0,
			   tdb_null, ctdb, &outdata, &res, &timeout, NULL);
	if (ret != 0 || res != 0) {
		DEBUG(DEBUG_ERR,("ctdb_control for get_runstate failed\n"));
		return ret != 0 ? ret : res;
	}

	if (outdata.dsize != sizeof(uint32_t)) {
		DEBUG(DEBUG_ERR,("Invalid return data in get_runstate\n"));
		talloc_free(outdata.dptr);
		return -1;
	}

	if (runstate != NULL) {
		*runstate = *(uint32_t *)outdata.dptr;
	}
	talloc_free(outdata.dptr);

	return 0;
}

/*
  get debug level on a node
 */
int ctdb_ctrl_get_debuglevel(struct ctdb_context *ctdb, uint32_t destnode, int32_t *level)
{
	int ret;
	int32_t res;
	TDB_DATA data;

	ret = ctdb_control(ctdb, destnode, 0, CTDB_CONTROL_GET_DEBUG, 0, tdb_null,
			   ctdb, &data, &res, NULL, NULL);
	if (ret != 0 || res != 0) {
		return -1;
	}
	if (data.dsize != sizeof(int32_t)) {
		DEBUG(DEBUG_ERR,("Bad control reply size in ctdb_get_debuglevel (got %u)\n",
			 (unsigned)data.dsize));
		return -1;
	}
	*level = *(int32_t *)data.dptr;
	talloc_free(data.dptr);
	return 0;
}

/* Freeze all databases */
int ctdb_ctrl_freeze(struct ctdb_context *ctdb, struct timeval timeout,
		     uint32_t destnode)
{
	int ret;
	int32_t res;

	ret = ctdb_control(ctdb, destnode, 0,
			   CTDB_CONTROL_FREEZE, 0, tdb_null,
			   NULL, NULL, &res, &timeout, NULL);
	if (ret != 0 || res != 0) {
		DEBUG(DEBUG_ERR, ("ctdb_ctrl_freeze_priority failed\n"));
		return -1;
	}

	return 0;
}

/*
  get pnn of a node, or -1
 */
int ctdb_ctrl_getpnn(struct ctdb_context *ctdb, struct timeval timeout, uint32_t destnode)
{
	int ret;
	int32_t res;

	ret = ctdb_control(ctdb, destnode, 0,
			   CTDB_CONTROL_GET_PNN, 0, tdb_null,
			   NULL, NULL, &res, &timeout, NULL);
	if (ret != 0) {
		DEBUG(DEBUG_ERR,(__location__ " ctdb_control for getpnn failed\n"));
		return -1;
	}

	return res;
}

int ctdb_ctrl_get_public_ips_flags(struct ctdb_context *ctdb,
				   struct timeval timeout, uint32_t destnode,
				   TALLOC_CTX *mem_ctx,
				   uint32_t flags,
				   struct ctdb_public_ip_list_old **ips)
{
	int ret;
	TDB_DATA outdata;
	int32_t res;

	ret = ctdb_control(ctdb, destnode, 0,
			   CTDB_CONTROL_GET_PUBLIC_IPS, flags, tdb_null,
			   mem_ctx, &outdata, &res, &timeout, NULL);
	if (ret != 0 || res != 0) {
		DEBUG(DEBUG_ERR,(__location__
				 " ctdb_control for getpublicips failed ret:%d res:%d\n",
				 ret, res));
		return -1;
	}

	*ips = (struct ctdb_public_ip_list_old *)talloc_memdup(mem_ctx, outdata.dptr, outdata.dsize);
	talloc_free(outdata.dptr);

	return 0;
}

int ctdb_ctrl_get_public_ips(struct ctdb_context *ctdb,
			     struct timeval timeout, uint32_t destnode,
			     TALLOC_CTX *mem_ctx,
			     struct ctdb_public_ip_list_old **ips)
{
	return ctdb_ctrl_get_public_ips_flags(ctdb, timeout,
					      destnode, mem_ctx,
					      0, ips);
}

int ctdb_ctrl_get_ifaces(struct ctdb_context *ctdb,
			 struct timeval timeout, uint32_t destnode,
			 TALLOC_CTX *mem_ctx,
			 struct ctdb_iface_list_old **_ifaces)
{
	int ret;
	TDB_DATA outdata;
	int32_t res;
	struct ctdb_iface_list_old *ifaces;
	uint32_t len;
	uint32_t i;

	ret = ctdb_control(ctdb, destnode, 0,
			   CTDB_CONTROL_GET_IFACES, 0, tdb_null,
			   mem_ctx, &outdata, &res, &timeout, NULL);
	if (ret != 0 || res != 0) {
		DEBUG(DEBUG_ERR,(__location__ " ctdb_control for get ifaces "
				"failed ret:%d res:%d\n",
				ret, res));
		return -1;
	}

	len = offsetof(struct ctdb_iface_list_old, ifaces);
	if (len > outdata.dsize) {
		DEBUG(DEBUG_ERR,(__location__ " ctdb_control for get ifaces "
				"returned invalid data with size %u > %u\n",
				(unsigned int)outdata.dsize,
				(unsigned int)len));
		dump_data(DEBUG_DEBUG, outdata.dptr, outdata.dsize);
		return -1;
	}

	ifaces = (struct ctdb_iface_list_old *)outdata.dptr;
	len += ifaces->num*sizeof(struct ctdb_iface);

	if (len > outdata.dsize) {
		DEBUG(DEBUG_ERR,(__location__ " ctdb_control for get ifaces "
				"returned invalid data with size %u > %u\n",
				(unsigned int)outdata.dsize,
				(unsigned int)len));
		dump_data(DEBUG_DEBUG, outdata.dptr, outdata.dsize);
		return -1;
	}

	/* make sure we null terminate the returned strings */
	for (i=0; i < ifaces->num; i++) {
		ifaces->ifaces[i].name[CTDB_IFACE_SIZE] = '\0';
	}

	*_ifaces = (struct ctdb_iface_list_old *)talloc_memdup(mem_ctx,
								  outdata.dptr,
								  outdata.dsize);
	talloc_free(outdata.dptr);
	if (*_ifaces == NULL) {
		DEBUG(DEBUG_ERR,(__location__ " ctdb_control for get ifaces "
				"talloc_memdup size %u failed\n",
				(unsigned int)outdata.dsize));
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
			       struct ctdb_tunable_list *tunables)
{
	TDB_DATA outdata;
	int ret;
	int32_t res;

	ret = ctdb_control(ctdb, destnode, 0, CTDB_CONTROL_GET_ALL_TUNABLES, 0, tdb_null, ctdb,
			   &outdata, &res, &timeout, NULL);
	if (ret != 0 || res != 0) {
		DEBUG(DEBUG_ERR,(__location__ " ctdb_control for get all tunables failed\n"));
		return -1;
	}

	if (outdata.dsize != sizeof(*tunables)) {
		DEBUG(DEBUG_ERR,(__location__ " bad data size %u in ctdb_ctrl_get_all_tunables should be %u\n",
			 (unsigned)outdata.dsize, (unsigned)sizeof(*tunables)));
		return -1;
	}

	*tunables = *(struct ctdb_tunable_list *)outdata.dptr;
	talloc_free(outdata.dptr);
	return 0;
}

/*
  set some ctdb flags
*/
void ctdb_set_flags(struct ctdb_context *ctdb, unsigned flags)
{
	ctdb->flags |= flags;
}

const char *ctdb_get_socketname(struct ctdb_context *ctdb)
{
	return ctdb->daemon.name;
}

/*
  return the pnn of this node
*/
uint32_t ctdb_get_pnn(struct ctdb_context *ctdb)
{
	return ctdb->pnn;
}

/*
  callback for the async helpers used when sending the same control
  to multiple nodes in parallel.
*/
static void async_callback(struct ctdb_client_control_state *state)
{
	struct client_async_data *data = talloc_get_type(state->async.private_data, struct client_async_data);
	struct ctdb_context *ctdb = talloc_get_type(state->ctdb, struct ctdb_context);
	int ret;
	TDB_DATA outdata;
	int32_t res = -1;
	uint32_t destnode = state->c->hdr.destnode;

	outdata.dsize = 0;
	outdata.dptr = NULL;

	/* one more node has responded with recmode data */
	data->count--;

	/* if we failed to push the db, then return an error and let
	   the main loop try again.
	*/
	if (state->state != CTDB_CONTROL_DONE) {
		if ( !data->dont_log_errors) {
			DEBUG(DEBUG_ERR,("Async operation failed with state %d, opcode:%u\n", state->state, data->opcode));
		}
		data->fail_count++;
		if (state->state == CTDB_CONTROL_TIMEOUT) {
			res = -ETIMEDOUT;
		} else {
			res = -1;
		}
		if (data->fail_callback) {
			data->fail_callback(ctdb, destnode, res, outdata,
					data->callback_data);
		}
		return;
	}

	state->async.fn = NULL;

	ret = ctdb_control_recv(ctdb, state, data, &outdata, &res, NULL);
	if ((ret != 0) || (res != 0)) {
		if ( !data->dont_log_errors) {
			DEBUG(DEBUG_ERR,("Async operation failed with ret=%d res=%d opcode=%u\n", ret, (int)res, data->opcode));
		}
		data->fail_count++;
		if (data->fail_callback) {
			data->fail_callback(ctdb, destnode, res, outdata,
					data->callback_data);
		}
	}
	if ((ret == 0) && (data->callback != NULL)) {
		data->callback(ctdb, destnode, res, outdata,
					data->callback_data);
	}
}


void ctdb_client_async_add(struct client_async_data *data, struct ctdb_client_control_state *state)
{
	/* set up the callback functions */
	state->async.fn = async_callback;
	state->async.private_data = data;

	/* one more control to wait for to complete */
	data->count++;
}


/* wait for up to the maximum number of seconds allowed
   or until all nodes we expect a response from has replied
*/
int ctdb_client_async_wait(struct ctdb_context *ctdb, struct client_async_data *data)
{
	while (data->count > 0) {
		tevent_loop_once(ctdb->ev);
	}
	if (data->fail_count != 0) {
		if (!data->dont_log_errors) {
			DEBUG(DEBUG_ERR,("Async wait failed - fail_count=%u\n",
				 data->fail_count));
		}
		return -1;
	}
	return 0;
}


/*
   perform a simple control on the listed nodes
   The control cannot return data
 */
int ctdb_client_async_control(struct ctdb_context *ctdb,
				enum ctdb_controls opcode,
				uint32_t *nodes,
				uint64_t srvid,
				struct timeval timeout,
				bool dont_log_errors,
				TDB_DATA data,
				client_async_callback client_callback,
			        client_async_callback fail_callback,
				void *callback_data)
{
	struct client_async_data *async_data;
	struct ctdb_client_control_state *state;
	int j, num_nodes;

	async_data = talloc_zero(ctdb, struct client_async_data);
	CTDB_NO_MEMORY_FATAL(ctdb, async_data);
	async_data->dont_log_errors = dont_log_errors;
	async_data->callback = client_callback;
	async_data->fail_callback = fail_callback;
	async_data->callback_data = callback_data;
	async_data->opcode        = opcode;

	num_nodes = talloc_get_size(nodes) / sizeof(uint32_t);

	/* loop over all nodes and send an async control to each of them */
	for (j=0; j<num_nodes; j++) {
		uint32_t pnn = nodes[j];

		state = ctdb_control_send(ctdb, pnn, srvid, opcode,
					  0, data, async_data, &timeout, NULL);
		if (state == NULL) {
			DEBUG(DEBUG_ERR,(__location__ " Failed to call async control %u\n", (unsigned)opcode));
			talloc_free(async_data);
			return -1;
		}

		ctdb_client_async_add(async_data, state);
	}

	if (ctdb_client_async_wait(ctdb, async_data) != 0) {
		talloc_free(async_data);
		return -1;
	}

	talloc_free(async_data);
	return 0;
}

uint32_t *list_of_vnnmap_nodes(struct ctdb_context *ctdb,
				struct ctdb_vnn_map *vnn_map,
				TALLOC_CTX *mem_ctx,
				bool include_self)
{
	unsigned int i, j, num_nodes;
	uint32_t *nodes;

	for (i=num_nodes=0;i<vnn_map->size;i++) {
		if (vnn_map->map[i] == ctdb->pnn && !include_self) {
			continue;
		}
		num_nodes++;
	}

	nodes = talloc_array(mem_ctx, uint32_t, num_nodes);
	CTDB_NO_MEMORY_FATAL(ctdb, nodes);

	for (i=j=0;i<vnn_map->size;i++) {
		if (vnn_map->map[i] == ctdb->pnn && !include_self) {
			continue;
		}
		nodes[j++] = vnn_map->map[i];
	}

	return nodes;
}

/* Get list of nodes not including those with flags specified by mask */
static uint32_t *list_of_nodes(struct ctdb_context *ctdb,
			       struct ctdb_node_map_old *node_map,
			       TALLOC_CTX *mem_ctx,
			       uint32_t mask,
			       bool include_self)
{
	unsigned int i, j, num_nodes;
	uint32_t exclude_pnn;
	uint32_t *nodes;

	exclude_pnn = include_self ? CTDB_UNKNOWN_PNN : ctdb->pnn;

	for (i=num_nodes=0;i<node_map->num;i++) {
		if (node_map->nodes[i].flags & mask) {
			continue;
		}
		if (node_map->nodes[i].pnn == exclude_pnn) {
			continue;
		}
		num_nodes++;
	}

	nodes = talloc_array(mem_ctx, uint32_t, num_nodes);
	CTDB_NO_MEMORY_FATAL(ctdb, nodes);

	for (i=j=0;i<node_map->num;i++) {
		if (node_map->nodes[i].flags & mask) {
			continue;
		}
		if (node_map->nodes[i].pnn == exclude_pnn) {
			continue;
		}
		nodes[j++] = node_map->nodes[i].pnn;
	}

	return nodes;
}

uint32_t *list_of_active_nodes(struct ctdb_context *ctdb,
				struct ctdb_node_map_old *node_map,
				TALLOC_CTX *mem_ctx,
				bool include_self)
{
	return list_of_nodes(ctdb,
			     node_map,
			     mem_ctx,
			     NODE_FLAGS_INACTIVE,
			     include_self);
}

uint32_t *list_of_connected_nodes(struct ctdb_context *ctdb,
				struct ctdb_node_map_old *node_map,
				TALLOC_CTX *mem_ctx,
				bool include_self)
{
	return list_of_nodes(ctdb,
			     node_map,
			     mem_ctx,
			     NODE_FLAGS_DISCONNECTED,
			     include_self);
}

/*
  get capabilities of a remote node
 */
struct ctdb_client_control_state *
ctdb_ctrl_getcapabilities_send(struct ctdb_context *ctdb, TALLOC_CTX *mem_ctx, struct timeval timeout, uint32_t destnode)
{
	return ctdb_control_send(ctdb, destnode, 0,
			   CTDB_CONTROL_GET_CAPABILITIES, 0, tdb_null,
			   mem_ctx, &timeout, NULL);
}

int ctdb_ctrl_getcapabilities_recv(struct ctdb_context *ctdb, TALLOC_CTX *mem_ctx, struct ctdb_client_control_state *state, uint32_t *capabilities)
{
	int ret;
	int32_t res;
	TDB_DATA outdata;

	ret = ctdb_control_recv(ctdb, state, mem_ctx, &outdata, &res, NULL);
	if ( (ret != 0) || (res != 0) ) {
		DEBUG(DEBUG_ERR,(__location__ " ctdb_ctrl_getcapabilities_recv failed\n"));
		return -1;
	}

	if (capabilities) {
		*capabilities = *((uint32_t *)outdata.dptr);
	}

	return 0;
}

int ctdb_ctrl_getcapabilities(struct ctdb_context *ctdb, struct timeval timeout, uint32_t destnode, uint32_t *capabilities)
{
	struct ctdb_client_control_state *state;
	TALLOC_CTX *tmp_ctx = talloc_new(NULL);
	int ret;

	state = ctdb_ctrl_getcapabilities_send(ctdb, tmp_ctx, timeout, destnode);
	ret = ctdb_ctrl_getcapabilities_recv(ctdb, tmp_ctx, state, capabilities);
	talloc_free(tmp_ctx);
	return ret;
}

static void get_capabilities_callback(struct ctdb_context *ctdb,
				      uint32_t node_pnn, int32_t res,
				      TDB_DATA outdata, void *callback_data)
{
	struct ctdb_node_capabilities *caps =
		talloc_get_type(callback_data,
				struct ctdb_node_capabilities);

	if ( (outdata.dsize != sizeof(uint32_t)) || (outdata.dptr == NULL) ) {
		DEBUG(DEBUG_ERR, (__location__ " Invalid length/pointer for getcap callback : %u %p\n",  (unsigned)outdata.dsize, outdata.dptr));
		return;
	}

	if (node_pnn >= talloc_array_length(caps)) {
		DEBUG(DEBUG_ERR,
		      (__location__ " unexpected PNN %u\n", node_pnn));
		return;
	}

	caps[node_pnn].retrieved = true;
	caps[node_pnn].capabilities = *((uint32_t *)outdata.dptr);
}

struct ctdb_node_capabilities *
ctdb_get_capabilities(struct ctdb_context *ctdb,
		      TALLOC_CTX *mem_ctx,
		      struct timeval timeout,
		      struct ctdb_node_map_old *nodemap)
{
	uint32_t *nodes;
	uint32_t i, res;
	struct ctdb_node_capabilities *ret;

	nodes = list_of_active_nodes(ctdb, nodemap, mem_ctx, true);

	ret = talloc_array(mem_ctx, struct ctdb_node_capabilities,
			   nodemap->num);
	CTDB_NO_MEMORY_NULL(ctdb, ret);
	/* Prepopulate the expected PNNs */
	for (i = 0; i < talloc_array_length(ret); i++) {
		ret[i].retrieved = false;
	}

	res = ctdb_client_async_control(ctdb, CTDB_CONTROL_GET_CAPABILITIES,
					nodes, 0, timeout,
					false, tdb_null,
					get_capabilities_callback, NULL,
					ret);
	if (res != 0) {
		DEBUG(DEBUG_ERR,
		      (__location__ " Failed to read node capabilities.\n"));
		TALLOC_FREE(ret);
	}

	return ret;
}

uint32_t *
ctdb_get_node_capabilities(struct ctdb_node_capabilities *caps,
			   uint32_t pnn)
{
	if (pnn < talloc_array_length(caps) && caps[pnn].retrieved) {
		return &caps[pnn].capabilities;
	}

	return NULL;
}

bool ctdb_node_has_capabilities(struct ctdb_node_capabilities *caps,
				uint32_t pnn,
				uint32_t capabilities_required)
{
	uint32_t *capp = ctdb_get_node_capabilities(caps, pnn);
	return (capp != NULL) &&
		((*capp & capabilities_required) == capabilities_required);
}

/*
  recovery daemon ping to main daemon
 */
int ctdb_ctrl_recd_ping(struct ctdb_context *ctdb)
{
	int ret;
	int32_t res;

	ret = ctdb_control(ctdb, CTDB_CURRENT_NODE, 0, CTDB_CONTROL_RECD_PING, 0, tdb_null,
			   ctdb, NULL, &res, NULL, NULL);
	if (ret != 0 || res != 0) {
		DEBUG(DEBUG_ERR,("Failed to send recd ping\n"));
		return -1;
	}

	return 0;
}

/*
  tell the main daemon how long it took to lock the reclock file
 */
int ctdb_ctrl_report_recd_lock_latency(struct ctdb_context *ctdb, struct timeval timeout, double latency)
{
	int ret;
	int32_t res;
	TDB_DATA data;

	data.dptr = (uint8_t *)&latency;
	data.dsize = sizeof(latency);

	ret = ctdb_control(ctdb, CTDB_CURRENT_NODE, 0, CTDB_CONTROL_RECD_RECLOCK_LATENCY, 0, data,
			   ctdb, NULL, &res, NULL, NULL);
	if (ret != 0 || res != 0) {
		DEBUG(DEBUG_ERR,("Failed to send recd reclock latency\n"));
		return -1;
	}

	return 0;
}

int ctdb_ctrl_set_ban(struct ctdb_context *ctdb, struct timeval timeout,
		      uint32_t destnode, struct ctdb_ban_state *bantime)
{
	int ret;
	TDB_DATA data;
	int32_t res;

	data.dsize = sizeof(*bantime);
	data.dptr  = (uint8_t *)bantime;

	ret = ctdb_control(ctdb, destnode, 0,
			   CTDB_CONTROL_SET_BAN_STATE, 0, data,
			   NULL, NULL, &res, &timeout, NULL);
	if (ret != 0 || res != 0) {
		DEBUG(DEBUG_ERR,(__location__ " ctdb_control for set ban state failed\n"));
		return -1;
	}

	return 0;
}

struct ctdb_client_control_state *
ctdb_ctrl_updaterecord_send(struct ctdb_context *ctdb, TALLOC_CTX *mem_ctx, struct timeval timeout, uint32_t destnode, struct ctdb_db_context *ctdb_db, TDB_DATA key, struct ctdb_ltdb_header *header, TDB_DATA data)
{
	struct ctdb_client_control_state *handle;
	struct ctdb_marshall_buffer *m;
	struct ctdb_rec_data_old *rec;
	TDB_DATA outdata;

	m = talloc_zero(mem_ctx, struct ctdb_marshall_buffer);
	if (m == NULL) {
		DEBUG(DEBUG_ERR, ("Failed to allocate marshall buffer for update record\n"));
		return NULL;
	}

	m->db_id = ctdb_db->db_id;

	rec = ctdb_marshall_record(m, 0, key, header, data);
	if (rec == NULL) {
		DEBUG(DEBUG_ERR,("Failed to marshall record for update record\n"));
		talloc_free(m);
		return NULL;
	}
	m = talloc_realloc_size(mem_ctx, m, rec->length + offsetof(struct ctdb_marshall_buffer, data));
	if (m == NULL) {
		DEBUG(DEBUG_CRIT,(__location__ " Failed to expand recdata\n"));
		talloc_free(m);
		return NULL;
	}
	m->count++;
	memcpy((uint8_t *)m + offsetof(struct ctdb_marshall_buffer, data), rec, rec->length);


	outdata.dptr = (uint8_t *)m;
	outdata.dsize = talloc_get_size(m);

	handle = ctdb_control_send(ctdb, destnode, 0,
			   CTDB_CONTROL_UPDATE_RECORD, 0, outdata,
			   mem_ctx, &timeout, NULL);
	talloc_free(m);
	return handle;
}

int ctdb_ctrl_updaterecord_recv(struct ctdb_context *ctdb, struct ctdb_client_control_state *state)
{
	int ret;
	int32_t res;

	ret = ctdb_control_recv(ctdb, state, state, NULL, &res, NULL);
	if ( (ret != 0) || (res != 0) ){
		DEBUG(DEBUG_ERR,(__location__ " ctdb_ctrl_update_record_recv failed\n"));
		return -1;
	}

	return 0;
}

int
ctdb_ctrl_updaterecord(struct ctdb_context *ctdb, TALLOC_CTX *mem_ctx, struct timeval timeout, uint32_t destnode, struct ctdb_db_context *ctdb_db, TDB_DATA key, struct ctdb_ltdb_header *header, TDB_DATA data)
{
	struct ctdb_client_control_state *state;

	state = ctdb_ctrl_updaterecord_send(ctdb, mem_ctx, timeout, destnode, ctdb_db, key, header, data);
	return ctdb_ctrl_updaterecord_recv(ctdb, state);
}
