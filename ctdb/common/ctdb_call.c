/* 
   ctdb_call protocol code

   Copyright (C) Andrew Tridgell  2006

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
/*
  see http://wiki.samba.org/index.php/Samba_%26_Clustering for
  protocol design and packet details
*/
#include "includes.h"
#include "lib/events/events.h"
#include "lib/tdb/include/tdb.h"
#include "system/network.h"
#include "system/filesys.h"
#include "../include/ctdb_private.h"

/*
  find the ctdb_db from a db index
 */
 struct ctdb_db_context *find_ctdb_db(struct ctdb_context *ctdb, uint32_t id)
{
	struct ctdb_db_context *ctdb_db;

	for (ctdb_db=ctdb->db_list; ctdb_db; ctdb_db=ctdb_db->next) {
		if (ctdb_db->db_id == id) {
			break;
		}
	}
	return ctdb_db;
}


/*
  local version of ctdb_call
*/
int ctdb_call_local(struct ctdb_db_context *ctdb_db, struct ctdb_call *call,
		    struct ctdb_ltdb_header *header, TDB_DATA *data,
		    uint32_t caller)
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
  send an error reply
*/
static void ctdb_send_error(struct ctdb_context *ctdb, 
			    struct ctdb_req_header *hdr, uint32_t status,
			    const char *fmt, ...) PRINTF_ATTRIBUTE(4,5);
static void ctdb_send_error(struct ctdb_context *ctdb, 
			    struct ctdb_req_header *hdr, uint32_t status,
			    const char *fmt, ...)
{
	va_list ap;
	struct ctdb_reply_error *r;
	char *msg;
	int msglen, len;

	va_start(ap, fmt);
	msg = talloc_vasprintf(ctdb, fmt, ap);
	if (msg == NULL) {
		ctdb_fatal(ctdb, "Unable to allocate error in ctdb_send_error\n");
	}
	va_end(ap);

	msglen = strlen(msg)+1;
	len = offsetof(struct ctdb_reply_error, msg);
	r = ctdb->methods->allocate_pkt(msg, len + msglen);
	CTDB_NO_MEMORY_FATAL(ctdb, r);
	talloc_set_name_const(r, "send_error packet");

	r->hdr.length    = len + msglen;
	r->hdr.ctdb_magic = CTDB_MAGIC;
	r->hdr.ctdb_version = CTDB_VERSION;
	r->hdr.operation = CTDB_REPLY_ERROR;
	r->hdr.destnode  = hdr->srcnode;
	r->hdr.srcnode   = ctdb->vnn;
	r->hdr.reqid     = hdr->reqid;
	r->status        = status;
	r->msglen        = msglen;
	memcpy(&r->msg[0], msg, msglen);

	ctdb_queue_packet(ctdb, &r->hdr);

	talloc_free(msg);
}


/*
  send a redirect reply
*/
static void ctdb_call_send_redirect(struct ctdb_context *ctdb, 
				    struct ctdb_req_call *c, 
				    struct ctdb_ltdb_header *header)
{
	struct ctdb_reply_redirect *r;

	r = ctdb->methods->allocate_pkt(ctdb, sizeof(*r));
	CTDB_NO_MEMORY_FATAL(ctdb, r);
	talloc_set_name_const(r, "send_redirect packet");
	r->hdr.length = sizeof(*r);
	r->hdr.ctdb_magic = CTDB_MAGIC;
	r->hdr.ctdb_version = CTDB_VERSION;
	r->hdr.operation = CTDB_REPLY_REDIRECT;
	r->hdr.destnode  = c->hdr.srcnode;
	r->hdr.srcnode   = ctdb->vnn;
	r->hdr.reqid     = c->hdr.reqid;
	r->dmaster       = header->dmaster;

	ctdb_queue_packet(ctdb, &r->hdr);

	talloc_free(r);
}


/*
  send a dmaster reply

  caller must have the chainlock before calling this routine. Caller must be
  the lmaster
*/
static void ctdb_send_dmaster_reply(struct ctdb_db_context *ctdb_db,
				    struct ctdb_ltdb_header *header,
				    TDB_DATA key, TDB_DATA data,
				    uint32_t new_dmaster,
				    uint32_t reqid)
{
	struct ctdb_context *ctdb = ctdb_db->ctdb;
	struct ctdb_reply_dmaster *r;
	int ret, len;
	TALLOC_CTX *tmp_ctx;

	if (ctdb->vnn != ctdb_lmaster(ctdb, &key)) {
		DEBUG(0,(__location__ " Caller is not lmaster!\n"));
		return;
	}

	header->dmaster = new_dmaster;
	ret = ctdb_ltdb_store(ctdb_db, key, header, data);
	if (ret != 0) {
		ctdb_fatal(ctdb, "ctdb_req_dmaster unable to update dmaster");
		return;
	}

	/* put the packet on a temporary context, allowing us to safely free
	   it below even if ctdb_reply_dmaster() has freed it already */
	tmp_ctx = talloc_new(ctdb);

	/* send the CTDB_REPLY_DMASTER */
	len = offsetof(struct ctdb_reply_dmaster, data) + data.dsize;
	r = ctdb->methods->allocate_pkt(tmp_ctx, len);
	CTDB_NO_MEMORY_FATAL(ctdb, r);

	talloc_set_name_const(r, "reply_dmaster packet");
	r->hdr.length    = len;
	r->hdr.ctdb_magic = CTDB_MAGIC;
	r->hdr.ctdb_version = CTDB_VERSION;
	r->hdr.operation = CTDB_REPLY_DMASTER;
	r->hdr.destnode  = new_dmaster;
	r->hdr.srcnode   = ctdb->vnn;
	r->hdr.reqid     = reqid;
	r->datalen       = data.dsize;
	memcpy(&r->data[0], data.dptr, data.dsize);

	ctdb_queue_packet(ctdb, &r->hdr);

	talloc_free(tmp_ctx);
}

/*
  send a dmaster request (give another node the dmaster for a record)

  This is always sent to the lmaster, which ensures that the lmaster
  always knows who the dmaster is. The lmaster will then send a
  CTDB_REPLY_DMASTER to the new dmaster
*/
static void ctdb_call_send_dmaster(struct ctdb_db_context *ctdb_db, 
				   struct ctdb_req_call *c, 
				   struct ctdb_ltdb_header *header,
				   TDB_DATA *key, TDB_DATA *data)
{
	struct ctdb_req_dmaster *r;
	struct ctdb_context *ctdb = ctdb_db->ctdb;
	int len;
	uint32_t lmaster = ctdb_lmaster(ctdb, key);

	if (lmaster == ctdb->vnn) {
		ctdb_send_dmaster_reply(ctdb_db, header, *key, *data, 
					c->hdr.srcnode, c->hdr.reqid);
		return;
	}
	
	len = offsetof(struct ctdb_req_dmaster, data) + key->dsize + data->dsize;
	r = ctdb->methods->allocate_pkt(ctdb, len);
	CTDB_NO_MEMORY_FATAL(ctdb, r);
	talloc_set_name_const(r, "send_dmaster packet");
	r->hdr.length    = len;
	r->hdr.ctdb_magic = CTDB_MAGIC;
	r->hdr.ctdb_version = CTDB_VERSION;
	r->hdr.operation = CTDB_REQ_DMASTER;
	r->hdr.destnode  = lmaster;
	r->hdr.srcnode   = ctdb->vnn;
	r->hdr.reqid     = c->hdr.reqid;
	r->db_id         = c->db_id;
	r->dmaster       = c->hdr.srcnode;
	r->keylen        = key->dsize;
	r->datalen       = data->dsize;
	memcpy(&r->data[0], key->dptr, key->dsize);
	memcpy(&r->data[key->dsize], data->dptr, data->dsize);

	header->dmaster = c->hdr.srcnode;
	ctdb_ltdb_store(ctdb_db, *key, header, *data);
	
	ctdb_queue_packet(ctdb, &r->hdr);

	talloc_free(r);
}

/*
  called when a CTDB_REPLY_DMASTER packet comes in, or when the lmaster
  gets a CTDB_REQUEST_DMASTER for itself. We become the dmaster.

  must be called with the chainlock held. This function releases the chainlock
*/
static void ctdb_become_dmaster(struct ctdb_context *ctdb, 
				uint32_t reqid, TDB_DATA data)
{
	struct ctdb_call_state *state;
	struct ctdb_db_context *ctdb_db;

	state = ctdb_reqid_find(ctdb, reqid, struct ctdb_call_state);

	if (state == NULL) {
		return;
	}

	if (reqid != state->reqid) {
		/* we found a record  but it was the wrong one */
		DEBUG(0, ("Dropped orphaned dmaster reply with reqid:%d\n",reqid));
		return;
	}

	ctdb_db = state->ctdb_db;

	DEBUG(2,("vnn %u dmaster response %08x\n", 
		 ctdb->vnn, ctdb_hash(&state->call.key)));

	/* we're now the dmaster - update our local ltdb with new header
	   and data */
	state->header.dmaster = ctdb->vnn;

	if (ctdb_ltdb_store(ctdb_db, state->call.key, &state->header, data) != 0) {
		ctdb_fatal(ctdb, "ctdb_reply_dmaster store failed\n");
		return;
	}

	ctdb_call_local(ctdb_db, &state->call, &state->header, &data, ctdb->vnn);

	ctdb_ltdb_unlock(ctdb_db, state->call.key);

	talloc_steal(state, state->call.reply_data.dptr);

	state->state = CTDB_CALL_DONE;
	if (state->async.fn) {
		state->async.fn(state);
	}
}



/*
  called when a CTDB_REQ_DMASTER packet comes in

  this comes into the lmaster for a record when the current dmaster
  wants to give up the dmaster role and give it to someone else
*/
void ctdb_request_dmaster(struct ctdb_context *ctdb, struct ctdb_req_header *hdr)
{
	struct ctdb_req_dmaster *c = (struct ctdb_req_dmaster *)hdr;
	TDB_DATA key, data, data2;
	struct ctdb_ltdb_header header;
	struct ctdb_db_context *ctdb_db;
	int ret;

	key.dptr = c->data;
	key.dsize = c->keylen;
	data.dptr = c->data + c->keylen;
	data.dsize = c->datalen;

	ctdb_db = find_ctdb_db(ctdb, c->db_id);
	if (!ctdb_db) {
		ctdb_send_error(ctdb, hdr, -1,
				"Unknown database in request. db_id==0x%08x",
				c->db_id);
		return;
	}
	
	/* fetch the current record */
	ret = ctdb_ltdb_lock_fetch_requeue(ctdb_db, key, &header, hdr, &data2,
					   ctdb_recv_raw_pkt, ctdb);
	if (ret == -1) {
		ctdb_fatal(ctdb, "ctdb_req_dmaster failed to fetch record");
		return;
	}
	if (ret == -2) {
		DEBUG(2,(__location__ " deferring ctdb_request_dmaster\n"));
		return;
	}

	if (ctdb_lmaster(ctdb, &key) != ctdb->vnn) {
		DEBUG(0,("vnn %u dmaster request to non-lmaster lmaster=%u\n",
			 ctdb->vnn, ctdb_lmaster(ctdb, &key)));
		ctdb_fatal(ctdb, "ctdb_req_dmaster to non-lmaster");
	}

	DEBUG(2,("vnn %u dmaster request on %08x for %u from %u\n", 
		 ctdb->vnn, ctdb_hash(&key), c->dmaster, c->hdr.srcnode));

	/* its a protocol error if the sending node is not the current dmaster */
	if (header.dmaster != hdr->srcnode) {
		DEBUG(0,("vnn %u dmaster request non-master %u dmaster=%u key %08x\n",
			 ctdb->vnn, hdr->srcnode, header.dmaster, ctdb_hash(&key)));
		ctdb_fatal(ctdb, "ctdb_req_dmaster from non-master");
		return;
	}

	/* check if the new dmaster is the lmaster, in which case we
	   skip the dmaster reply */
	if (c->dmaster == ctdb->vnn) {
		ctdb_become_dmaster(ctdb, hdr->reqid, data);
	} else {
		ctdb_send_dmaster_reply(ctdb_db, &header, key, data, c->dmaster, hdr->reqid);
		ctdb_ltdb_unlock(ctdb_db, key);
	}
}


/*
  called when a CTDB_REQ_CALL packet comes in
*/
void ctdb_request_call(struct ctdb_context *ctdb, struct ctdb_req_header *hdr)
{
	struct ctdb_req_call *c = (struct ctdb_req_call *)hdr;
	TDB_DATA data;
	struct ctdb_reply_call *r;
	int ret, len;
	struct ctdb_ltdb_header header;
	struct ctdb_call call;
	struct ctdb_db_context *ctdb_db;

	ctdb_db = find_ctdb_db(ctdb, c->db_id);
	if (!ctdb_db) {
		ctdb_send_error(ctdb, hdr, -1,
				"Unknown database in request. db_id==0x%08x",
				c->db_id);
		return;
	}

	call.call_id  = c->callid;
	call.key.dptr = c->data;
	call.key.dsize = c->keylen;
	call.call_data.dptr = c->data + c->keylen;
	call.call_data.dsize = c->calldatalen;

	/* determine if we are the dmaster for this key. This also
	   fetches the record data (if any), thus avoiding a 2nd fetch of the data 
	   if the call will be answered locally */

	ret = ctdb_ltdb_lock_fetch_requeue(ctdb_db, call.key, &header, hdr, &data,
					   ctdb_recv_raw_pkt, ctdb);
	if (ret == -1) {
		ctdb_send_error(ctdb, hdr, ret, "ltdb fetch failed in ctdb_request_call");
		return;
	}
	if (ret == -2) {
		DEBUG(2,(__location__ " deferred ctdb_request_call\n"));
		return;
	}

	/* if we are not the dmaster, then send a redirect to the
	   requesting node */
	if (header.dmaster != ctdb->vnn) {
		ctdb_call_send_redirect(ctdb, c, &header);
		talloc_free(data.dptr);
		ctdb_ltdb_unlock(ctdb_db, call.key);
		return;
	}

	/* if this nodes has done enough consecutive calls on the same record
	   then give them the record
	   or if the node requested an immediate migration
	*/
	if ( c->hdr.srcnode != ctdb->vnn &&
	     ((header.laccessor == c->hdr.srcnode
	       && header.lacount >= ctdb->max_lacount)
	      || (c->flags&CTDB_IMMEDIATE_MIGRATION)) ) {
		DEBUG(2,("vnn %u starting migration of %08x to %u\n", 
			 ctdb->vnn, ctdb_hash(&call.key), c->hdr.srcnode));
		ctdb_call_send_dmaster(ctdb_db, c, &header, &call.key, &data);
		talloc_free(data.dptr);
		ctdb_ltdb_unlock(ctdb_db, call.key);
		return;
	}

	ctdb_call_local(ctdb_db, &call, &header, &data, c->hdr.srcnode);

	ctdb_ltdb_unlock(ctdb_db, call.key);

	len = offsetof(struct ctdb_reply_call, data) + call.reply_data.dsize;
	r = ctdb->methods->allocate_pkt(ctdb, len);
	CTDB_NO_MEMORY_FATAL(ctdb, r);
	talloc_set_name_const(r, "reply_call packet");
	r->hdr.length    = len;
	r->hdr.ctdb_magic = CTDB_MAGIC;
	r->hdr.ctdb_version = CTDB_VERSION;
	r->hdr.operation = CTDB_REPLY_CALL;
	r->hdr.destnode  = hdr->srcnode;
	r->hdr.srcnode   = hdr->destnode;
	r->hdr.reqid     = hdr->reqid;
	r->status        = call.status;
	r->datalen       = call.reply_data.dsize;
	if (call.reply_data.dsize) {
		memcpy(&r->data[0], call.reply_data.dptr, call.reply_data.dsize);
		talloc_free(call.reply_data.dptr);
	}

	ctdb_queue_packet(ctdb, &r->hdr);

	talloc_free(r);
}

/*
  called when a CTDB_REPLY_CALL packet comes in

  This packet comes in response to a CTDB_REQ_CALL request packet. It
  contains any reply data from the call
*/
void ctdb_reply_call(struct ctdb_context *ctdb, struct ctdb_req_header *hdr)
{
	struct ctdb_reply_call *c = (struct ctdb_reply_call *)hdr;
	struct ctdb_call_state *state;

	state = ctdb_reqid_find(ctdb, hdr->reqid, struct ctdb_call_state);
	if (state == NULL) {
		DEBUG(0, (__location__ " reqid %d not found\n", hdr->reqid));
		return;
	}

	if (hdr->reqid != state->reqid) {
		/* we found a record  but it was the wrong one */
		DEBUG(0, ("Dropped orphaned dmaster reply with reqid:%d\n",hdr->reqid));
		return;
	}

	state->call.reply_data.dptr = c->data;
	state->call.reply_data.dsize = c->datalen;
	state->call.status = c->status;

	talloc_steal(state, c);

	state->state = CTDB_CALL_DONE;
	if (state->async.fn) {
		state->async.fn(state);
	}
}


/*
  called when a CTDB_REPLY_DMASTER packet comes in

  This packet comes in from the lmaster response to a CTDB_REQ_CALL
  request packet. It means that the current dmaster wants to give us
  the dmaster role
*/
void ctdb_reply_dmaster(struct ctdb_context *ctdb, struct ctdb_req_header *hdr)
{
	struct ctdb_reply_dmaster *c = (struct ctdb_reply_dmaster *)hdr;
	struct ctdb_call_state *state;
	struct ctdb_db_context *ctdb_db;
	TDB_DATA data;
	int ret;

	state = ctdb_reqid_find(ctdb, hdr->reqid, struct ctdb_call_state);

	if (state == NULL) {
		return;
	}

	if (hdr->reqid != state->reqid) {
		/* we found a record  but it was the wrong one */
		DEBUG(0, ("Dropped orphaned dmaster reply with reqid:%d\n",hdr->reqid));
		return;
	}

	ctdb_db = state->ctdb_db;

	ret = ctdb_ltdb_lock_requeue(ctdb_db, state->call.key, hdr,
				     ctdb_recv_raw_pkt, ctdb);
	if (ret == -2) {
		return;
	}
	if (ret != 0) {
		DEBUG(0,(__location__ " Failed to get lock in ctdb_reply_dmaster\n"));
		return;
	}

	data.dptr = c->data;
	data.dsize = c->datalen;

	ctdb_become_dmaster(ctdb, hdr->reqid, data);
}


/*
  called when a CTDB_REPLY_ERROR packet comes in
*/
void ctdb_reply_error(struct ctdb_context *ctdb, struct ctdb_req_header *hdr)
{
	struct ctdb_reply_error *c = (struct ctdb_reply_error *)hdr;
	struct ctdb_call_state *state;

	state = ctdb_reqid_find(ctdb, hdr->reqid, struct ctdb_call_state);
	if (state == NULL) {
		return;
	}

	if (hdr->reqid != state->reqid) {
		/* we found a record  but it was the wrong one */
		DEBUG(0, ("Dropped orphaned dmaster reply with reqid:%d\n",hdr->reqid));
		return;
	}

	talloc_steal(state, c);

	state->state  = CTDB_CALL_ERROR;
	state->errmsg = (char *)c->msg;
	if (state->async.fn) {
		state->async.fn(state);
	}
}


/*
  called when a CTDB_REPLY_REDIRECT packet comes in

  This packet arrives when we have sent a CTDB_REQ_CALL request and
  the node that received it is not the dmaster for the given key. We
  are given a hint as to what node to try next.
*/
void ctdb_reply_redirect(struct ctdb_context *ctdb, struct ctdb_req_header *hdr)
{
	struct ctdb_reply_redirect *c = (struct ctdb_reply_redirect *)hdr;
	struct ctdb_call_state *state;

	state = ctdb_reqid_find(ctdb, hdr->reqid, struct ctdb_call_state);
	if (state == NULL) {
		return;
	}

	if (hdr->reqid != state->reqid) {
		/* we found a record  but it was the wrong one */
		DEBUG(0, ("Dropped orphaned dmaster reply with reqid:%d\n",hdr->reqid));
		return;
	}

	/* don't allow for too many redirects */
	if ((++state->redirect_count) % CTDB_MAX_REDIRECT == 0) {
		c->dmaster = ctdb_lmaster(ctdb, &state->call.key);
		if (state->redirect_count > ctdb->status.max_redirect_count) {
			ctdb->status.max_redirect_count = state->redirect_count;
		}
	}

	/* send it off again */
	state->node = ctdb->nodes[c->dmaster];
	state->c->hdr.destnode = c->dmaster;

	ctdb_queue_packet(ctdb, &state->c->hdr);
}

/*
  destroy a ctdb_call
*/
static int ctdb_call_destructor(struct ctdb_call_state *state)
{
	ctdb_reqid_remove(state->node->ctdb, state->reqid);
	return 0;
}


/*
  called when a ctdb_call times out
*/
void ctdb_call_timeout(struct event_context *ev, struct timed_event *te, 
		       struct timeval t, void *private_data)
{
	struct ctdb_call_state *state = talloc_get_type(private_data, struct ctdb_call_state);
	DEBUG(0,(__location__ " call timeout for reqid %d\n", state->c->hdr.reqid));
	state->state = CTDB_CALL_ERROR;
	ctdb_set_error(state->node->ctdb, "ctdb_call %u timed out",
		       state->c->hdr.reqid);
	if (state->async.fn) {
		state->async.fn(state);
	}
}

/*
  this allows the caller to setup a async.fn 
*/
static void call_local_trigger(struct event_context *ev, struct timed_event *te, 
		       struct timeval t, void *private_data)
{
	struct ctdb_call_state *state = talloc_get_type(private_data, struct ctdb_call_state);
	if (state->async.fn) {
		state->async.fn(state);
	}
}	


/*
  construct an event driven local ctdb_call

  this is used so that locally processed ctdb_call requests are processed
  in an event driven manner
*/
struct ctdb_call_state *ctdb_call_local_send(struct ctdb_db_context *ctdb_db, 
					     struct ctdb_call *call,
					     struct ctdb_ltdb_header *header,
					     TDB_DATA *data)
{
	struct ctdb_call_state *state;
	struct ctdb_context *ctdb = ctdb_db->ctdb;
	int ret;

	state = talloc_zero(ctdb_db, struct ctdb_call_state);
	CTDB_NO_MEMORY_NULL(ctdb, state);

	talloc_steal(state, data->dptr);

	state->state = CTDB_CALL_DONE;
	state->node = ctdb->nodes[ctdb->vnn];
	state->call = *call;
	state->ctdb_db = ctdb_db;

	ret = ctdb_call_local(ctdb_db, &state->call, header, data, ctdb->vnn);
	talloc_steal(state, state->call.reply_data.dptr);

	event_add_timed(ctdb->ev, state, timeval_zero(), call_local_trigger, state);

	return state;
}


/*
  make a remote ctdb call - async send. Called in daemon context.

  This constructs a ctdb_call request and queues it for processing. 
  This call never blocks.
*/
struct ctdb_call_state *ctdb_daemon_call_send_remote(struct ctdb_db_context *ctdb_db, 
						     struct ctdb_call *call, 
						     struct ctdb_ltdb_header *header)
{
	uint32_t len;
	struct ctdb_call_state *state;
	struct ctdb_context *ctdb = ctdb_db->ctdb;

	state = talloc_zero(ctdb_db, struct ctdb_call_state);
	CTDB_NO_MEMORY_NULL(ctdb, state);
	state->reqid = ctdb_reqid_new(ctdb, state);
	talloc_set_destructor(state, ctdb_call_destructor);

	len = offsetof(struct ctdb_req_call, data) + call->key.dsize + call->call_data.dsize;
	state->c = ctdb->methods->allocate_pkt(state, len);
	CTDB_NO_MEMORY_NULL(ctdb, state->c);
	talloc_set_name_const(state->c, "req_call packet");

	state->c->hdr.length    = len;
	state->c->hdr.ctdb_magic = CTDB_MAGIC;
	state->c->hdr.ctdb_version = CTDB_VERSION;
	state->c->hdr.operation = CTDB_REQ_CALL;
	state->c->hdr.destnode  = header->dmaster;
	/*
	   always sending the remote call straight to the lmaster
	   improved performance slightly in some tests.
	   worth investigating further in the future
	state->c->hdr.destnode  = ctdb_lmaster(ctdb_db->ctdb, &(call->key));
	*/


	state->c->hdr.srcnode   = ctdb->vnn;
	/* this limits us to 16k outstanding messages - not unreasonable */
	state->c->hdr.reqid     = state->reqid;
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

	state->node   = ctdb->nodes[header->dmaster];
	state->state  = CTDB_CALL_WAIT;
	state->header = *header;
	state->ctdb_db = ctdb_db;

	ctdb_queue_packet(ctdb, &state->c->hdr);

#if CTDB_REQ_TIMEOUT
	event_add_timed(ctdb->ev, state, timeval_current_ofs(CTDB_REQ_TIMEOUT, 0), 
			ctdb_call_timeout, state);
#endif
	return state;
}

/*
  make a remote ctdb call - async recv - called in daemon context

  This is called when the program wants to wait for a ctdb_call to complete and get the 
  results. This call will block unless the call has already completed.
*/
int ctdb_daemon_call_recv(struct ctdb_call_state *state, struct ctdb_call *call)
{
	while (state->state < CTDB_CALL_DONE) {
		event_loop_once(state->node->ctdb->ev);
	}
	if (state->state != CTDB_CALL_DONE) {
		ctdb_set_error(state->node->ctdb, "%s", state->errmsg);
		talloc_free(state);
		return -1;
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


