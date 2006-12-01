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

#include "includes.h"
#include "lib/events/events.h"
#include "system/network.h"
#include "system/filesys.h"
#include "ctdb_private.h"


/*
  local version of ctdb_call
*/
static int ctdb_call_local(struct ctdb_context *ctdb, TDB_DATA key, int call_id, 
			   TDB_DATA *call_data, TDB_DATA *reply_data)
{
	struct ctdb_call *c;
	struct ctdb_registered_call *fn;
	TDB_DATA data;

	c = talloc(ctdb, struct ctdb_call);
	CTDB_NO_MEMORY(ctdb, c);

	data = tdb_fetch(ctdb->ltdb, key);
	
	c->key = key;
	c->call_data = call_data;
	c->record_data.dptr = talloc_memdup(c, data.dptr, data.dsize);
	c->record_data.dsize = data.dsize;
	CTDB_NO_MEMORY(ctdb, c->record_data.dptr);
	if (data.dptr) free(data.dptr);
	c->new_data = NULL;
	c->reply_data = NULL;

	for (fn=ctdb->calls;fn;fn=fn->next) {
		if (fn->id == call_id) break;
	}
	if (fn == NULL) {
		ctdb_set_error(ctdb, "Unknown call id %u\n", call_id);
		return -1;
	}

	if (fn->fn(c) != 0) {
		free(c->record_data.dptr);
		ctdb_set_error(ctdb, "ctdb_call %u failed\n", call_id);
		return -1;
	}

	if (c->new_data) {
		if (tdb_store(ctdb->ltdb, key, *c->new_data, TDB_REPLACE) != 0) {
			ctdb_set_error(ctdb, "ctdb_call tdb_store failed\n");
			return -1;
		}
	}

	if (reply_data) {
		if (c->reply_data) {
			*reply_data = *c->reply_data;
			talloc_steal(ctdb, reply_data->dptr);
		} else {
			reply_data->dptr = NULL;
			reply_data->dsize = 0;
		}
	}

	talloc_free(c);

	return 0;
}

/*
  called when a CTDB_REQ_CALL packet comes in
*/
void ctdb_request_call(struct ctdb_context *ctdb, struct ctdb_req_header *hdr)
{
	struct ctdb_req_call *c = (struct ctdb_req_call *)hdr;
	TDB_DATA key, call_data, reply_data;
	struct ctdb_reply_call *r;
	struct ctdb_node *node;

	key.dptr = c->data;
	key.dsize = c->keylen;
	call_data.dptr = c->data + c->keylen;
	call_data.dsize = c->calldatalen;

	ctdb_call_local(ctdb, key, c->callid, 
			call_data.dsize?&call_data:NULL,
			&reply_data);

	r = talloc_size(ctdb, sizeof(*r) + reply_data.dsize);
	r->hdr.length = sizeof(*r) + reply_data.dsize;
	r->hdr.operation = CTDB_REPLY_CALL;
	r->hdr.destnode  = hdr->srcnode;
	r->hdr.srcnode   = hdr->destnode;
	r->hdr.reqid     = hdr->reqid;
	r->datalen       = reply_data.dsize;
	memcpy(&r->data[0], reply_data.dptr, reply_data.dsize);

	node = ctdb->nodes[hdr->srcnode];

	ctdb->methods->queue_pkt(node, (uint8_t *)r, r->hdr.length);

	talloc_free(reply_data.dptr);
	talloc_free(r);
}

enum call_state {CTDB_CALL_WAIT, CTDB_CALL_DONE, CTDB_CALL_ERROR};

/*
  state of a in-progress ctdb call
*/
struct ctdb_call_state {
	enum call_state state;
	struct ctdb_req_call *c;
	struct ctdb_node *node;
	TDB_DATA reply_data;
};


/*
  called when a CTDB_REPLY_CALL packet comes in
*/
void ctdb_reply_call(struct ctdb_context *ctdb, struct ctdb_req_header *hdr)
{
	struct ctdb_reply_call *c = (struct ctdb_reply_call *)hdr;
	struct ctdb_call_state *state;
	TDB_DATA reply_data;

	state = idr_find(ctdb->idr, hdr->reqid);

	reply_data.dptr = c->data;
	reply_data.dsize = c->datalen;

	state->reply_data = reply_data;

	talloc_steal(state, c);

	state->state = CTDB_CALL_DONE;
}

/*
  destroy a ctdb_call
*/
static int ctdb_call_destructor(struct ctdb_call_state *state)
{
	idr_remove(state->node->ctdb->idr, state->c->hdr.reqid);
	return 0;
}

/*
  called when a call times out
*/
void ctdb_call_timeout(struct event_context *ev, struct timed_event *te, 
		       struct timeval t, void *private)
{
	struct ctdb_call_state *state = talloc_get_type(private, struct ctdb_call_state);
	state->state = CTDB_CALL_ERROR;
	ctdb_set_error(state->node->ctdb, "ctdb_call timed out");
}

/*
  fake an event driven local ctdb_call
*/
struct ctdb_call_state *ctdb_call_local_send(struct ctdb_context *ctdb, 
					     TDB_DATA key, int call_id, 
					     TDB_DATA *call_data, TDB_DATA *reply_data)
{
	struct ctdb_call_state *state;
	int ret;

	state = talloc_zero(ctdb, struct ctdb_call_state);
	CTDB_NO_MEMORY(ctdb, state);

	state->state = CTDB_CALL_DONE;
	state->node = ctdb->nodes[ctdb->vnn];

	ret = ctdb_call_local(ctdb, key, call_id, call_data, &state->reply_data);
	return state;
}


/*
  make a remote ctdb call - async send
*/
struct ctdb_call_state *ctdb_call_send(struct ctdb_context *ctdb, 
				       TDB_DATA key, int call_id, 
				       TDB_DATA *call_data, TDB_DATA *reply_data)
{
	uint32_t dest;
	uint32_t len;
	struct ctdb_call_state *state;

	dest = ctdb_hash(&key) % ctdb->num_nodes;
	if (dest == ctdb->vnn && !(ctdb->flags & CTDB_FLAG_SELF_CONNECT)) {
		return ctdb_call_local_send(ctdb, key, call_id, call_data, reply_data);
	}

	state = talloc_zero(ctdb, struct ctdb_call_state);
	CTDB_NO_MEMORY(ctdb, state);

	len = sizeof(*state->c) + key.dsize + (call_data?call_data->dsize:0);
	state->c = talloc_size(ctdb, len);
	CTDB_NO_MEMORY(ctdb, state->c);

	state->c->hdr.length    = len;
	state->c->hdr.operation = CTDB_REQ_CALL;
	state->c->hdr.destnode  = dest;
	state->c->hdr.srcnode   = ctdb->vnn;
	/* this limits us to 16k outstanding messages - not unreasonable */
	state->c->hdr.reqid     = idr_get_new(ctdb->idr, state, 0xFFFF);
	state->c->callid        = call_id;
	state->c->keylen        = key.dsize;
	state->c->calldatalen   = call_data?call_data->dsize:0;
	memcpy(&state->c->data[0], key.dptr, key.dsize);
	if (call_data) {
		memcpy(&state->c->data[key.dsize], call_data->dptr, call_data->dsize);
	}

	state->node = ctdb->nodes[dest];
	state->state = CTDB_CALL_WAIT;

	talloc_set_destructor(state, ctdb_call_destructor);

	if (ctdb->methods->queue_pkt(state->node, (uint8_t *)state->c, len) != 0) {
		talloc_free(state);
		return NULL;
	}

	event_add_timed(ctdb->ev, state, timeval_current_ofs(CTDB_REQ_TIMEOUT, 0), 
			ctdb_call_timeout, state);
	return state;
}


/*
  make a remote ctdb call - async recv
*/
int ctdb_call_recv(struct ctdb_call_state *state, TDB_DATA *reply_data)
{
	while (state->state < CTDB_CALL_DONE) {
		event_loop_once(state->node->ctdb->ev);
	}
	if (state->state != CTDB_CALL_DONE) {
		talloc_free(state);
		return -1;
	}
	if (reply_data) {
		reply_data->dptr = talloc_memdup(state->node->ctdb,
						 state->reply_data.dptr,
						 state->reply_data.dsize);
		reply_data->dsize = state->reply_data.dsize;
	}
	talloc_free(state);
	return 0;
}

/*
  full ctdb_call
*/
int ctdb_call(struct ctdb_context *ctdb, 
	      TDB_DATA key, int call_id, 
	      TDB_DATA *call_data, TDB_DATA *reply_data)
{
	struct ctdb_call_state *state;
	state = ctdb_call_send(ctdb, key, call_id, call_data, reply_data);
	return ctdb_call_recv(state, reply_data);
}
