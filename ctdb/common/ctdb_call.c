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
  make a remote ctdb call
*/
int ctdb_call(struct ctdb_context *ctdb, TDB_DATA key, int call_id, 
	      TDB_DATA *call_data, TDB_DATA *reply_data)
{
	uint32_t dest;
	struct ctdb_req_call *c;
	uint32_t len;
	struct ctdb_node *node;

	dest = ctdb_hash(&key) % ctdb->num_nodes;
	if (dest == ctdb->vnn) {
		return ctdb_call_local(ctdb, key, call_id, call_data, reply_data);
	}

	len = sizeof(*c) + key.dsize + (call_data?call_data->dsize:0);
	c = talloc_size(ctdb, len);
	CTDB_NO_MEMORY(ctdb, c);

	c->hdr.operation = CTDB_OP_CALL;
	c->hdr.destnode  = dest;
	c->hdr.srcnode   = ctdb->vnn;
	/* this limits us to 16k outstanding messages - not unreasonable */
	c->hdr.reqid     = idr_get_new(ctdb->idr, c, 0xFFFF);
	c->callid        = call_id;
	c->keylen        = key.dsize;
	c->calldatalen   = call_data?call_data->dsize:0;
	memcpy(&c->data[0], key.dptr, key.dsize);
	if (call_data) {
		memcpy(&c->data[key.dsize], call_data->dptr, call_data->dsize);
	}

	node = ctdb->nodes[dest];

	if (ctdb->methods->queue_pkt(node, (uint8_t *)c, len) != 0) {
		talloc_free(c);
		return -1;
	}

	/*
	event_add_timed(ctdb->ev, c, timeval_current_ofs(CTDB_REQ_TIMEOUT, 0), 
			ctdb_call_timeout, c);
	*/
	return -1;
}

