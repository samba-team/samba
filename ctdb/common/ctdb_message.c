/* 
   ctdb_message protocol code

   Copyright (C) Andrew Tridgell  2007

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
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
#include "lib/util/dlinklist.h"

/*
  this dispatches the messages to the registered ctdb message handler
*/
int ctdb_dispatch_message(struct ctdb_context *ctdb, uint64_t srvid, TDB_DATA data)
{
	struct ctdb_message_list *ml;

	for (ml=ctdb->message_list;ml;ml=ml->next) {
		if (ml->srvid == srvid || ml->srvid == CTDB_SRVID_ALL) {
			ml->message_handler(ctdb, srvid, data, ml->message_private);
		}
	}

	return 0;
}

/*
  called when a CTDB_REQ_MESSAGE packet comes in
*/
void ctdb_request_message(struct ctdb_context *ctdb, struct ctdb_req_header *hdr)
{
	struct ctdb_req_message *c = (struct ctdb_req_message *)hdr;
	TDB_DATA data;

	data.dptr = &c->data[0];
	data.dsize = c->datalen;

	ctdb_dispatch_message(ctdb, c->srvid, data);
}

/*
  this local messaging handler is ugly, but is needed to prevent
  recursion in ctdb_send_message() when the destination node is the
  same as the source node
 */
struct ctdb_local_message {
	struct ctdb_context *ctdb;
	uint64_t srvid;
	TDB_DATA data;
};

static void ctdb_local_message_trigger(struct event_context *ev, struct timed_event *te, 
				       struct timeval t, void *private_data)
{
	struct ctdb_local_message *m = talloc_get_type(private_data, 
						       struct ctdb_local_message);
	int res;

	res = ctdb_dispatch_message(m->ctdb, m->srvid, m->data);
	if (res != 0) {
		DEBUG(0, (__location__ " Failed to dispatch message for srvid=%llu\n", 
			  (unsigned long long)m->srvid));
	}
	talloc_free(m);
}

static int ctdb_local_message(struct ctdb_context *ctdb, uint64_t srvid, TDB_DATA data)
{
	struct ctdb_local_message *m;
	m = talloc(ctdb, struct ctdb_local_message);
	CTDB_NO_MEMORY(ctdb, m);

	m->ctdb = ctdb;
	m->srvid = srvid;
	m->data  = data;
	m->data.dptr = talloc_memdup(m, m->data.dptr, m->data.dsize);
	if (m->data.dptr == NULL) {
		talloc_free(m);
		return -1;
	}

	/* this needs to be done as an event to prevent recursion */
	event_add_timed(ctdb->ev, m, timeval_zero(), ctdb_local_message_trigger, m);
	return 0;
}

/*
  send a ctdb message
*/
int ctdb_daemon_send_message(struct ctdb_context *ctdb, uint32_t vnn,
			     uint64_t srvid, TDB_DATA data)
{
	struct ctdb_req_message *r;
	int len;

	/* see if this is a message to ourselves */
	if (vnn == ctdb->vnn && !(ctdb->flags & CTDB_FLAG_SELF_CONNECT)) {
		return ctdb_local_message(ctdb, srvid, data);
	}

	len = offsetof(struct ctdb_req_message, data) + data.dsize;
	r = ctdb_transport_allocate(ctdb, ctdb, CTDB_REQ_MESSAGE, len,
				    struct ctdb_req_message);
	CTDB_NO_MEMORY(ctdb, r);

	r->hdr.destnode  = vnn;
	r->srvid         = srvid;
	r->datalen       = data.dsize;
	memcpy(&r->data[0], data.dptr, data.dsize);

	ctdb_queue_packet(ctdb, &r->hdr);

	talloc_free(r);
	return 0;
}


/*
  when a client goes away, we need to remove its srvid handler from the list
 */
static int message_handler_destructor(struct ctdb_message_list *m)
{
	DLIST_REMOVE(m->ctdb->message_list, m);
	return 0;
}

/*
  setup handler for receipt of ctdb messages from ctdb_send_message()
*/
int ctdb_register_message_handler(struct ctdb_context *ctdb, 
				  TALLOC_CTX *mem_ctx,
				  uint64_t srvid,
				  ctdb_message_fn_t handler,
				  void *private_data)
{
	struct ctdb_message_list *m;

	m = talloc(mem_ctx, struct ctdb_message_list);
	CTDB_NO_MEMORY(ctdb, m);

	m->ctdb            = ctdb;
	m->srvid           = srvid;
	m->message_handler = handler;
	m->message_private = private_data;
	
	DLIST_ADD(ctdb->message_list, m);

	talloc_set_destructor(m, message_handler_destructor);

	return 0;
}


/*
  setup handler for receipt of ctdb messages from ctdb_send_message()
*/
int ctdb_deregister_message_handler(struct ctdb_context *ctdb, uint64_t srvid, void *private_data)
{
	struct ctdb_message_list *m;

	for (m=ctdb->message_list;m;m=m->next) {
		if (m->srvid == srvid && m->message_private == private_data) {
			talloc_free(m);
			return 0;
		}
	}
	return -1;
}
