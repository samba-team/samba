/* 
   ctdb_message protocol code

   Copyright (C) Andrew Tridgell  2007

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
  called when a CTDB_REQ_MESSAGE packet comes in

  this dispatches the messages to the registered ctdb message handler
*/
void ctdb_request_message(struct ctdb_context *ctdb, struct ctdb_req_header *hdr)
{
	struct ctdb_req_message *c = (struct ctdb_req_message *)hdr;
	struct ctdb_message_list *ml;
	TDB_DATA data;

	/* XXX we need a must faster way of finding the matching srvid
	   - maybe a tree? */
	for (ml=ctdb->message_list;ml;ml=ml->next) {
		if (ml->srvid == c->srvid) break;
	}
	if (ml == NULL) {
		printf("no msg handler\n");
		/* no registered message handler */
		return;
	}

	data.dptr = &c->data[0];
	data.dsize = c->datalen;
	ml->message_handler(ctdb, c->srvid, data, ml->message_private);
}


/*
  send a ctdb message
*/
int ctdb_daemon_send_message(struct ctdb_context *ctdb, uint32_t vnn,
		      uint32_t srvid, TDB_DATA data)
{
	struct ctdb_req_message *r;
	int len;

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
	
	ctdb_queue_packet(ctdb, &r->hdr);

	talloc_free(r);
	return 0;
}

/*
  send a ctdb message
*/
int ctdb_send_message(struct ctdb_context *ctdb, uint32_t vnn,
		      uint32_t srvid, TDB_DATA data)
{
	if (ctdb->flags & CTDB_FLAG_DAEMON_MODE) {
		return ctdb_client_send_message(ctdb, vnn, srvid, data);
	}
	return ctdb_daemon_send_message(ctdb, vnn, srvid, data);
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
				  uint32_t srvid,
				  ctdb_message_fn_t handler,
				  void *private)
{
	struct ctdb_message_list *m;

	m = talloc(mem_ctx, struct ctdb_message_list);
	CTDB_NO_MEMORY(ctdb, m);

	m->ctdb            = ctdb;
	m->srvid           = srvid;
	m->message_handler = handler;
	m->message_private = private;
	
	DLIST_ADD(ctdb->message_list, m);

	talloc_set_destructor(m, message_handler_destructor);

	return 0;
}
