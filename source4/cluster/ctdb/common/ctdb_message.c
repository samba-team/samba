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
	TDB_DATA data;
	if (ctdb->message_handler == NULL) {
		/* no registered message handler */
		return;
	}
	data.dptr = &c->data[0];
	data.dsize = c->datalen;
	ctdb->message_handler(ctdb, c->srvid, data, ctdb->message_private);
}


/*
  send a ctdb message
*/
int ctdb_send_message(struct ctdb_context *ctdb, uint32_t vnn,
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
  setup handler for receipt of ctdb messages from ctdb_send_message()
*/
int ctdb_set_message_handler(struct ctdb_context *ctdb, ctdb_message_fn_t handler,
			     void *private)
{
	ctdb->message_handler = handler;
	ctdb->message_private = private;
	return 0;
}

