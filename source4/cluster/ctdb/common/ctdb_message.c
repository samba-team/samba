/* 
   ctdb_message protocol code

   Copyright (C) Andrew Tridgell  2007

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
