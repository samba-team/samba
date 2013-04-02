/* 
   ctdb_message protocol code

   Copyright (C) Andrew Tridgell  2007
   Copyright (C) Amitay Isaacs  2013

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
#include "lib/tdb/include/tdb.h"
#include "system/network.h"
#include "system/filesys.h"
#include "../include/ctdb_private.h"
#include "lib/util/dlinklist.h"

static int message_list_db_init(struct ctdb_context *ctdb)
{
	ctdb->message_list_indexdb = tdb_open("messagedb", 8192,
					      TDB_INTERNAL|TDB_DISALLOW_NESTING,
					      O_RDWR|O_CREAT, 0);
	if (ctdb->message_list_indexdb == NULL) {
		DEBUG(DEBUG_ERR, ("Failed to create message list indexdb\n"));
		return -1;
	}

	return 0;
}

static int message_list_db_add(struct ctdb_context *ctdb, TDB_DATA key, TDB_DATA data)
{
	int ret;

	if (ctdb->message_list_indexdb == NULL) {
		ret = message_list_db_init(ctdb);
		if (ret < 0) {
			return -1;
		}
	}

	ret = tdb_store(ctdb->message_list_indexdb, key, data, TDB_INSERT);
	if (ret < 0) {
		DEBUG(DEBUG_ERR, ("Failed to add message list handler (%s)\n",
				  tdb_errorstr(ctdb->message_list_indexdb)));
		return -1;
	}

	return 0;
}

static int message_list_db_delete(struct ctdb_context *ctdb, TDB_DATA key)
{
	int ret;

	if (ctdb->message_list_indexdb == NULL) {
		return -1;
	}

	ret = tdb_delete(ctdb->message_list_indexdb, key);
	if (ret < 0) {
		DEBUG(DEBUG_ERR, ("Failed to delete message list handler (%s)\n",
				  tdb_errorstr(ctdb->message_list_indexdb)));
		return -1;
	}

	return 0;
}

static int message_list_db_fetch(struct ctdb_context *ctdb, TDB_DATA key, TDB_DATA *data)
{
	if (ctdb->message_list_indexdb == NULL) {
		return -1;
	}

	*data = tdb_fetch(ctdb->message_list_indexdb, key);
	if (data->dsize == 0) {
		return -1;
	}
	return 0;
}

/*
  this dispatches the messages to the registered ctdb message handler
*/
int ctdb_dispatch_message(struct ctdb_context *ctdb, uint64_t srvid, TDB_DATA data)
{
	struct ctdb_message_list_header *h;
	struct ctdb_message_list *m;
	TDB_DATA key, hdata;
	uint64_t srvid_all = CTDB_SRVID_ALL;
	int ret;

	key.dptr = (uint8_t *)&srvid;
	key.dsize = sizeof(uint64_t);

	ret = message_list_db_fetch(ctdb, key, &hdata);
	if (ret == 0) {
		h = *(struct ctdb_message_list_header **)hdata.dptr;

		for (m=h->m; m; m=m->next) {
			m->message_handler(ctdb, srvid, data, m->message_private);
		}
	}

	key.dptr = (uint8_t *)&srvid_all;
	key.dsize = sizeof(uint64_t);

	ret = message_list_db_fetch(ctdb, key, &hdata);
	if (ret == 0) {
		h = *(struct ctdb_message_list_header **)hdata.dptr;

		for(m=h->m; m; m=m->next) {
			m->message_handler(ctdb, srvid, data, m->message_private);
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

	data.dsize = c->datalen;
	data.dptr = talloc_memdup(c, &c->data[0], c->datalen);

	ctdb_dispatch_message(ctdb, c->srvid, data);
}

/*
 * When header is freed, remove all the srvid handlers
 */
static int message_header_destructor(struct ctdb_message_list_header *h)
{
	struct ctdb_message_list *m;
	TDB_DATA key;

	while (h->m != NULL) {
		m = h->m;
		DLIST_REMOVE(h->m, m);
		TALLOC_FREE(m);
	}

	key.dptr = (uint8_t *)&h->srvid;
	key.dsize = sizeof(uint64_t);

	message_list_db_delete(h->ctdb, key);
	DLIST_REMOVE(h->ctdb->message_list_header, h);

	return 0;
}

/*
  when a client goes away, we need to remove its srvid handler from the list
 */
static int message_handler_destructor(struct ctdb_message_list *m)
{
	struct ctdb_message_list_header *h = m->h;

	DLIST_REMOVE(h->m, m);
	if (h->m == NULL) {
		talloc_free(h);
	}
	return 0;
}

/*
  setup handler for receipt of ctdb messages from ctdb_send_message()
*/
int ctdb_register_message_handler(struct ctdb_context *ctdb, 
				  TALLOC_CTX *mem_ctx,
				  uint64_t srvid,
				  ctdb_msg_fn_t handler,
				  void *private_data)
{
	struct ctdb_message_list_header *h;
	struct ctdb_message_list *m;
	TDB_DATA key, data;
	int ret;

	m = talloc_zero(mem_ctx, struct ctdb_message_list);
	CTDB_NO_MEMORY(ctdb, m);

	m->message_handler = handler;
	m->message_private = private_data;

	key.dptr = (uint8_t *)&srvid;
	key.dsize = sizeof(uint64_t);

	ret = message_list_db_fetch(ctdb, key, &data);
	if (ret < 0) {
		/* srvid not registered yet */
		h = talloc_zero(ctdb, struct ctdb_message_list_header);
		CTDB_NO_MEMORY(ctdb, h);

		h->ctdb = ctdb;
		h->srvid = srvid;

		data.dptr = (uint8_t *)&h;
		data.dsize = sizeof(struct ctdb_message_list_header *);
		ret = message_list_db_add(ctdb, key, data);
		if (ret < 0) {
			talloc_free(m);
			talloc_free(h);
			return -1;
		}

		DLIST_ADD(ctdb->message_list_header, h);
		talloc_set_destructor(h, message_header_destructor);
	} else {
		h = *(struct ctdb_message_list_header **)data.dptr;
	}

	m->h = h;
	DLIST_ADD(h->m, m);
	talloc_set_destructor(m, message_handler_destructor);
	return 0;
}


/*
  setup handler for receipt of ctdb messages from ctdb_send_message()
*/
int ctdb_deregister_message_handler(struct ctdb_context *ctdb, uint64_t srvid, void *private_data)
{
	struct ctdb_message_list_header *h;
	struct ctdb_message_list *m;
	TDB_DATA key, data;
	int ret;

	key.dptr = (uint8_t *)&srvid;
	key.dsize = sizeof(uint64_t);

	ret = message_list_db_fetch(ctdb, key, &data);
	if (ret < 0) {
		return -1;
	}

	h = *(struct ctdb_message_list_header **)data.dptr;
	for (m=h->m; m; m=m->next) {
		if (m->message_private == private_data) {
			talloc_free(m);
			return 0;
		}
	}

	return -1;
}


/*
 * check if the given srvid exists
 */
bool ctdb_check_message_handler(struct ctdb_context *ctdb, uint64_t srvid)
{
	struct ctdb_message_list_header *h;
	TDB_DATA key, data;

	key.dptr = (uint8_t *)&srvid;
	key.dsize = sizeof(uint64_t);

	if (message_list_db_fetch(ctdb, key, &data) < 0) {
		return false;
	}

	h = *(struct ctdb_message_list_header **)data.dptr;
	if (h->m == NULL) {
		return false;
	}

	return true;
}
