/*
   core of libctdb

   Copyright (C) Rusty Russell 2010

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

#include <sys/socket.h>
#include "libctdb_private.h"
#include "messages.h"
#include "io_elem.h"
#include <ctdb.h>
#include <tdb.h>
#include <ctdb_protocol.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

/* Remove type-safety macros. */
#undef ctdb_set_message_handler_send
#undef ctdb_set_message_handler_recv
#undef ctdb_remove_message_handler_send

struct message_handler_info {
	struct message_handler_info *next, *prev;

	uint64_t srvid;
	ctdb_message_fn_t handler;
	void *handler_data;
};

void deliver_message(struct ctdb_connection *ctdb, struct ctdb_req_header *hdr)
{
	struct message_handler_info *i;
	struct ctdb_req_message *msg = (struct ctdb_req_message *)hdr;
	TDB_DATA data;
	bool found;

	data.dptr = msg->data;
	data.dsize = msg->datalen;

	/* Note: we want to call *every* handler: there may be more than one */
	for (i = ctdb->message_handlers; i; i = i->next) {
		if (i->srvid == msg->srvid) {
			i->handler(ctdb, msg->srvid, data, i->handler_data);
			found = true;
		}
	}
	if (!found) {
		DEBUG(ctdb, LOG_WARNING,
		      "ctdb_service: messsage for unregistered srvid %llu",
		      (unsigned long long)msg->srvid);
	}
}

void remove_message_handlers(struct ctdb_connection *ctdb)
{
	struct message_handler_info *i;

	/* ctdbd should unregister automatically when we close fd, so we don't
	   need to do that here. */
	while ((i = ctdb->message_handlers) != NULL) {
		DLIST_REMOVE(ctdb->message_handlers, i);
		free(i);
	}
}

static void free_info(struct ctdb_connection *ctdb, struct ctdb_request *req);

struct ctdb_request *
ctdb_set_message_handler_send(struct ctdb_connection *ctdb, uint64_t srvid,
			      ctdb_message_fn_t handler, void *handler_data,
			      ctdb_callback_t callback, void *private_data)
{
	struct message_handler_info *info;
	struct ctdb_request *req;

	info = malloc(sizeof(*info));
	if (!info) {
		DEBUG(ctdb, LOG_ERR,
		      "ctdb_set_message_handler_send: allocating info");
		return NULL;
	}

	req = new_ctdb_control_request(ctdb, CTDB_CONTROL_REGISTER_SRVID,
				       CTDB_CURRENT_NODE, NULL, 0,
				       callback, private_data);
	if (!req) {
		DEBUG(ctdb, LOG_ERR,
		      "ctdb_set_message_handler_send: allocating request");
		free(info);
		return NULL;
	}
	req->extra = info;
	req->extra_destructor = free_info;
	req->hdr.control->srvid = srvid;

	info->srvid = srvid;
	info->handler = handler;
	info->handler_data = handler_data;

	DEBUG(ctdb, LOG_DEBUG,
	      "ctdb_set_message_handler_send: sending request %u for id %llx",
	      req->hdr.hdr->reqid, (unsigned long long)srvid);
	return req;
}

static void free_info(struct ctdb_connection *ctdb, struct ctdb_request *req)
{
	free(req->extra);
}

bool ctdb_set_message_handler_recv(struct ctdb_connection *ctdb,
				   struct ctdb_request *req)
{
	struct message_handler_info *info = req->extra;
	struct ctdb_reply_control *reply;

	reply = unpack_reply_control(req, CTDB_CONTROL_REGISTER_SRVID);
	if (!reply) {
		return false;
	}
	if (reply->status != 0) {
		DEBUG(ctdb, LOG_ERR,
		      "ctdb_set_message_handler_recv: status %i",
		      reply->status);
		return false;
	}

	/* Put ourselves in list of handlers. */
	DLIST_ADD(ctdb->message_handlers, info);
	/* Keep safe from destructor */
	req->extra = NULL;
	return true;
}

struct ctdb_request *
ctdb_remove_message_handler_send(struct ctdb_connection *ctdb, uint64_t srvid,
				 ctdb_message_fn_t handler, void *hdata,
				 ctdb_callback_t callback, void *cbdata)
{
	struct message_handler_info *i;
	struct ctdb_request *req;

	for (i = ctdb->message_handlers; i; i = i->next) {
		if (i->srvid == srvid
		    && i->handler == handler && i->handler_data == hdata) {
			break;
		}
	}
	if (!i) {
		DEBUG(ctdb, LOG_ALERT,
		      "ctdb_remove_message_handler_send: no such handler");
		errno = ENOENT;
		return NULL;
	}

	req = new_ctdb_control_request(ctdb, CTDB_CONTROL_DEREGISTER_SRVID,
				       CTDB_CURRENT_NODE, NULL, 0,
				       callback, cbdata);
	if (!req) {
		DEBUG(ctdb, LOG_ERR,
		      "ctdb_remove_message_handler_send: allocating request");
		return NULL;
	}
	req->hdr.control->srvid = srvid;
	req->extra = i;

	DEBUG(ctdb, LOG_DEBUG,
	      "ctdb_set_remove_handler_send: sending request %u for id %llu",
	      req->hdr.hdr->reqid, (unsigned long long)srvid);
	return req;
}

bool ctdb_remove_message_handler_recv(struct ctdb_connection *ctdb,
				      struct ctdb_request *req)
{
	struct message_handler_info *handler = req->extra;
	struct ctdb_reply_control *reply;

	reply = unpack_reply_control(req, CTDB_CONTROL_DEREGISTER_SRVID);
	if (!reply) {
		return false;
	}
	if (reply->status != 0) {
		DEBUG(ctdb, LOG_ERR,
		      "ctdb_remove_message_handler_recv: status %i",
		      reply->status);
		return false;
	}

	/* Remove ourselves from list of handlers. */
	DLIST_REMOVE(ctdb->message_handlers, handler);
	free(handler);
	/* Crash if they call this again! */
	req->extra = NULL;
	return true;
}

bool ctdb_send_message(struct ctdb_connection *ctdb,
		      uint32_t pnn, uint64_t srvid,
		      TDB_DATA data)
{
	struct ctdb_request *req;
	struct ctdb_req_message *pkt;

	/* We just discard it once it's finished: no reply. */
	req = new_ctdb_request(
		ctdb, offsetof(struct ctdb_req_message, data) + data.dsize,
		ctdb_cancel_callback, NULL);
	if (!req) {
		DEBUG(ctdb, LOG_ERR, "ctdb_set_message: allocating message");
		return false;
	}

	io_elem_init_req_header(req->io,
				CTDB_REQ_MESSAGE, pnn, new_reqid(ctdb));

	pkt = req->hdr.message;
	pkt->srvid = srvid;
	pkt->datalen = data.dsize;
	memcpy(pkt->data, data.dptr, data.dsize);
	DLIST_ADD_END(ctdb->outq, req, struct ctdb_request);
	return true;
}
