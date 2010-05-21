#include "libctdb_private.h"
#include "messages.h"
#include "io_elem.h"
#include <ctdb.h>
#include <tdb.h>
#include <ctdb_protocol.h>
#include <stdlib.h>
#include <string.h>

struct message_handler_info {
	struct message_handler_info *next, *prev;
	/* Callback when we're first registered. */
	ctdb_set_message_handler_cb callback;

	uint64_t srvid;
	ctdb_message_fn_t handler;
	void *private_data;
	struct ctdb_connection *ctdb;
};

void deliver_message(struct ctdb_connection *ctdb, struct ctdb_req_header *hdr)
{
	struct message_handler_info *i;
	struct ctdb_req_message *msg = (struct ctdb_req_message *)hdr;
	TDB_DATA data;

	data.dptr = msg->data;
	data.dsize = msg->datalen;

	for (i = ctdb->message_handlers; i; i = i->next) {
		if (i->srvid == msg->srvid) {
			i->handler(ctdb, msg->srvid, data, i->private_data);
		}
	}
	/* FIXME: Report unknown messages */
}

static void set_message_handler(int status, struct message_handler_info *info)
{
	/* If registration failed, tell callback and clean up */
	if (status < 0) {
		info->callback(status, info->private_data);
		free(info);
		return;
	} else {
		/* Put ourselves in list of handlers. */
		DLIST_ADD_END(info->ctdb->message_handlers, info,
			      struct message_handler_info);
		/* Now call callback: it could remove us in theory. */
		info->callback(status, info->private_data);
	}
}

struct ctdb_request *
ctdb_set_message_handler_send(struct ctdb_connection *ctdb, uint64_t srvid,
			      ctdb_set_message_handler_cb callback,
			      ctdb_message_fn_t handler, void *private_data)
{
	struct ctdb_request *req;
	struct message_handler_info *info;

	info = malloc(sizeof(*info));
	if (!info) {
		return NULL;
	}
	req = new_ctdb_control_request(ctdb, CTDB_CONTROL_REGISTER_SRVID,
				       CTDB_CURRENT_NODE, NULL, 0);
	if (!req) {
		free(info);
		return NULL;
	}
	req->hdr.control->srvid = srvid;

	info->srvid = srvid;
	info->handler = handler;
	info->callback = callback;
	info->private_data = private_data;
	info->ctdb = ctdb;

	req->callback.register_srvid = set_message_handler;
	req->priv_data = info;

	return req;
}

int ctdb_send_message(struct ctdb_connection *ctdb,
		      uint32_t pnn, uint64_t srvid,
		      TDB_DATA data)
{
	struct ctdb_request *req;
	struct ctdb_req_message *pkt;

	req = new_ctdb_request(sizeof(*pkt) + data.dsize);
	if (!req) {
		return -1;
	}

	io_elem_init_req_header(req->io,
				CTDB_REQ_MESSAGE, pnn, new_reqid(ctdb));

	/* There's no reply to this, so we mark it cancelled immediately. */
	req->cancelled = true;

	pkt = req->hdr.message;
	pkt->srvid = srvid;
	pkt->datalen = data.dsize;
	memcpy(pkt->data, data.dptr, data.dsize);
	DLIST_ADD_END(ctdb->outq, req, struct ctdb_request);
	return 0;
}
