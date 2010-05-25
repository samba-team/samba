#include "libctdb_private.h"
#include "messages.h"
#include "io_elem.h"
#include <ctdb.h>
#include <tdb.h>
#include <ctdb_protocol.h>
#include <stdlib.h>
#include <string.h>

/* Remove type-safety macros. */
#undef ctdb_set_message_handler_send
#undef ctdb_set_message_handler_recv
#undef ctdb_remove_message_handler_send

struct message_handler_info {
	struct message_handler_info *next, *prev;

	uint64_t srvid;
	ctdb_message_fn_t handler;
	void *private_data;
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

int ctdb_set_message_handler_recv(struct ctdb_connection *ctdb,
				  struct ctdb_request *req)
{
	struct message_handler_info *info = req->extra;
	struct ctdb_reply_control *reply;

	reply = unpack_reply_control(req, CTDB_CONTROL_REGISTER_SRVID);
	if (!reply || reply->status != 0) {
		return -1;
	}

	/* Put ourselves in list of handlers. */
	DLIST_ADD(ctdb->message_handlers, info);
	/* Keep safe from destructor */
	req->extra = NULL;
	return 0;
}

static void free_info(struct ctdb_request *req)
{
	free(req->extra);
}

struct ctdb_request *
ctdb_set_message_handler_send(struct ctdb_connection *ctdb, uint64_t srvid,
			      ctdb_message_fn_t handler,
			      ctdb_callback_t callback, void *private_data)
{
	struct message_handler_info *info;
	struct ctdb_request *req;

	info = malloc(sizeof(*info));
	if (!info) {
		return NULL;
	}

	req = new_ctdb_control_request(ctdb, CTDB_CONTROL_REGISTER_SRVID,
				       CTDB_CURRENT_NODE, NULL, 0,
				       callback, private_data);
	if (!req) {
		free(info);
		return NULL;
	}
	req->extra = info;
	req->extra_destructor = free_info;
	req->hdr.control->srvid = srvid;

	info->srvid = srvid;
	info->handler = handler;
	info->private_data = private_data;

	return req;
}

int ctdb_send_message(struct ctdb_connection *ctdb,
		      uint32_t pnn, uint64_t srvid,
		      TDB_DATA data)
{
	struct ctdb_request *req;
	struct ctdb_req_message *pkt;

	/* We just discard it once it's finished: no reply. */
	req = new_ctdb_request(sizeof(*pkt) + data.dsize,
			       ctdb_cancel_callback, NULL);
	if (!req) {
		return -1;
	}

	io_elem_init_req_header(req->io,
				CTDB_REQ_MESSAGE, pnn, new_reqid(ctdb));

	pkt = req->hdr.message;
	pkt->srvid = srvid;
	pkt->datalen = data.dsize;
	memcpy(pkt->data, data.dptr, data.dsize);
	DLIST_ADD_END(ctdb->outq, req, struct ctdb_request);
	return 0;
}
