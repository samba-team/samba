/* 
   Unix SMB/CIFS implementation.

   Samba internal messaging functions

   Copyright (C) Andrew Tridgell 2004
   
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

#include "includes.h"
#include "lib/events/events.h"
#include "system/filesys.h"
#include "messaging/messaging.h"
#include "lib/util/dlinklist.h"
#include "lib/socket/socket.h"
#include "librpc/gen_ndr/ndr_irpc.h"
#include "lib/messaging/irpc.h"
#include "db_wrap.h"
#include "lib/util/unix_privs.h"
#include "librpc/rpc/dcerpc.h"
#include "lib/tdb/include/tdb.h"
#include "lib/util/util_tdb.h"

/* change the message version with any incompatible changes in the protocol */
#define MESSAGING_VERSION 1

struct messaging_context {
	uint32_t server_id;
	struct socket_context *sock;
	const char *base_path;
	const char *path;
	struct dispatch_fn **dispatch;
	uint32_t num_types;
	struct idr_context *dispatch_tree;
	struct messaging_rec *pending;
	struct irpc_list *irpc;
	struct idr_context *idr;
	const char **names;
	struct timeval start_time;

	struct {
		struct event_context *ev;
		struct fd_event *fde;
	} event;
};

/* we have a linked list of dispatch handlers for each msg_type that
   this messaging server can deal with */
struct dispatch_fn {
	struct dispatch_fn *next, *prev;
	uint32_t msg_type;
	void *private;
	msg_callback_t fn;
};

/* an individual message */
struct messaging_rec {
	struct messaging_rec *next, *prev;
	struct messaging_context *msg;
	const char *path;

	struct messaging_header {
		uint32_t version;
		uint32_t msg_type;
		uint32_t from;
		uint32_t to;
		uint32_t length;
	} *header;

	DATA_BLOB packet;
};


static void irpc_handler(struct messaging_context *, void *, 
			 uint32_t, uint32_t, DATA_BLOB *);


/*
 A useful function for testing the message system.
*/
static void ping_message(struct messaging_context *msg, void *private, 
			 uint32_t msg_type, uint32_t src, DATA_BLOB *data)
{
	DEBUG(1,("INFO: Received PING message from server %u [%.*s]\n",
		 (uint_t)src, (int)data->length, 
		 data->data?(const char *)data->data:""));
	messaging_send(msg, src, MSG_PONG, data);
}

/*
  return uptime of messaging server via irpc
*/
static NTSTATUS irpc_uptime(struct irpc_message *msg, 
			    struct irpc_uptime *r)
{
	struct messaging_context *ctx = talloc_get_type(msg->private, struct messaging_context);
	*r->out.start_time = timeval_to_nttime(&ctx->start_time);
	return NT_STATUS_OK;
}

/* 
   return the path to a messaging socket
*/
static char *messaging_path(struct messaging_context *msg, uint32_t server_id)
{
	return talloc_asprintf(msg, "%s/msg.%u", msg->base_path, (unsigned)server_id);
}

/*
  dispatch a fully received message

  note that this deliberately can match more than one message handler
  per message. That allows a single messasging context to register
  (for example) a debug handler for more than one piece of code
*/
static void messaging_dispatch(struct messaging_context *msg, struct messaging_rec *rec)
{
	struct dispatch_fn *d, *next;

	/* temporary IDs use an idtree, the rest use a array of pointers */
	if (rec->header->msg_type >= MSG_TMP_BASE) {
		d = idr_find(msg->dispatch_tree, rec->header->msg_type);
	} else if (rec->header->msg_type < msg->num_types) {
		d = msg->dispatch[rec->header->msg_type];
	} else {
		d = NULL;
	}

	for (; d; d = next) {
		DATA_BLOB data;
		next = d->next;
		data.data = rec->packet.data + sizeof(*rec->header);
		data.length = rec->header->length;
		d->fn(msg, d->private, d->msg_type, rec->header->from, &data);
	}
	rec->header->length = 0;
}


/*
  try to send the message
*/
static NTSTATUS try_send(struct messaging_rec *rec)
{
	struct messaging_context *msg = rec->msg;
	size_t nsent;
	void *priv;
	NTSTATUS status;
	struct socket_address *path;

	/* rec->path is the path of the *other* socket, where we want
	 * this to end up */
	path = socket_address_from_strings(msg, msg->sock->backend_name, 
					   rec->path, 0);
	if (!path) {
		return NT_STATUS_NO_MEMORY;
	}

	/* we send with privileges so messages work from any context */
	priv = root_privileges();
	status = socket_sendto(msg->sock, &rec->packet, &nsent, path);
	talloc_free(path);
	talloc_free(priv);

	return status;
}

/*
  handle a socket write event
*/
static void messaging_send_handler(struct messaging_context *msg)
{
	while (msg->pending) {
		struct messaging_rec *rec = msg->pending;
		NTSTATUS status;
		status = try_send(rec);
		if (NT_STATUS_EQUAL(status, STATUS_MORE_ENTRIES)) {
			break;
		}
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(1,("messaging: Lost message from %u to %u of type %u - %s\n", 
				 rec->header->from, rec->header->to, rec->header->msg_type, 
				 nt_errstr(status)));
		}
		DLIST_REMOVE(msg->pending, rec);
		talloc_free(rec);
	}
	if (msg->pending == NULL) {
		EVENT_FD_NOT_WRITEABLE(msg->event.fde);
	}
}

/*
  handle a new incoming packet
*/
static void messaging_recv_handler(struct messaging_context *msg)
{
	struct messaging_rec *rec;
	NTSTATUS status;
	DATA_BLOB packet;
	size_t msize;

	/* see how many bytes are in the next packet */
	status = socket_pending(msg->sock, &msize);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0,("socket_pending failed in messaging - %s\n", 
			 nt_errstr(status)));
		return;
	}
	
	packet = data_blob_talloc(msg, NULL, msize);
	if (packet.data == NULL) {
		/* assume this is temporary and retry */
		return;
	}
	    
	status = socket_recv(msg->sock, packet.data, msize, &msize);
	if (!NT_STATUS_IS_OK(status)) {
		data_blob_free(&packet);
		return;
	}

	if (msize < sizeof(*rec->header)) {
		DEBUG(0,("messaging: bad message of size %d\n", (int)msize));
		data_blob_free(&packet);
		return;
	}

	rec = talloc(msg, struct messaging_rec);
	if (rec == NULL) {
		smb_panic("Unable to allocate messaging_rec");
	}

	talloc_steal(rec, packet.data);
	rec->msg           = msg;
	rec->path          = msg->path;
	rec->header        = (struct messaging_header *)packet.data;
	rec->packet        = packet;

	if (msize != sizeof(*rec->header) + rec->header->length) {
		DEBUG(0,("messaging: bad message header size %d should be %d\n", 
			 rec->header->length, (int)(msize - sizeof(*rec->header))));
		talloc_free(rec);
		return;
	}

	messaging_dispatch(msg, rec);
	talloc_free(rec);
}


/*
  handle a socket event
*/
static void messaging_handler(struct event_context *ev, struct fd_event *fde, 
			      uint16_t flags, void *private)
{
	struct messaging_context *msg = talloc_get_type(private, 
							struct messaging_context);
	if (flags & EVENT_FD_WRITE) {
		messaging_send_handler(msg);
	}
	if (flags & EVENT_FD_READ) {
		messaging_recv_handler(msg);
	}
}


/*
  Register a dispatch function for a particular message type.
*/
NTSTATUS messaging_register(struct messaging_context *msg, void *private,
			    uint32_t msg_type, msg_callback_t fn)
{
	struct dispatch_fn *d;

	/* possibly expand dispatch array */
	if (msg_type >= msg->num_types) {
		struct dispatch_fn **dp;
		int i;
		dp = talloc_realloc(msg, msg->dispatch, struct dispatch_fn *, msg_type+1);
		NT_STATUS_HAVE_NO_MEMORY(dp);
		msg->dispatch = dp;
		for (i=msg->num_types;i<=msg_type;i++) {
			msg->dispatch[i] = NULL;
		}
		msg->num_types = msg_type+1;
	}

	d = talloc_zero(msg->dispatch, struct dispatch_fn);
	NT_STATUS_HAVE_NO_MEMORY(d);
	d->msg_type = msg_type;
	d->private = private;
	d->fn = fn;

	DLIST_ADD(msg->dispatch[msg_type], d);

	return NT_STATUS_OK;
}

/*
  register a temporary message handler. The msg_type is allocated
  above MSG_TMP_BASE
*/
NTSTATUS messaging_register_tmp(struct messaging_context *msg, void *private,
				msg_callback_t fn, uint32_t *msg_type)
{
	struct dispatch_fn *d;
	int id;

	d = talloc_zero(msg->dispatch, struct dispatch_fn);
	NT_STATUS_HAVE_NO_MEMORY(d);
	d->private = private;
	d->fn = fn;

	id = idr_get_new_above(msg->dispatch_tree, d, MSG_TMP_BASE, UINT16_MAX);
	if (id == -1) {
		talloc_free(d);
		return NT_STATUS_TOO_MANY_CONTEXT_IDS;
	}

	d->msg_type = (uint32_t)id;
	(*msg_type) = d->msg_type;

	return NT_STATUS_OK;
}

/*
  De-register the function for a particular message type.
*/
void messaging_deregister(struct messaging_context *msg, uint32_t msg_type, void *private)
{
	struct dispatch_fn *d, *next;

	if (msg_type >= msg->num_types) {
		d = idr_find(msg->dispatch_tree, msg_type);
		if (!d) return;
		idr_remove(msg->dispatch_tree, msg_type);
		talloc_free(d);
		return;
	}

	for (d = msg->dispatch[msg_type]; d; d = next) {
		next = d->next;
		if (d->private == private) {
			DLIST_REMOVE(msg->dispatch[msg_type], d);
			talloc_free(d);
		}
	}
}

/*
  Send a message to a particular server
*/
NTSTATUS messaging_send(struct messaging_context *msg, uint32_t server, 
			uint32_t msg_type, DATA_BLOB *data)
{
	struct messaging_rec *rec;
	NTSTATUS status;
	size_t dlength = data?data->length:0;

	rec = talloc(msg, struct messaging_rec);
	if (rec == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	rec->packet = data_blob_talloc(rec, NULL, sizeof(*rec->header) + dlength);
	if (rec->packet.data == NULL) {
		talloc_free(rec);
		return NT_STATUS_NO_MEMORY;
	}

	rec->msg              = msg;
	rec->header           = (struct messaging_header *)rec->packet.data;
	rec->header->version  = MESSAGING_VERSION;
	rec->header->msg_type = msg_type;
	rec->header->from     = msg->server_id;
	rec->header->to       = server;
	rec->header->length   = dlength;
	if (dlength != 0) {
		memcpy(rec->packet.data + sizeof(*rec->header), 
		       data->data, dlength);
	}

	rec->path = messaging_path(msg, server);
	talloc_steal(rec, rec->path);

	if (msg->pending != NULL) {
		status = STATUS_MORE_ENTRIES;
	} else {
		status = try_send(rec);
	}

	if (NT_STATUS_EQUAL(status, STATUS_MORE_ENTRIES)) {
		if (msg->pending == NULL) {
			EVENT_FD_WRITEABLE(msg->event.fde);
		}
		DLIST_ADD_END(msg->pending, rec, struct messaging_rec *);
		return NT_STATUS_OK;
	}

	talloc_free(rec);

	return status;
}

/*
  Send a message to a particular server, with the message containing a single pointer
*/
NTSTATUS messaging_send_ptr(struct messaging_context *msg, uint32_t server, 
			    uint32_t msg_type, void *ptr)
{
	DATA_BLOB blob;

	blob.data = (void *)&ptr;
	blob.length = sizeof(void *);

	return messaging_send(msg, server, msg_type, &blob);
}


/*
  destroy the messaging context
*/
static int messaging_destructor(struct messaging_context *msg)
{
	unlink(msg->path);
	while (msg->names && msg->names[0]) {
		irpc_remove_name(msg, msg->names[0]);
	}
	return 0;
}

/*
  create the listening socket and setup the dispatcher
*/
struct messaging_context *messaging_init(TALLOC_CTX *mem_ctx, uint32_t server_id, 
					 struct event_context *ev)
{
	struct messaging_context *msg;
	NTSTATUS status;
	struct socket_address *path;
	char *dir;

	msg = talloc_zero(mem_ctx, struct messaging_context);
	if (msg == NULL) {
		return NULL;
	}

	if (ev == NULL) {
		ev = event_context_init(msg);
	}

	/* create the messaging directory if needed */
	dir = smbd_tmp_path(msg, "messaging");
	mkdir(dir, 0700);
	talloc_free(dir);

	msg->base_path     = smbd_tmp_path(msg, "messaging");
	msg->path          = messaging_path(msg, server_id);
	msg->server_id     = server_id;
	msg->idr           = idr_init(msg);
	msg->dispatch_tree = idr_init(msg);
	msg->start_time    = timeval_current();

	status = socket_create("unix", SOCKET_TYPE_DGRAM, &msg->sock, 0);
	if (!NT_STATUS_IS_OK(status)) {
		talloc_free(msg);
		return NULL;
	}

	/* by stealing here we ensure that the socket is cleaned up (and even 
	   deleted) on exit */
	talloc_steal(msg, msg->sock);

	path = socket_address_from_strings(msg, msg->sock->backend_name, 
					   msg->path, 0);
	if (!path) {
		talloc_free(msg);
		return NULL;
	}

	status = socket_listen(msg->sock, path, 50, 0);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0,("Unable to setup messaging listener for '%s':%s\n", msg->path, nt_errstr(status)));
		talloc_free(msg);
		return NULL;
	}

	/* it needs to be non blocking for sends */
	set_blocking(socket_get_fd(msg->sock), False);

	msg->event.ev   = talloc_reference(msg, ev);
	msg->event.fde	= event_add_fd(ev, msg, socket_get_fd(msg->sock), 
				       EVENT_FD_READ, messaging_handler, msg);

	talloc_set_destructor(msg, messaging_destructor);
	
	messaging_register(msg, NULL, MSG_PING, ping_message);
	messaging_register(msg, NULL, MSG_IRPC, irpc_handler);
	IRPC_REGISTER(msg, irpc, IRPC_UPTIME, irpc_uptime, msg);

	return msg;
}

/* 
   A hack, for the short term until we get 'client only' messaging in place 
*/
struct messaging_context *messaging_client_init(TALLOC_CTX *mem_ctx, 
						struct event_context *ev)
{
	return messaging_init(mem_ctx, random() % 0x10000000, ev);
}
/*
  a list of registered irpc server functions
*/
struct irpc_list {
	struct irpc_list *next, *prev;
	struct GUID uuid;
	const struct dcerpc_interface_table *table;
	int callnum;
	irpc_function_t fn;
	void *private;
};


/*
  register a irpc server function
*/
NTSTATUS irpc_register(struct messaging_context *msg_ctx, 
		       const struct dcerpc_interface_table *table, 
		       int callnum, irpc_function_t fn, void *private)
{
	struct irpc_list *irpc;

	/* override an existing handler, if any */
	for (irpc=msg_ctx->irpc; irpc; irpc=irpc->next) {
		if (irpc->table == table && irpc->callnum == callnum) {
			break;
		}
	}
	if (irpc == NULL) {
		irpc = talloc(msg_ctx, struct irpc_list);
		NT_STATUS_HAVE_NO_MEMORY(irpc);
		DLIST_ADD(msg_ctx->irpc, irpc);
	}

	irpc->table   = table;
	irpc->callnum = callnum;
	irpc->fn      = fn;
	irpc->private = private;
	irpc->uuid = irpc->table->syntax_id.uuid;

	return NT_STATUS_OK;
}


/*
  handle an incoming irpc reply message
*/
static void irpc_handler_reply(struct messaging_context *msg_ctx, struct irpc_message *m)
{
	struct irpc_request *irpc;

	irpc = idr_find(msg_ctx->idr, m->header.callid);
	if (irpc == NULL) return;

	/* parse the reply data */
	irpc->status = irpc->table->calls[irpc->callnum].ndr_pull(m->ndr, NDR_OUT, irpc->r);
	if (NT_STATUS_IS_OK(irpc->status)) {
		irpc->status = m->header.status;
		talloc_steal(irpc->mem_ctx, m);
	} else {
		talloc_steal(irpc, m);
	}
	irpc->done = True;
	if (irpc->async.fn) {
		irpc->async.fn(irpc);
	}
}

/*
  send a irpc reply
*/
NTSTATUS irpc_send_reply(struct irpc_message *m, NTSTATUS status)
{
	struct ndr_push *push;
	DATA_BLOB packet;

	m->header.status = status;

	/* setup the reply */
	push = ndr_push_init_ctx(m->ndr);
	if (push == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto failed;
	}

	m->header.flags |= IRPC_FLAG_REPLY;

	/* construct the packet */
	status = ndr_push_irpc_header(push, NDR_SCALARS|NDR_BUFFERS, &m->header);
	if (!NT_STATUS_IS_OK(status)) goto failed;

	status = m->irpc->table->calls[m->irpc->callnum].ndr_push(push, NDR_OUT, m->data);
	if (!NT_STATUS_IS_OK(status)) goto failed;

	/* send the reply message */
	packet = ndr_push_blob(push);
	status = messaging_send(m->msg_ctx, m->from, MSG_IRPC, &packet);
	if (!NT_STATUS_IS_OK(status)) goto failed;

failed:
	talloc_free(m);
	return status;
}

/*
  handle an incoming irpc request message
*/
static void irpc_handler_request(struct messaging_context *msg_ctx, 
				 struct irpc_message *m)
{
	struct irpc_list *i;
	void *r;
	NTSTATUS status;

	for (i=msg_ctx->irpc; i; i=i->next) {
		if (GUID_equal(&i->uuid, &m->header.uuid) &&
		    i->table->syntax_id.if_version == m->header.if_version &&
		    i->callnum == m->header.callnum) {
			break;
		}
	}

	if (i == NULL) {
		/* no registered handler for this message */
		talloc_free(m);
		return;
	}

	/* allocate space for the structure */
	r = talloc_zero_size(m->ndr, i->table->calls[m->header.callnum].struct_size);
	if (r == NULL) goto failed;

	/* parse the request data */
	status = i->table->calls[i->callnum].ndr_pull(m->ndr, NDR_IN, r);
	if (!NT_STATUS_IS_OK(status)) goto failed;

	/* make the call */
	m->private     = i->private;
	m->defer_reply = False;
	m->msg_ctx     = msg_ctx;
	m->irpc        = i;
	m->data        = r;
	m->ev          = msg_ctx->event.ev;

	m->header.status = i->fn(m, r);

	if (m->defer_reply) {
		/* the server function has asked to defer the reply to later */
		talloc_steal(msg_ctx, m);
		return;
	}

	irpc_send_reply(m, m->header.status);
	return;

failed:
	talloc_free(m);
}

/*
  handle an incoming irpc message
*/
static void irpc_handler(struct messaging_context *msg_ctx, void *private, 
			 uint32_t msg_type, uint32_t src, DATA_BLOB *packet)
{
	struct irpc_message *m;
	NTSTATUS status;

	m = talloc(msg_ctx, struct irpc_message);
	if (m == NULL) goto failed;

	m->from = src;

	m->ndr = ndr_pull_init_blob(packet, m);
	if (m->ndr == NULL) goto failed;

	m->ndr->flags |= LIBNDR_FLAG_REF_ALLOC;

	status = ndr_pull_irpc_header(m->ndr, NDR_BUFFERS|NDR_SCALARS, &m->header);
	if (!NT_STATUS_IS_OK(status)) goto failed;

	if (m->header.flags & IRPC_FLAG_REPLY) {
		irpc_handler_reply(msg_ctx, m);
	} else {
		irpc_handler_request(msg_ctx, m);
	}
	return;

failed:
	talloc_free(m);
}


/*
  destroy a irpc request
*/
static int irpc_destructor(struct irpc_request *irpc)
{
	idr_remove(irpc->msg_ctx->idr, irpc->callid);
	return 0;
}

/*
  timeout a irpc request
*/
static void irpc_timeout(struct event_context *ev, struct timed_event *te, 
			 struct timeval t, void *private)
{
	struct irpc_request *irpc = talloc_get_type(private, struct irpc_request);
	irpc->status = NT_STATUS_IO_TIMEOUT;
	irpc->done = True;
	if (irpc->async.fn) {
		irpc->async.fn(irpc);
	}
}


/*
  make a irpc call - async send
*/
struct irpc_request *irpc_call_send(struct messaging_context *msg_ctx, 
				    uint32_t server_id, 
				    const struct dcerpc_interface_table *table, 
				    int callnum, void *r, TALLOC_CTX *ctx)
{
	struct irpc_header header;
	struct ndr_push *ndr;
	NTSTATUS status;
	DATA_BLOB packet;
	struct irpc_request *irpc;

	irpc = talloc(msg_ctx, struct irpc_request);
	if (irpc == NULL) goto failed;

	irpc->msg_ctx  = msg_ctx;
	irpc->table    = table;
	irpc->callnum  = callnum;
	irpc->callid   = idr_get_new(msg_ctx->idr, irpc, UINT16_MAX);
	if (irpc->callid == -1) goto failed;
	irpc->r        = r;
	irpc->done     = False;
	irpc->async.fn = NULL;
	irpc->mem_ctx  = ctx;

	talloc_set_destructor(irpc, irpc_destructor);

	/* setup the header */
	header.uuid = table->syntax_id.uuid;

	header.if_version = table->syntax_id.if_version;
	header.callid     = irpc->callid;
	header.callnum    = callnum;
	header.flags      = 0;
	header.status     = NT_STATUS_OK;

	/* construct the irpc packet */
	ndr = ndr_push_init_ctx(irpc);
	if (ndr == NULL) goto failed;

	status = ndr_push_irpc_header(ndr, NDR_SCALARS|NDR_BUFFERS, &header);
	if (!NT_STATUS_IS_OK(status)) goto failed;

	status = table->calls[callnum].ndr_push(ndr, NDR_IN, r);
	if (!NT_STATUS_IS_OK(status)) goto failed;

	/* and send it */
	packet = ndr_push_blob(ndr);
	status = messaging_send(msg_ctx, server_id, MSG_IRPC, &packet);
	if (!NT_STATUS_IS_OK(status)) goto failed;

	event_add_timed(msg_ctx->event.ev, irpc, 
			timeval_current_ofs(IRPC_CALL_TIMEOUT, 0), 
			irpc_timeout, irpc);

	talloc_free(ndr);
	return irpc;

failed:
	talloc_free(irpc);
	return NULL;
}

/*
  wait for a irpc reply
*/
NTSTATUS irpc_call_recv(struct irpc_request *irpc)
{
	NTSTATUS status;

	NT_STATUS_HAVE_NO_MEMORY(irpc);

	while (!irpc->done) {
		if (event_loop_once(irpc->msg_ctx->event.ev) != 0) {
			return NT_STATUS_CONNECTION_DISCONNECTED;
		}
	}
	status = irpc->status;
	talloc_free(irpc);
	return status;
}

/*
  perform a synchronous irpc request
*/
NTSTATUS irpc_call(struct messaging_context *msg_ctx, 
		   uint32_t server_id, 
		   const struct dcerpc_interface_table *table, 
		   int callnum, void *r,
		   TALLOC_CTX *mem_ctx)
{
	struct irpc_request *irpc = irpc_call_send(msg_ctx, server_id, 
						   table, callnum, r, mem_ctx);
	return irpc_call_recv(irpc);
}

/*
  open the naming database
*/
static struct tdb_wrap *irpc_namedb_open(struct messaging_context *msg_ctx)
{
	struct tdb_wrap *t;
	char *path = talloc_asprintf(msg_ctx, "%s/names.tdb", msg_ctx->base_path);
	if (path == NULL) {
		return NULL;
	}
	t = tdb_wrap_open(msg_ctx, path, 0, 0, O_RDWR|O_CREAT, 0660);
	talloc_free(path);
	return t;
}
	

/*
  add a string name that this irpc server can be called on
*/
NTSTATUS irpc_add_name(struct messaging_context *msg_ctx, const char *name)
{
	struct tdb_wrap *t;
	TDB_DATA rec;
	int count;
	NTSTATUS status = NT_STATUS_OK;

	t = irpc_namedb_open(msg_ctx);
	NT_STATUS_HAVE_NO_MEMORY(t);

	if (tdb_lock_bystring(t->tdb, name) != 0) {
		talloc_free(t);
		return NT_STATUS_LOCK_NOT_GRANTED;
	}
	rec = tdb_fetch_bystring(t->tdb, name);
	count = rec.dsize / sizeof(uint32_t);
	rec.dptr = (unsigned char *)realloc_p(rec.dptr, uint32_t, count+1);
	rec.dsize += sizeof(uint32_t);
	if (rec.dptr == NULL) {
		tdb_unlock_bystring(t->tdb, name);
		talloc_free(t);
		return NT_STATUS_NO_MEMORY;
	}
	((uint32_t *)rec.dptr)[count] = msg_ctx->server_id;
	if (tdb_store_bystring(t->tdb, name, rec, 0) != 0) {
		status = NT_STATUS_INTERNAL_ERROR;
	}
	free(rec.dptr);
	tdb_unlock_bystring(t->tdb, name);
	talloc_free(t);

	msg_ctx->names = str_list_add(msg_ctx->names, name);
	talloc_steal(msg_ctx, msg_ctx->names);

	return status;
}

/*
  return a list of server ids for a server name
*/
uint32_t *irpc_servers_byname(struct messaging_context *msg_ctx, const char *name)
{
	struct tdb_wrap *t;
	TDB_DATA rec;
	int count, i;
	uint32_t *ret;

	t = irpc_namedb_open(msg_ctx);
	if (t == NULL) {
		return NULL;
	}

	if (tdb_lock_bystring(t->tdb, name) != 0) {
		talloc_free(t);
		return NULL;
	}
	rec = tdb_fetch_bystring(t->tdb, name);
	if (rec.dptr == NULL) {
		tdb_unlock_bystring(t->tdb, name);
		talloc_free(t);
		return NULL;
	}
	count = rec.dsize / sizeof(uint32_t);
	ret = talloc_array(msg_ctx, uint32_t, count+1);
	if (ret == NULL) {
		tdb_unlock_bystring(t->tdb, name);
		talloc_free(t);
		return NULL;
	}
	for (i=0;i<count;i++) {
		ret[i] = ((uint32_t *)rec.dptr)[i];
	}
	ret[i] = 0;
	free(rec.dptr);
	tdb_unlock_bystring(t->tdb, name);
	talloc_free(t);

	return ret;
}

/*
  remove a name from a messaging context
*/
void irpc_remove_name(struct messaging_context *msg_ctx, const char *name)
{
	struct tdb_wrap *t;
	TDB_DATA rec;
	int count, i;
	uint32_t *ids;

	str_list_remove(msg_ctx->names, name);

	t = irpc_namedb_open(msg_ctx);
	if (t == NULL) {
		return;
	}

	if (tdb_lock_bystring(t->tdb, name) != 0) {
		talloc_free(t);
		return;
	}
	rec = tdb_fetch_bystring(t->tdb, name);
	count = rec.dsize / sizeof(uint32_t);
	if (count == 0) {
		tdb_unlock_bystring(t->tdb, name);
		talloc_free(t);
		return;
	}
	ids = (uint32_t *)rec.dptr;
	for (i=0;i<count;i++) {
		if (ids[i] == msg_ctx->server_id) {
			if (i < count-1) {
				memmove(ids+i, ids+i+1, count-(i+1));
			}
			rec.dsize -= sizeof(uint32_t);
			break;
		}
	}
	tdb_store_bystring(t->tdb, name, rec, 0);
	free(rec.dptr);
	tdb_unlock_bystring(t->tdb, name);
	talloc_free(t);
}
