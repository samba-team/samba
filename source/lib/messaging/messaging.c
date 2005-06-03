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
#include "system/time.h"
#include "messages.h"
#include "dlinklist.h"
#include "lib/socket/socket.h"

/* change the message version with any incompatible changes in the protocol */
#define MESSAGING_VERSION 1

/* maximum message size */
#define MESSAGING_MAX_SIZE 512

struct messaging_context {
	uint32_t server_id;
	struct socket_context *sock;
	const char *path;
	struct dispatch_fn *dispatch;
	struct messaging_rec *pending;

	struct {
		struct event_context *ev;
		struct fd_event *fde;
	} event;
};

/* we have a linked list of dispatch handlers that this messaging
   server can deal with */
struct dispatch_fn {
	struct dispatch_fn *next, *prev;
	uint32_t msg_type;
	void *private;
	void (*fn)(struct messaging_context *msg, void *private, 
		   uint32_t msg_type, uint32_t server_id, DATA_BLOB *data);
};

/* an individual message */
struct messaging_rec {
	struct messaging_rec *next, *prev;
	struct messaging_context *msg;
	const char *path;

	struct {
		uint32_t version;
		uint32_t msg_type;
		uint32_t from;
		uint32_t to;
		uint32_t length;
	} header;

	DATA_BLOB data;
};


/*
 A useful function for testing the message system.
*/
static void ping_message(struct messaging_context *msg, void *private, 
			 uint32_t msg_type, uint32_t src, DATA_BLOB *data)
{
	DEBUG(1,("INFO: Received PING message from server %u [%.*s]\n",
		 (uint_t)src, data->length, data->data?(const char *)data->data:""));
	messaging_send(msg, src, MSG_PONG, data);
}

/* 
   return the path to a messaging socket
*/
static char *messaging_path(TALLOC_CTX *mem_ctx, uint32_t server_id)
{
	char *name = talloc_asprintf(mem_ctx, "messaging/msg.%u", (unsigned)server_id);
	char *ret;
	ret = smbd_tmp_path(mem_ctx, name);
	talloc_free(name);
	return ret;
}

/*
  dispatch a fully received message
*/
static void messaging_dispatch(struct messaging_context *msg, struct messaging_rec *rec)
{
	struct dispatch_fn *d, *next;
	for (d=msg->dispatch;d;d=next) {
		next = d->next;
		if (d->msg_type == rec->header.msg_type) {
			d->fn(msg, d->private, d->msg_type, rec->header.from, &rec->data);
		}
	}
	rec->header.length = 0;
}


/*
  try to send the message
*/
static NTSTATUS try_send(struct messaging_rec *rec)
{
	struct messaging_context *msg = rec->msg;
	DATA_BLOB blob;
	size_t nsent;
	void *priv;
	NTSTATUS status;

	blob = data_blob_talloc(rec, NULL, sizeof(rec->header) + rec->data.length);
	NT_STATUS_HAVE_NO_MEMORY(blob.data);

	memcpy(blob.data, &rec->header, sizeof(rec->header));
	memcpy(blob.data + sizeof(rec->header), rec->data.data, rec->data.length);

	/* we send with privileges so messages work from any context */
	priv = root_privileges();
	status = socket_sendto(msg->sock, &blob, &nsent, 0, rec->path, 0);
	talloc_free(priv);

	data_blob_free(&blob);

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
				 rec->header.from, rec->header.to, rec->header.msg_type, 
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
	uint8_t data[MESSAGING_MAX_SIZE];
	size_t msize;

	status = socket_recv(msg->sock, data, sizeof(data), &msize, 0);
	if (!NT_STATUS_IS_OK(status)) {
		return;
	}

	if (msize < sizeof(rec->header)) {
		DEBUG(0,("messaging: bad message of size %d\n", msize));
		return;
	}

	rec = talloc(msg, struct messaging_rec);
	if (rec == NULL) {
		smb_panic("Unable to allocate messaging_rec");
	}

	rec->msg           = msg;
	rec->path          = msg->path;

	memcpy(&rec->header, data, sizeof(rec->header));
	if (msize != sizeof(rec->header) + rec->header.length) {
		DEBUG(0,("messaging: bad message header size %d should be %d\n", 
			 rec->header.length, msize - sizeof(rec->header)));
		talloc_free(rec);
		return;
	}

	rec->data = data_blob_talloc(rec, data+sizeof(rec->header), rec->header.length);
	if (rec->data.data == NULL) {
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
void messaging_register(struct messaging_context *msg, void *private,
			uint32_t msg_type, 
			void (*fn)(struct messaging_context *, void *, uint32_t, uint32_t, DATA_BLOB *))
{
	struct dispatch_fn *d;

	d = talloc(msg, struct dispatch_fn);
	d->msg_type = msg_type;
	d->private = private;
	d->fn = fn;
	DLIST_ADD(msg->dispatch, d);
}

/*
  De-register the function for a particular message type.
*/
void messaging_deregister(struct messaging_context *msg, uint32_t msg_type, void *private)
{
	struct dispatch_fn *d, *next;

	for (d = msg->dispatch; d; d = next) {
		next = d->next;
		if (d->msg_type == msg_type && 
		    d->private == private) {
			DLIST_REMOVE(msg->dispatch, d);
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

	rec = talloc(msg, struct messaging_rec);
	if (rec == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	rec->msg             = msg;
	rec->header.version  = MESSAGING_VERSION;
	rec->header.msg_type = msg_type;
	rec->header.from     = msg->server_id;
	rec->header.to       = server;
	rec->header.length   = data?data->length:0;
	if (rec->header.length != 0) {
		rec->data = data_blob_talloc(rec, data->data, data->length);
	} else {
		rec->data = data_blob(NULL, 0);
	}

	rec->path = messaging_path(rec, server);

	status = try_send(rec);
	if (NT_STATUS_EQUAL(status, STATUS_MORE_ENTRIES)) {
		if (msg->pending == NULL) {
			EVENT_FD_WRITEABLE(msg->event.fde);
		}
		DLIST_ADD(msg->pending, rec);
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
static int messaging_destructor(void *ptr)
{
	struct messaging_context *msg = ptr;
	unlink(msg->path);
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
	char *path;

	msg = talloc(mem_ctx, struct messaging_context);
	if (msg == NULL) {
		return NULL;
	}

	/* create the messaging directory if needed */
	path = smbd_tmp_path(msg, "messaging");
	mkdir(path, 0700);
	talloc_free(path);

	msg->path = messaging_path(msg, server_id);
	msg->server_id = server_id;
	msg->dispatch = NULL;
	msg->pending = NULL;

	status = socket_create("unix", SOCKET_TYPE_DGRAM, &msg->sock, 0);
	if (!NT_STATUS_IS_OK(status)) {
		talloc_free(msg);
		return NULL;
	}

	/* by stealing here we ensure that the socket is cleaned up (and even 
	   deleted) on exit */
	talloc_steal(msg, msg->sock);

	status = socket_listen(msg->sock, msg->path, 0, 50, 0);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0,("Unable to setup messaging listener for '%s'\n", msg->path));
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

	return msg;
}
