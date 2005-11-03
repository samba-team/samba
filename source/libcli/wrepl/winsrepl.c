/* 
   Unix SMB/CIFS implementation.

   low level WINS replication client code

   Copyright (C) Andrew Tridgell 2005
   
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
#include "dlinklist.h"
#include "lib/socket/socket.h"
#include "libcli/wrepl/winsrepl.h"

/*
  mark all pending requests as dead - called when a socket error happens
*/
static void wrepl_socket_dead(struct wrepl_socket *wrepl_socket, NTSTATUS status)
{
	talloc_set_destructor(wrepl_socket, NULL);
	wrepl_socket->dead = True;

	if (wrepl_socket->fde) {
		talloc_free(wrepl_socket->fde);
		wrepl_socket->fde = NULL;
	}

	if (wrepl_socket->sock) {
		talloc_free(wrepl_socket->sock);
		wrepl_socket->sock = NULL;
	}

	if (NT_STATUS_EQUAL(NT_STATUS_UNSUCCESSFUL, status)) {
		status = NT_STATUS_UNEXPECTED_NETWORK_ERROR;
	}
	while (wrepl_socket->send_queue) {
		struct wrepl_request *req = wrepl_socket->send_queue;
		DLIST_REMOVE(wrepl_socket->send_queue, req);
		req->state = WREPL_REQUEST_ERROR;
		req->status = status;
		if (req->async.fn) {
			req->async.fn(req);
		}
	}
	while (wrepl_socket->recv_queue) {
		struct wrepl_request *req = wrepl_socket->recv_queue;
		DLIST_REMOVE(wrepl_socket->recv_queue, req);
		req->state = WREPL_REQUEST_ERROR;
		req->status = status;
		if (req->async.fn) {
			req->async.fn(req);
		}
	}
}

static void wrepl_request_timeout_handler(struct event_context *ev, struct timed_event *te,
					  struct timeval t, void *ptr)
{
	struct wrepl_request *req = talloc_get_type(ptr, struct wrepl_request);
	wrepl_socket_dead(req->wrepl_socket, NT_STATUS_IO_TIMEOUT);
}

/*
  handle send events 
*/
static void wrepl_handler_send(struct wrepl_socket *wrepl_socket)
{
	while (wrepl_socket->send_queue) {
		struct wrepl_request *req = wrepl_socket->send_queue;
		size_t nsent;
		NTSTATUS status;

		status = socket_send(wrepl_socket->sock, &req->buffer, &nsent, 0);
		if (NT_STATUS_IS_ERR(status)) {
			wrepl_socket_dead(wrepl_socket, status);
			return;
		}
		if (!NT_STATUS_IS_OK(status) || nsent == 0) return;

		req->buffer.data   += nsent;
		req->buffer.length -= nsent;
		if (req->buffer.length != 0) {
			return;
		}

		if (req->disconnect_after_send) {
			DLIST_REMOVE(wrepl_socket->send_queue, req);
			req->status = NT_STATUS_OK;
			req->state = WREPL_REQUEST_DONE;
			wrepl_socket_dead(wrepl_socket, NT_STATUS_LOCAL_DISCONNECT);
			if (req->async.fn) {
				req->async.fn(req);
			}
			return;
		}

		if (req->send_only) {
			DLIST_REMOVE(wrepl_socket->send_queue, req);
			req->status = NT_STATUS_OK;
			req->state = WREPL_REQUEST_DONE;
			if (req->async.fn) {
				EVENT_FD_READABLE(wrepl_socket->fde);
				req->async.fn(req);
				return;
			}
		} else {
			DLIST_REMOVE(wrepl_socket->send_queue, req);
			DLIST_ADD_END(wrepl_socket->recv_queue, req, struct wrepl_request *);
			req->state = WREPL_REQUEST_RECV;
		}

		EVENT_FD_READABLE(wrepl_socket->fde);
	}

	EVENT_FD_NOT_WRITEABLE(wrepl_socket->fde);
}


/*
  handle recv events 
*/
static void wrepl_handler_recv(struct wrepl_socket *wrepl_socket)
{
	size_t nread;
	struct wrepl_request *req = wrepl_socket->recv_queue;
	DATA_BLOB blob;

	if (req == NULL) {
		NTSTATUS status;

		EVENT_FD_NOT_READABLE(wrepl_socket->fde);

		status = socket_recv(wrepl_socket->sock, NULL, 0, &nread, 0);
		if (NT_STATUS_EQUAL(NT_STATUS_END_OF_FILE,status)) return;
		if (NT_STATUS_IS_ERR(status)) {
			wrepl_socket_dead(wrepl_socket, status);
			return;
		}
		return;
	}

	if (req->buffer.length == 0) {
		req->buffer = data_blob_talloc(req, NULL, 4);
		if (req->buffer.data == NULL) {
			req->status = NT_STATUS_NO_MEMORY;
			goto failed;
		}
		req->num_read = 0;
	}

	/* read in the packet length */
	if (req->num_read < 4) {
		uint32_t req_length;

		req->status = socket_recv(wrepl_socket->sock, 
					  req->buffer.data + req->num_read,
					  4 - req->num_read,
					  &nread, 0);
		if (NT_STATUS_IS_ERR(req->status)) {
			wrepl_socket_dead(wrepl_socket, req->status);
			return;
		}
		if (!NT_STATUS_IS_OK(req->status)) return;

		req->num_read += nread;
		if (req->num_read != 4) return;

		req_length = RIVAL(req->buffer.data, 0) + 4;

		req->buffer.data = talloc_realloc(req, req->buffer.data, 
						  uint8_t, req_length);
		if (req->buffer.data == NULL) {
			req->status = NT_STATUS_NO_MEMORY;
			goto failed;
		}
		req->buffer.length = req_length;
	}

	/* read in the body */
	req->status = socket_recv(wrepl_socket->sock, 
				  req->buffer.data + req->num_read,
				  req->buffer.length - req->num_read,
				  &nread, 0);
	if (NT_STATUS_IS_ERR(req->status)) {
		wrepl_socket_dead(wrepl_socket, req->status);
		return;
	}
	if (!NT_STATUS_IS_OK(req->status)) return;

	req->num_read += nread;
	if (req->num_read != req->buffer.length) return;

	req->packet = talloc(req, struct wrepl_packet);
	if (req->packet == NULL) {
		req->status = NT_STATUS_NO_MEMORY;
		goto failed;
	}

	blob.data = req->buffer.data + 4;
	blob.length = req->buffer.length - 4;
	
	/* we have a full request - parse it */
	req->status = ndr_pull_struct_blob(&blob,
					   req->packet, req->packet,
					   (ndr_pull_flags_fn_t)ndr_pull_wrepl_packet);
	if (!NT_STATUS_IS_OK(req->status)) {
		DEBUG(2,("Failed to parse incoming WINS packet - %s\n",
			 nt_errstr(req->status)));
		DEBUG(10,("packet length %d\n", (int)req->buffer.length));
		NDR_PRINT_DEBUG(wrepl_packet, req->packet);
		goto failed;
	}

	if (DEBUGLVL(10)) {
		DEBUG(10,("Received WINS packet of length %d\n", (int)req->buffer.length));
		NDR_PRINT_DEBUG(wrepl_packet, req->packet);
	}

	DLIST_REMOVE(wrepl_socket->recv_queue, req);
	req->state = WREPL_REQUEST_DONE;
	if (req->async.fn) {
		req->async.fn(req);
	}
	return;

failed:
	if (req->state == WREPL_REQUEST_RECV) {
		DLIST_REMOVE(wrepl_socket->recv_queue, req);
	}
	req->state = WREPL_REQUEST_ERROR;
	if (req->async.fn) {
		req->async.fn(req);
	}
}


/*
  handler for winrepl events
*/
static void wrepl_handler(struct event_context *ev, struct fd_event *fde, 
			  uint16_t flags, void *private)
{
	struct wrepl_socket *wrepl_socket = talloc_get_type(private, 
							    struct wrepl_socket);
	if (flags & EVENT_FD_WRITE) {
		wrepl_handler_send(wrepl_socket);
	}
	if (flags & EVENT_FD_READ) {
		wrepl_handler_recv(wrepl_socket);
	}
}


/*
  handler for winrepl connection completion
*/
static void wrepl_connect_handler(struct event_context *ev, struct fd_event *fde, 
				  uint16_t flags, void *private)
{
	struct wrepl_socket *wrepl_socket = talloc_get_type(private, 
							    struct wrepl_socket);
	struct wrepl_request *req = wrepl_socket->recv_queue;

	talloc_free(wrepl_socket->fde);
	wrepl_socket->fde = NULL;

	if (req == NULL) return;

	req->status = socket_connect_complete(wrepl_socket->sock, 0);
	if (NT_STATUS_IS_ERR(req->status)) goto failed;

	if (!NT_STATUS_IS_OK(req->status)) return;

	wrepl_socket->fde = event_add_fd(wrepl_socket->event_ctx, wrepl_socket, 
					 socket_get_fd(wrepl_socket->sock), 
					 EVENT_FD_WRITE,
					 wrepl_handler, wrepl_socket);
	if (wrepl_socket->fde == NULL) {
		req->status = NT_STATUS_NO_MEMORY;
	}


failed:
	DLIST_REMOVE(wrepl_socket->recv_queue, req);
	if (!NT_STATUS_IS_OK(req->status)) {
		req->state = WREPL_REQUEST_ERROR;
	} else {
		req->state = WREPL_REQUEST_DONE;
	}
	if (req->async.fn) {
		req->async.fn(req);
	}
}

/*
  destroy a wrepl_socket destructor
*/
static int wrepl_socket_destructor(void *ptr)
{
	struct wrepl_socket *sock = talloc_get_type(ptr, struct wrepl_socket);
	wrepl_socket_dead(sock, NT_STATUS_LOCAL_DISCONNECT);
	return 0;
}

/*
  initialise a wrepl_socket. The event_ctx is optional, if provided then
  operations will use that event context
*/
struct wrepl_socket *wrepl_socket_init(TALLOC_CTX *mem_ctx, 
				       struct event_context *event_ctx)
{
	struct wrepl_socket *wrepl_socket;
	NTSTATUS status;

	wrepl_socket = talloc(mem_ctx, struct wrepl_socket);
	if (wrepl_socket == NULL) goto failed;

	if (event_ctx == NULL) {
		wrepl_socket->event_ctx = event_context_init(wrepl_socket);
	} else {
		wrepl_socket->event_ctx = talloc_reference(wrepl_socket, event_ctx);
	}
	if (wrepl_socket->event_ctx == NULL) goto failed;

	status = socket_create("ip", SOCKET_TYPE_STREAM, &wrepl_socket->sock, 0);
	if (!NT_STATUS_IS_OK(status)) goto failed;

	talloc_steal(wrepl_socket, wrepl_socket->sock);

	wrepl_socket->send_queue	= NULL;
	wrepl_socket->recv_queue	= NULL;
	wrepl_socket->request_timeout	= WREPL_SOCKET_REQUEST_TIMEOUT;
	wrepl_socket->dead		= False;

	wrepl_socket->fde = event_add_fd(wrepl_socket->event_ctx, wrepl_socket, 
					 socket_get_fd(wrepl_socket->sock), 
					 EVENT_FD_WRITE,
					 wrepl_connect_handler, wrepl_socket);
	if (wrepl_socket->fde == NULL) {
		goto failed;
	}

	set_blocking(socket_get_fd(wrepl_socket->sock), False);

	talloc_set_destructor(wrepl_socket, wrepl_socket_destructor);

	return wrepl_socket;

failed:
	talloc_free(wrepl_socket);
	return NULL;
}

/*
  initialise a wrepl_socket from an already existing connection
*/
struct wrepl_socket *wrepl_socket_merge(TALLOC_CTX *mem_ctx, 
				        struct event_context *event_ctx,
					struct socket_context *socket)
{
	struct wrepl_socket *wrepl_socket;

	wrepl_socket = talloc(mem_ctx, struct wrepl_socket);
	if (wrepl_socket == NULL) goto failed;

	wrepl_socket->event_ctx = talloc_reference(wrepl_socket, event_ctx);
	if (wrepl_socket->event_ctx == NULL) goto failed;

	wrepl_socket->sock = socket;
	talloc_steal(wrepl_socket, wrepl_socket->sock);

	wrepl_socket->send_queue	= NULL;
	wrepl_socket->recv_queue	= NULL;
	wrepl_socket->request_timeout	= WREPL_SOCKET_REQUEST_TIMEOUT;
	wrepl_socket->dead		= False;

	wrepl_socket->fde = event_add_fd(wrepl_socket->event_ctx, wrepl_socket,
					 socket_get_fd(wrepl_socket->sock), 
					 0,
					 wrepl_handler, wrepl_socket);
	if (wrepl_socket->fde == NULL) {
		goto failed;
	}

	talloc_set_destructor(wrepl_socket, wrepl_socket_destructor);
	
	return wrepl_socket;

failed:
	talloc_free(wrepl_socket);
	return NULL;
}

/*
  destroy a wrepl_request
*/
static int wrepl_request_destructor(void *ptr)
{
	struct wrepl_request *req = talloc_get_type(ptr, struct wrepl_request);
	if (req->state == WREPL_REQUEST_SEND) {
		DLIST_REMOVE(req->wrepl_socket->send_queue, req);
	}
	if (req->state == WREPL_REQUEST_RECV) {
		DLIST_REMOVE(req->wrepl_socket->recv_queue, req);
	}
	req->state = WREPL_REQUEST_ERROR;
	return 0;
}

/*
  wait for a request to complete
*/
static NTSTATUS wrepl_request_wait(struct wrepl_request *req)
{
	NT_STATUS_HAVE_NO_MEMORY(req);
	while (req->state < WREPL_REQUEST_DONE) {
		event_loop_once(req->wrepl_socket->event_ctx);
	}
	return req->status;
}

static void wrepl_request_trigger(struct wrepl_request *req);

/*
  connect a wrepl_socket to a WINS server
*/
struct wrepl_request *wrepl_connect_send(struct wrepl_socket *wrepl_socket,
					 const char *our_ip, const char *peer_ip)
{
	struct wrepl_request *req;
	NTSTATUS status;

	req = talloc_zero(wrepl_socket, struct wrepl_request);
	if (req == NULL) goto failed;

	req->wrepl_socket = wrepl_socket;
	req->state        = WREPL_REQUEST_RECV;

	DLIST_ADD(wrepl_socket->recv_queue, req);

	talloc_set_destructor(req, wrepl_request_destructor);

	if (!our_ip) {
		our_ip = iface_best_ip(peer_ip);
	}

	status = socket_connect(wrepl_socket->sock, our_ip, 0, peer_ip, 
				WINS_REPLICATION_PORT, 0);
	if (!NT_STATUS_EQUAL(status, NT_STATUS_MORE_PROCESSING_REQUIRED)) {
		req->wrepl_socket = wrepl_socket;
		req->state        = WREPL_REQUEST_ERROR;
		req->status       = status;
		wrepl_request_trigger(req);
		return req;
	}

	return req;

failed:
	talloc_free(req);
	return NULL;
}

/*
  connect a wrepl_socket to a WINS server - recv side
*/
NTSTATUS wrepl_connect_recv(struct wrepl_request *req)
{
	return wrepl_request_wait(req);
}


/*
  connect a wrepl_socket to a WINS server - sync API
*/
NTSTATUS wrepl_connect(struct wrepl_socket *wrepl_socket, const char *our_ip, const char *peer_ip)
{
	struct wrepl_request *req = wrepl_connect_send(wrepl_socket, our_ip, peer_ip);
	return wrepl_connect_recv(req);
}

/* 
   callback from wrepl_request_trigger() 
*/
static void wrepl_request_trigger_handler(struct event_context *ev, struct timed_event *te,
					  struct timeval t, void *ptr)
{
	struct wrepl_request *req = talloc_get_type(ptr, struct wrepl_request);
	struct wrepl_socket *wrepl_socket = req->wrepl_socket;
	DLIST_REMOVE(wrepl_socket->send_queue, req);
	DLIST_REMOVE(wrepl_socket->recv_queue, req);
	if (req->async.fn) {
		req->async.fn(req);
	}
}

/*
  trigger an immediate event on a wrepl_request
*/
static void wrepl_request_trigger(struct wrepl_request *req)
{
	/* a zero timeout means immediate */
	event_add_timed(req->wrepl_socket->event_ctx,
			req, timeval_zero(),
			wrepl_request_trigger_handler, req);
}


/*
  send a generic wins replication request
*/
struct wrepl_request *wrepl_request_send(struct wrepl_socket *wrepl_socket,
					 struct wrepl_packet *packet)
{
	struct wrepl_request *req;
	struct wrepl_wrap wrap;

	req = talloc_zero(wrepl_socket, struct wrepl_request);
	if (req == NULL) goto failed;

	if (wrepl_socket->dead) {
		req->wrepl_socket = wrepl_socket;
		req->state        = WREPL_REQUEST_ERROR;
		req->status       = NT_STATUS_INVALID_CONNECTION;
		wrepl_request_trigger(req);
		return req;
	}

	req->wrepl_socket = wrepl_socket;
	req->state        = WREPL_REQUEST_SEND;

	wrap.packet = *packet;
	req->status = ndr_push_struct_blob(&req->buffer, req, &wrap,
					   (ndr_push_flags_fn_t)ndr_push_wrepl_wrap);
	if (!NT_STATUS_IS_OK(req->status)) goto failed;

	if (DEBUGLVL(10)) {
		DEBUG(10,("Sending WINS packet of length %d\n", (int)req->buffer.length));
		NDR_PRINT_DEBUG(wrepl_packet, &wrap.packet);
	}

	DLIST_ADD(wrepl_socket->send_queue, req);

	talloc_set_destructor(req, wrepl_request_destructor);

	if (wrepl_socket->request_timeout > 0) {
		req->te = event_add_timed(wrepl_socket->event_ctx, req, 
					  timeval_current_ofs(wrepl_socket->request_timeout, 0), 
					  wrepl_request_timeout_handler, req);
	}

	EVENT_FD_WRITEABLE(wrepl_socket->fde);
	
	return req;

failed:
	talloc_free(req);
	return NULL;
}

/*
  receive a generic WINS replication reply
*/
NTSTATUS wrepl_request_recv(struct wrepl_request *req,
			    TALLOC_CTX *mem_ctx,
			    struct wrepl_packet **packet)
{
	NTSTATUS status = wrepl_request_wait(req);
	if (NT_STATUS_IS_OK(status)) {
		*packet = talloc_steal(mem_ctx, req->packet);
	}
	talloc_free(req);
	return status;
}

/*
  a full WINS replication request/response
*/
NTSTATUS wrepl_request(struct wrepl_socket *wrepl_socket,
		       TALLOC_CTX *mem_ctx,
		       struct wrepl_packet *req_packet,
		       struct wrepl_packet **reply_packet)
{
	struct wrepl_request *req = wrepl_request_send(wrepl_socket, req_packet);
	return wrepl_request_recv(req, mem_ctx, reply_packet);
}


/*
  setup an association - send
*/
struct wrepl_request *wrepl_associate_send(struct wrepl_socket *wrepl_socket,
					   struct wrepl_associate *io)
{
	struct wrepl_packet *packet;
	struct wrepl_request *req;

	packet = talloc_zero(wrepl_socket, struct wrepl_packet);
	if (packet == NULL) return NULL;

	packet->opcode                      = WREPL_OPCODE_BITS;
	packet->mess_type                   = WREPL_START_ASSOCIATION;
	packet->message.start.minor_version = 2;
	packet->message.start.major_version = 5;

	req = wrepl_request_send(wrepl_socket, packet);

	talloc_free(packet);

	return req;	
}

/*
  setup an association - recv
*/
NTSTATUS wrepl_associate_recv(struct wrepl_request *req,
			      struct wrepl_associate *io)
{
	struct wrepl_packet *packet=NULL;
	NTSTATUS status;
	status = wrepl_request_recv(req, req->wrepl_socket, &packet);
	NT_STATUS_NOT_OK_RETURN(status);
	if (packet->mess_type != WREPL_START_ASSOCIATION_REPLY) {
		status = NT_STATUS_UNEXPECTED_NETWORK_ERROR;
	}
	if (NT_STATUS_IS_OK(status)) {
		io->out.assoc_ctx = packet->message.start_reply.assoc_ctx;
	}
	talloc_free(packet);
	return status;
}

/*
  setup an association - sync api
*/
NTSTATUS wrepl_associate(struct wrepl_socket *wrepl_socket,
			 struct wrepl_associate *io)
{
	struct wrepl_request *req = wrepl_associate_send(wrepl_socket, io);
	return wrepl_associate_recv(req, io);
}


/*
  stop an association - send
*/
struct wrepl_request *wrepl_associate_stop_send(struct wrepl_socket *wrepl_socket,
						struct wrepl_associate_stop *io)
{
	struct wrepl_packet *packet;
	struct wrepl_request *req;

	packet = talloc_zero(wrepl_socket, struct wrepl_packet);
	if (packet == NULL) return NULL;

	packet->opcode			= WREPL_OPCODE_BITS;
	packet->assoc_ctx		= io->in.assoc_ctx;
	packet->mess_type		= WREPL_STOP_ASSOCIATION;
	packet->message.stop.reason	= io->in.reason;

	req = wrepl_request_send(wrepl_socket, packet);

	if (req && io->in.reason == 0) {
		req->send_only			= True;
		req->disconnect_after_send	= True;
	}

	talloc_free(packet);

	return req;	
}

/*
  stop an association - recv
*/
NTSTATUS wrepl_associate_stop_recv(struct wrepl_request *req,
				   struct wrepl_associate_stop *io)
{
	struct wrepl_packet *packet=NULL;
	NTSTATUS status;
	status = wrepl_request_recv(req, req->wrepl_socket, &packet);
	NT_STATUS_NOT_OK_RETURN(status);
	talloc_free(packet);
	return status;
}

/*
  setup an association - sync api
*/
NTSTATUS wrepl_associate_stop(struct wrepl_socket *wrepl_socket,
			      struct wrepl_associate_stop *io)
{
	struct wrepl_request *req = wrepl_associate_stop_send(wrepl_socket, io);
	return wrepl_associate_stop_recv(req, io);
}

/*
  fetch the partner tables - send
*/
struct wrepl_request *wrepl_pull_table_send(struct wrepl_socket *wrepl_socket,
					    struct wrepl_pull_table *io)
{
	struct wrepl_packet *packet;
	struct wrepl_request *req;

	packet = talloc_zero(wrepl_socket, struct wrepl_packet);
	if (packet == NULL) return NULL;

	packet->opcode                      = WREPL_OPCODE_BITS;
	packet->assoc_ctx                   = io->in.assoc_ctx;
	packet->mess_type                   = WREPL_REPLICATION;
	packet->message.replication.command = WREPL_REPL_TABLE_QUERY;

	req = wrepl_request_send(wrepl_socket, packet);

	talloc_free(packet);

	return req;	
}


/*
  fetch the partner tables - recv
*/
NTSTATUS wrepl_pull_table_recv(struct wrepl_request *req,
			       TALLOC_CTX *mem_ctx,
			       struct wrepl_pull_table *io)
{
	struct wrepl_packet *packet=NULL;
	NTSTATUS status;
	struct wrepl_table *table;
	int i;

	status = wrepl_request_recv(req, req->wrepl_socket, &packet);
	NT_STATUS_NOT_OK_RETURN(status);
	if (packet->mess_type != WREPL_REPLICATION) {
		status = NT_STATUS_NETWORK_ACCESS_DENIED;
	} else if (packet->message.replication.command != WREPL_REPL_TABLE_REPLY) {
		status = NT_STATUS_UNEXPECTED_NETWORK_ERROR;
	}
	if (!NT_STATUS_IS_OK(status)) goto failed;

	table = &packet->message.replication.info.table;
	io->out.num_partners = table->partner_count;
	io->out.partners = talloc_steal(mem_ctx, table->partners);
	for (i=0;i<io->out.num_partners;i++) {
		talloc_steal(io->out.partners, io->out.partners[i].address);
	}

failed:
	talloc_free(packet);
	return status;
}


/*
  fetch the partner table - sync api
*/
NTSTATUS wrepl_pull_table(struct wrepl_socket *wrepl_socket,
			  TALLOC_CTX *mem_ctx,
			  struct wrepl_pull_table *io)
{
	struct wrepl_request *req = wrepl_pull_table_send(wrepl_socket, io);
	return wrepl_pull_table_recv(req, mem_ctx, io);
}


/*
  fetch the names for a WINS partner - send
*/
struct wrepl_request *wrepl_pull_names_send(struct wrepl_socket *wrepl_socket,
					    struct wrepl_pull_names *io)
{
	struct wrepl_packet *packet;
	struct wrepl_request *req;

	packet = talloc_zero(wrepl_socket, struct wrepl_packet);
	if (packet == NULL) return NULL;

	packet->opcode                         = WREPL_OPCODE_BITS;
	packet->assoc_ctx                      = io->in.assoc_ctx;
	packet->mess_type                      = WREPL_REPLICATION;
	packet->message.replication.command    = WREPL_REPL_SEND_REQUEST;
	packet->message.replication.info.owner = io->in.partner;

	req = wrepl_request_send(wrepl_socket, packet);

	talloc_free(packet);

	return req;	
}

/*
  fetch the names for a WINS partner - recv
*/
NTSTATUS wrepl_pull_names_recv(struct wrepl_request *req,
			       TALLOC_CTX *mem_ctx,
			       struct wrepl_pull_names *io)
{
	struct wrepl_packet *packet=NULL;
	NTSTATUS status;
	int i;

	status = wrepl_request_recv(req, req->wrepl_socket, &packet);
	NT_STATUS_NOT_OK_RETURN(status);
	if (packet->mess_type != WREPL_REPLICATION ||
	    packet->message.replication.command != WREPL_REPL_SEND_REPLY) {
		status = NT_STATUS_UNEXPECTED_NETWORK_ERROR;
	}
	if (!NT_STATUS_IS_OK(status)) goto failed;

	io->out.num_names = packet->message.replication.info.reply.num_names;

	io->out.names = talloc_array(packet, struct wrepl_name, io->out.num_names);
	if (io->out.names == NULL) goto nomem;

	/* convert the list of names and addresses to a sane format */
	for (i=0;i<io->out.num_names;i++) {
		struct wrepl_wins_name *wname = &packet->message.replication.info.reply.names[i];
		struct wrepl_name *name = &io->out.names[i];

		name->name	= *wname->name;
		talloc_steal(io->out.names, wname->name);
		name->type	= WREPL_NAME_TYPE(wname->flags);
		name->state	= WREPL_NAME_STATE(wname->flags);
		name->node	= WREPL_NAME_NODE(wname->flags);
		name->is_static	= WREPL_NAME_IS_STATIC(wname->flags);
		name->raw_flags	= wname->flags;
		name->version_id= wname->id;
		name->owner	= talloc_strdup(io->out.names, io->in.partner.address);
		if (name->owner == NULL) goto nomem;

		/* trying to save 1 or 2 bytes on the wire isn't a good idea */
		if (wname->flags & 2) {
			int j;

			name->num_addresses = wname->addresses.addresses.num_ips;
			name->addresses = talloc_array(io->out.names, 
						       struct wrepl_address, 
						       name->num_addresses);
			if (name->addresses == NULL) goto nomem;
			for (j=0;j<name->num_addresses;j++) {
				name->addresses[j].owner = 
					talloc_steal(name->addresses, 
						     wname->addresses.addresses.ips[j].owner);
				name->addresses[j].address = 
					talloc_steal(name->addresses, 
						     wname->addresses.addresses.ips[j].ip);
			}
		} else {
			name->num_addresses = 1;
			name->addresses = talloc(io->out.names, struct wrepl_address);
			if (name->addresses == NULL) goto nomem;
			name->addresses[0].owner = talloc_strdup(name->addresses,io->in.partner.address);
			if (name->addresses[0].owner == NULL) goto nomem;
			name->addresses[0].address = talloc_steal(name->addresses,
								  wname->addresses.ip);
		}
	}

	talloc_steal(mem_ctx, io->out.names);
	talloc_free(packet);
	return NT_STATUS_OK;
nomem:
	status = NT_STATUS_NO_MEMORY;
failed:
	talloc_free(packet);
	return status;
}



/*
  fetch the names for a WINS partner - sync api
*/
NTSTATUS wrepl_pull_names(struct wrepl_socket *wrepl_socket,
			  TALLOC_CTX *mem_ctx,
			  struct wrepl_pull_names *io)
{
	struct wrepl_request *req = wrepl_pull_names_send(wrepl_socket, io);
	return wrepl_pull_names_recv(req, mem_ctx, io);
}
