/* 
   Unix SMB/CIFS implementation.

   dcerpc over standard sockets transport

   Copyright (C) Andrew Tridgell 2003
   Copyright (C) Jelmer Vernooij 2004
   
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
#include "dlinklist.h"
#include "lib/events/events.h"
#include "librpc/gen_ndr/ndr_epmapper.h"
#include "lib/socket/socket.h"
#include "lib/stream/packet.h"
#include "libcli/composite/composite.h"

/* transport private information used by general socket pipe transports */
struct sock_private {
	struct fd_event *fde;
	struct socket_context *sock;
	char *server_name;

	struct packet_context *packet;
	uint32_t pending_reads;
};


/*
  mark the socket dead
*/
static void sock_dead(struct dcerpc_connection *p, NTSTATUS status)
{
	struct sock_private *sock = p->transport.private;

	if (sock && sock->sock != NULL) {
		talloc_free(sock->fde);
		talloc_free(sock->sock);
		sock->sock = NULL;
	}

	if (!NT_STATUS_IS_OK(status)) {
		p->transport.recv_data(p, NULL, status);
	}
}


/*
  handle socket recv errors
*/
static void sock_error_handler(void *private, NTSTATUS status)
{
	struct dcerpc_connection *p = talloc_get_type(private, 
						      struct dcerpc_connection);
	sock_dead(p, status);
}

/*
  check if a blob is a complete packet
*/
static NTSTATUS sock_complete_packet(void *private, DATA_BLOB blob, size_t *size)
{
	if (blob.length < DCERPC_FRAG_LEN_OFFSET+2) {
		return STATUS_MORE_ENTRIES;
	}
	*size = dcerpc_get_frag_length(&blob);
	if (*size > blob.length) {
		return STATUS_MORE_ENTRIES;
	}
	return NT_STATUS_OK;
}

/*
  process recv requests
*/
static NTSTATUS sock_process_recv(void *private, DATA_BLOB blob)
{
	struct dcerpc_connection *p = talloc_get_type(private, 
						      struct dcerpc_connection);
	struct sock_private *sock = p->transport.private;
	sock->pending_reads--;
	if (sock->pending_reads == 0) {
		packet_recv_disable(sock->packet);
	}
	p->transport.recv_data(p, &blob, NT_STATUS_OK);
	return NT_STATUS_OK;
}

/*
  called when a IO is triggered by the events system
*/
static void sock_io_handler(struct event_context *ev, struct fd_event *fde, 
			    uint16_t flags, void *private)
{
	struct dcerpc_connection *p = talloc_get_type(private, 
						      struct dcerpc_connection);
	struct sock_private *sock = p->transport.private;

	if (flags & EVENT_FD_WRITE) {
		packet_queue_run(sock->packet);
		return;
	}

	if (sock->sock == NULL) {
		return;
	}

	if (flags & EVENT_FD_READ) {
		packet_recv(sock->packet);
	}
}

/* 
   initiate a read request - not needed for dcerpc sockets
*/
static NTSTATUS sock_send_read(struct dcerpc_connection *p)
{
	struct sock_private *sock = p->transport.private;
	sock->pending_reads++;
	if (sock->pending_reads == 1) {
		packet_recv_enable(sock->packet);
	}
	return NT_STATUS_OK;
}

/* 
   send an initial pdu in a multi-pdu sequence
*/
static NTSTATUS sock_send_request(struct dcerpc_connection *p, DATA_BLOB *data, 
				  BOOL trigger_read)
{
	struct sock_private *sock = p->transport.private;
	DATA_BLOB blob;
	NTSTATUS status;

	if (sock->sock == NULL) {
		return NT_STATUS_CONNECTION_DISCONNECTED;
	}

	blob = data_blob_talloc(sock->packet, data->data, data->length);
	if (blob.data == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	status = packet_send(sock->packet, blob);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	if (trigger_read) {
		sock_send_read(p);
	}

	return NT_STATUS_OK;
}

/* 
   shutdown sock pipe connection
*/
static NTSTATUS sock_shutdown_pipe(struct dcerpc_connection *p)
{
	struct sock_private *sock = p->transport.private;

	if (sock && sock->sock) {
		sock_dead(p, NT_STATUS_OK);
	}

	return NT_STATUS_OK;
}

/*
  return sock server name
*/
static const char *sock_peer_name(struct dcerpc_connection *p)
{
	struct sock_private *sock = p->transport.private;
	return sock->server_name;
}


struct pipe_open_socket_state {
	struct dcerpc_connection *conn;
	struct socket_context *socket_ctx;
	struct sock_private *sock;
	const char *server;
	uint32_t port;
	enum dcerpc_transport_t transport;
};


static void continue_socket_connect(struct composite_context *ctx)
{
	struct dcerpc_connection *conn;
	struct sock_private *sock;
	struct composite_context *c = talloc_get_type(ctx->async.private_data,
						      struct composite_context);
	struct pipe_open_socket_state *s = talloc_get_type(c->private_data,
							   struct pipe_open_socket_state);

	/* make it easier to write a function calls */
	conn = s->conn;
	sock = s->sock;

	c->status = socket_connect_recv(ctx);
	if (!NT_STATUS_IS_OK(c->status)) {
		DEBUG(0, ("Failed to connect host %s on port %d - %s\n", s->server, s->port,
			  nt_errstr(c->status)));
		composite_error(c, c->status);
		return;
	}

	/*
	  fill in the transport methods
	*/
	conn->transport.transport     = s->transport;
	conn->transport.private       = NULL;

	conn->transport.send_request  = sock_send_request;
	conn->transport.send_read     = sock_send_read;
	conn->transport.recv_data     = NULL;

	conn->transport.shutdown_pipe = sock_shutdown_pipe;
	conn->transport.peer_name     = sock_peer_name;

	sock->sock          = s->socket_ctx;
	sock->pending_reads = 0;
	sock->server_name   = strupper_talloc(sock, s->server);

	sock->fde = event_add_fd(conn->event_ctx, sock->sock, socket_get_fd(sock->sock),
				 0, sock_io_handler, conn);
	
	conn->transport.private = sock;

	sock->packet = packet_init(sock);
	if (sock->packet == NULL) {
		composite_error(c, NT_STATUS_NO_MEMORY);
		talloc_free(sock);
		return;
	}

	packet_set_private(sock->packet, conn);
	packet_set_socket(sock->packet, sock->sock);
	packet_set_callback(sock->packet, sock_process_recv);
	packet_set_full_request(sock->packet, sock_complete_packet);
	packet_set_error_handler(sock->packet, sock_error_handler);
	packet_set_event_context(sock->packet, conn->event_ctx);
	packet_set_fde(sock->packet, sock->fde);
	packet_set_serialise(sock->packet);
	packet_recv_disable(sock->packet);
	packet_set_initial_read(sock->packet, 16);

	/* ensure we don't get SIGPIPE */
	BlockSignals(True,SIGPIPE);

	composite_done(c);
}


struct composite_context *dcerpc_pipe_open_socket_send(TALLOC_CTX *mem_ctx,
						       struct dcerpc_connection *cn,
						       const char *server,
						       uint32_t port, 
						       const char *type,
						       enum dcerpc_transport_t transport)
{
	NTSTATUS status;
	struct composite_context *c;
	struct pipe_open_socket_state *s;
	struct composite_context *conn_req;

	c = talloc_zero(mem_ctx, struct composite_context);
	if (c == NULL) return NULL;

	s = talloc_zero(c, struct pipe_open_socket_state);
	if (s == NULL) {
		composite_error(c, NT_STATUS_NO_MEMORY);
		goto done;
	}

	c->state = COMPOSITE_STATE_IN_PROGRESS;
	c->private_data = s;
	c->event_ctx = cn->event_ctx;

	s->conn      = cn;
	s->transport = transport;
	s->port      = port;
	s->server    = talloc_strdup(c, server);
	if (s->server == NULL) {
		composite_error(c, NT_STATUS_NO_MEMORY);
		goto done;
	}

	s->sock = talloc(cn, struct sock_private);
	if (s->sock == NULL) {
		composite_error(c, NT_STATUS_NO_MEMORY);
		goto done;
	}

	status = socket_create(type, SOCKET_TYPE_STREAM, &s->socket_ctx, 0);
	if (!NT_STATUS_IS_OK(status)) {
		composite_error(c, status);
		talloc_free(s->sock);
		goto done;
	}
	talloc_steal(s->sock, s->socket_ctx);

	conn_req = socket_connect_send(s->socket_ctx, NULL, 0, s->server, s->port, 0, c->event_ctx);
	if (conn_req == NULL) {
		composite_error(c, NT_STATUS_NO_MEMORY);
		goto done;
	}
	
	composite_continue(c, conn_req, continue_socket_connect, c);

done:
	return c;
}


NTSTATUS dcerpc_pipe_open_socket_recv(struct composite_context *c)
{
	NTSTATUS status = composite_wait(c);

	talloc_free(c);
	return status;
}

/* 
   open a rpc connection using the generic socket library
*/
NTSTATUS dcerpc_pipe_open_socket(struct dcerpc_connection *conn,
				 const char *server,
				 uint32_t port, 
				 const char *type,
				 enum dcerpc_transport_t transport)
{
	struct composite_context *c;
	
	c = dcerpc_pipe_open_socket_send(conn, conn, server, port,
					 type, transport);
	return dcerpc_pipe_open_socket_recv(c);
}


/* 
   open a rpc connection using tcp
*/
NTSTATUS dcerpc_pipe_open_tcp(struct dcerpc_connection *c, const char *server, uint32_t port)
{
	NTSTATUS status;
	
	/* Try IPv6 first */
	status = dcerpc_pipe_open_socket(c, server, port, "ipv6", NCACN_IP_TCP);
	if (NT_STATUS_IS_OK(status)) {
		return status;
	}
	
	return dcerpc_pipe_open_socket(c, server, port, "ipv4", NCACN_IP_TCP);
}

/* 
   open a rpc connection to a unix socket 
*/
NTSTATUS dcerpc_pipe_open_unix_stream(struct dcerpc_connection *c, const char *path)
{
	return dcerpc_pipe_open_socket(c, path, 0, "unix", NCACN_UNIX_STREAM);
}

/* 
   open a rpc connection to a named pipe 
*/
NTSTATUS dcerpc_pipe_open_pipe(struct dcerpc_connection *c, const char *identifier)
{
	NTSTATUS status;
	char *canon, *full_path;

	canon = talloc_strdup(NULL, identifier);

	string_replace(canon, '/', '\\');
	full_path = talloc_asprintf(canon, "%s/%s", lp_ncalrpc_dir(), canon);

	status = dcerpc_pipe_open_socket(c, full_path, 0, "unix", NCALRPC);
	talloc_free(canon);

	return status;
}
