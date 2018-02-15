/* 
   Unix SMB/CIFS implementation.

   dcerpc over standard sockets transport

   Copyright (C) Andrew Tridgell 2003
   Copyright (C) Jelmer Vernooij 2004
   Copyright (C) Rafal Szczesniak 2006
   
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "includes.h"
#include "system/filesys.h"
#include "lib/events/events.h"
#include "lib/socket/socket.h"
#include "lib/tsocket/tsocket.h"
#include "libcli/composite/composite.h"
#include "librpc/rpc/dcerpc.h"
#include "librpc/rpc/dcerpc_proto.h"
#include "libcli/resolve/resolve.h"
#include "librpc/rpc/rpc_common.h"

struct pipe_open_socket_state {
	struct dcecli_connection *conn;
	struct socket_context *socket_ctx;
	struct socket_address *localaddr;
	struct socket_address *server;
	const char *target_hostname;
	enum dcerpc_transport_t transport;
	struct socket_address *client;
};


static void continue_socket_connect(struct composite_context *ctx)
{
	struct dcecli_connection *conn;
	struct composite_context *c = talloc_get_type_abort(
		ctx->async.private_data, struct composite_context);
	struct pipe_open_socket_state *s = talloc_get_type_abort(
		c->private_data, struct pipe_open_socket_state);
	int rc;
	int sock_fd;

	/* make it easier to write a function calls */
	conn = s->conn;

	c->status = socket_connect_recv(ctx);
	if (!NT_STATUS_IS_OK(c->status)) {
		DEBUG(0, ("Failed to connect host %s on port %d - %s\n", 
			  s->server->addr, s->server->port,
			  nt_errstr(c->status)));
		composite_error(c, c->status);
		return;
	}

	s->client = socket_get_my_addr(s->socket_ctx, s);
	if (s->client == NULL) {
		TALLOC_FREE(s->socket_ctx);
		composite_error(c, NT_STATUS_NO_MEMORY);
		return;
	}
	sock_fd = socket_get_fd(s->socket_ctx);
	if (sock_fd == -1) {
		TALLOC_FREE(s->socket_ctx);
		composite_error(c, NT_STATUS_INVALID_HANDLE);
		return;
	}
	socket_set_flags(s->socket_ctx, SOCKET_FLAG_NOCLOSE);
	TALLOC_FREE(s->socket_ctx);

	/*
	  fill in the transport methods
	*/
	conn->transport.transport       = s->transport;
	conn->transport.private_data    = NULL;

	/*
	 * Windows uses 5840 for ncacn_ip_tcp,
	 * so we also use it (for every transport which uses bsd sockets)
	 */
	conn->srv_max_xmit_frag = 5840;
	conn->srv_max_recv_frag = 5840;

	conn->transport.pending_reads = 0;
	conn->server_name   = strupper_talloc(conn, s->target_hostname);

	rc = tstream_bsd_existing_socket(conn, sock_fd,
					 &conn->transport.stream);
	if (rc < 0) {
		close(sock_fd);
		composite_error(c, NT_STATUS_NO_MEMORY);
		return;
	}

	conn->transport.write_queue =
		tevent_queue_create(conn, "dcerpc sock write queue");
	if (conn->transport.write_queue == NULL) {
		TALLOC_FREE(conn->transport.stream);
		composite_error(c, NT_STATUS_NO_MEMORY);
		return;
	}

	/* ensure we don't get SIGPIPE */
	BlockSignals(true, SIGPIPE);

	composite_done(c);
}


static struct composite_context *dcerpc_pipe_open_socket_send(TALLOC_CTX *mem_ctx,
						       struct dcecli_connection *cn,
						       struct socket_address *localaddr,
						       struct socket_address *server,
						       const char *target_hostname,
						       const char *full_path,
						       enum dcerpc_transport_t transport)
{
	struct composite_context *c;
	struct pipe_open_socket_state *s;
	struct composite_context *conn_req;

	c = composite_create(mem_ctx, cn->event_ctx);
	if (c == NULL) return NULL;

	s = talloc_zero(c, struct pipe_open_socket_state);
	if (composite_nomem(s, c)) return c;
	c->private_data = s;

	s->conn      = cn;
	s->transport = transport;
	if (localaddr) {
		s->localaddr = socket_address_copy(s, localaddr);
		if (composite_nomem(s->localaddr, c)) return c;
	}
	s->server = socket_address_copy(s, server);
	if (composite_nomem(s->server, c)) return c;
	if (target_hostname) {
		s->target_hostname = talloc_strdup(s, target_hostname);
		if (composite_nomem(s->target_hostname, c)) return c;
	}

	c->status = socket_create(s, server->family, SOCKET_TYPE_STREAM,
				  &s->socket_ctx, 0);
	if (!composite_is_ok(c)) return c;

	conn_req = socket_connect_send(s->socket_ctx, s->localaddr, s->server, 0,
				       c->event_ctx);
	composite_continue(c, conn_req, continue_socket_connect, c);
	return c;
}

static NTSTATUS dcerpc_pipe_open_socket_recv(struct composite_context *c,
					     TALLOC_CTX *mem_ctx,
					     struct socket_address **localaddr)
{
	NTSTATUS status = composite_wait(c);

	if (NT_STATUS_IS_OK(status)) {
		struct pipe_open_socket_state *s =
			talloc_get_type_abort(c->private_data,
			struct pipe_open_socket_state);

		if (localaddr != NULL) {
			*localaddr = talloc_move(mem_ctx, &s->client);
		}
	}

	talloc_free(c);
	return status;
}

struct pipe_tcp_state {
	const char *server;
	const char *target_hostname;
	const char **addresses;
	uint32_t index;
	uint32_t port;
	struct socket_address *localaddr;
	struct socket_address *srvaddr;
	struct resolve_context *resolve_ctx;
	struct dcecli_connection *conn;
	struct nbt_name name;
	char *local_address;
	char *remote_address;
};


static void continue_ip_open_socket(struct composite_context *ctx);
static void continue_ip_resolve_name(struct composite_context *ctx);

static void continue_ip_resolve_name(struct composite_context *ctx)
{
	struct composite_context *c = talloc_get_type_abort(
		ctx->async.private_data, struct composite_context);
	struct pipe_tcp_state *s = talloc_get_type_abort(
		c->private_data, struct pipe_tcp_state);
	struct composite_context *sock_ip_req;

	c->status = resolve_name_multiple_recv(ctx, s, &s->addresses);
	if (!composite_is_ok(c)) return;

	/* prepare server address using host ip:port and transport name */
	s->srvaddr = socket_address_from_strings(s->conn, "ip", s->addresses[s->index], s->port);
	s->index++;
	if (composite_nomem(s->srvaddr, c)) return;

	sock_ip_req = dcerpc_pipe_open_socket_send(c, s->conn, s->localaddr,
						     s->srvaddr, s->target_hostname,
						     NULL,
						     NCACN_IP_TCP);
	composite_continue(c, sock_ip_req, continue_ip_open_socket, c);
}


/*
  Stage 2 of dcerpc_pipe_open_tcp_send: receive result of pipe open request
  on IP transport.
*/
static void continue_ip_open_socket(struct composite_context *ctx)
{
	struct composite_context *c = talloc_get_type_abort(
		ctx->async.private_data, struct composite_context);
	struct pipe_tcp_state *s = talloc_get_type_abort(
		c->private_data, struct pipe_tcp_state);
	struct socket_address *localaddr = NULL;

	/* receive result socket open request */
	c->status = dcerpc_pipe_open_socket_recv(ctx, s, &localaddr);
	if (!NT_STATUS_IS_OK(c->status)) {
		/* something went wrong... */
		DEBUG(0, ("Failed to connect host %s (%s) on port %d - %s.\n",
			  s->addresses[s->index - 1], s->target_hostname,
			  s->port, nt_errstr(c->status)));
		if (s->addresses[s->index]) {
			struct composite_context *sock_ip_req;
			talloc_free(s->srvaddr);
			/* prepare server address using host ip:port and transport name */
			s->srvaddr = socket_address_from_strings(s->conn, "ip", s->addresses[s->index], s->port);
			s->index++;
			if (composite_nomem(s->srvaddr, c)) return;

			sock_ip_req = dcerpc_pipe_open_socket_send(c, s->conn, s->localaddr,
								s->srvaddr, s->target_hostname,
								NULL,
								NCACN_IP_TCP);
			composite_continue(c, sock_ip_req, continue_ip_open_socket, c);

			return;
		} else {
			composite_error(c, c->status);
			return;
		}
	}

	s->local_address = talloc_strdup(s, localaddr->addr);
	if (composite_nomem(s->local_address, c)) return;
	s->remote_address = talloc_strdup(s, s->addresses[s->index - 1]);
	if (composite_nomem(s->remote_address, c)) return;

	composite_done(c);
}

/*
  Send rpc pipe open request to given host:port using
  tcp/ip transport
*/
struct composite_context* dcerpc_pipe_open_tcp_send(struct dcecli_connection *conn,
						    const char *localaddr,
						    const char *server,
						    const char *target_hostname,
						    uint32_t port,
						    struct resolve_context *resolve_ctx)
{
	struct composite_context *c;
	struct pipe_tcp_state *s;
	struct composite_context *resolve_req;

	/* composite context allocation and setup */
	c = composite_create(conn, conn->event_ctx);
	if (c == NULL) return NULL;

	s = talloc_zero(c, struct pipe_tcp_state);
	if (composite_nomem(s, c)) return c;
	c->private_data = s;

	/* store input parameters in state structure */
	s->server          = talloc_strdup(c, server);
	if (composite_nomem(s->server, c)) return c;
	if (target_hostname) {
		s->target_hostname = talloc_strdup(c, target_hostname);
		if (composite_nomem(s->target_hostname, c)) return c;
	}
	s->port            = port;
	s->conn            = conn;
	s->resolve_ctx     = resolve_ctx;
	if (localaddr) {
		s->localaddr = socket_address_from_strings(s, "ip", localaddr, 0);
		/* if there is no localaddr, we pass NULL for
		   s->localaddr, which is handled by the socket libraries as
		   meaning no local binding address specified */
	}

	make_nbt_name_server(&s->name, s->server);
	resolve_req = resolve_name_send(resolve_ctx, s, &s->name, c->event_ctx);
	composite_continue(c, resolve_req, continue_ip_resolve_name, c);
	return c;
}

/*
  Receive result of pipe open request on tcp/ip
*/
NTSTATUS dcerpc_pipe_open_tcp_recv(struct composite_context *c,
				   TALLOC_CTX *mem_ctx,
				   char **localaddr,
				   char **remoteaddr)
{
	NTSTATUS status;
	status = composite_wait(c);

	if (NT_STATUS_IS_OK(status)) {
		struct pipe_tcp_state *s = talloc_get_type_abort(
			c->private_data, struct pipe_tcp_state);

		if (localaddr != NULL) {
			*localaddr = talloc_move(mem_ctx, &s->local_address);
		}
		if (remoteaddr != NULL) {
			*remoteaddr = talloc_move(mem_ctx, &s->remote_address);
		}
	}

	talloc_free(c);
	return status;
}


struct pipe_unix_state {
	const char *path;
	struct socket_address *srvaddr;
	struct dcecli_connection *conn;
};


/*
  Stage 2 of dcerpc_pipe_open_unix_stream_send: receive result of pipe open
  request on unix socket.
*/
static void continue_unix_open_socket(struct composite_context *ctx)
{
	struct composite_context *c = talloc_get_type_abort(
		ctx->async.private_data, struct composite_context);

	c->status = dcerpc_pipe_open_socket_recv(ctx, NULL, NULL);
	if (NT_STATUS_IS_OK(c->status)) {
		composite_done(c);
		return;
	}

	composite_error(c, c->status);
}


/*
  Send pipe open request on unix socket
*/
struct composite_context *dcerpc_pipe_open_unix_stream_send(struct dcecli_connection *conn,
							    const char *path)
{
	struct composite_context *c;
	struct composite_context *sock_unix_req;
	struct pipe_unix_state *s;

	/* composite context allocation and setup */
	c = composite_create(conn, conn->event_ctx);
	if (c == NULL) return NULL;

	s = talloc_zero(c, struct pipe_unix_state);
	if (composite_nomem(s, c)) return c;
	c->private_data = s;

	/* store parameters in state structure */
	s->path = talloc_strdup(c, path);
	if (composite_nomem(s->path, c)) return c;
	s->conn = conn;

	/* prepare server address using socket path and transport name */
	s->srvaddr = socket_address_from_strings(conn, "unix", s->path, 0);
	if (composite_nomem(s->srvaddr, c)) return c;

	/* send socket open request */
	sock_unix_req = dcerpc_pipe_open_socket_send(c, s->conn, NULL,
						     s->srvaddr, NULL,
						     s->path,
						     NCALRPC);
	composite_continue(c, sock_unix_req, continue_unix_open_socket, c);
	return c;
}


/*
  Receive result of pipe open request on unix socket
*/
NTSTATUS dcerpc_pipe_open_unix_stream_recv(struct composite_context *c)
{
	NTSTATUS status = composite_wait(c);

	talloc_free(c);
	return status;
}


/*
  Stage 2 of dcerpc_pipe_open_pipe_send: receive socket open request
*/
static void continue_np_open_socket(struct composite_context *ctx)
{
	struct composite_context *c = talloc_get_type_abort(
		ctx->async.private_data, struct composite_context);

	c->status = dcerpc_pipe_open_socket_recv(ctx, NULL, NULL);
	if (!composite_is_ok(c)) return;

	composite_done(c);
}


/*
  Send pipe open request on ncalrpc
*/
struct composite_context* dcerpc_pipe_open_pipe_send(struct dcecli_connection *conn,
						     const char *ncalrpc_dir,
						     const char *identifier)
{
	char *canon = NULL;

	struct composite_context *c;
	struct composite_context *sock_np_req;
	struct pipe_unix_state *s;

	/* composite context allocation and setup */
	c = composite_create(conn, conn->event_ctx);
	if (c == NULL) return NULL;

	s = talloc_zero(c, struct pipe_unix_state);
	if (composite_nomem(s, c)) return c;
	c->private_data = s;

	/* store parameters in state structure */
	canon = talloc_strdup(s, identifier);
	if (composite_nomem(canon, c)) return c;
	s->conn = conn;

	string_replace(canon, '/', '\\');
	s->path = talloc_asprintf(canon, "%s/%s", ncalrpc_dir, canon);
	if (composite_nomem(s->path, c)) return c;

	/* prepare server address using path and transport name */
	s->srvaddr = socket_address_from_strings(conn, "unix", s->path, 0);
	if (composite_nomem(s->srvaddr, c)) return c;

	/* send socket open request */
	sock_np_req = dcerpc_pipe_open_socket_send(c, s->conn, NULL, s->srvaddr, NULL, s->path, NCALRPC);
	composite_continue(c, sock_np_req, continue_np_open_socket, c);
	return c;
}


/*
  Receive result of pipe open request on ncalrpc
*/
NTSTATUS dcerpc_pipe_open_pipe_recv(struct composite_context *c)
{
	NTSTATUS status = composite_wait(c);
	
	talloc_free(c);
	return status;
}


/*
  Open a rpc pipe on a named pipe - sync version
*/
NTSTATUS dcerpc_pipe_open_pipe(struct dcecli_connection *conn, const char *ncalrpc_dir, const char *identifier)
{
	struct composite_context *c = dcerpc_pipe_open_pipe_send(conn, ncalrpc_dir, identifier);
	return dcerpc_pipe_open_pipe_recv(c);
}
