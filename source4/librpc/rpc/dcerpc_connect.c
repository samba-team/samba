/* 
   Unix SMB/CIFS implementation.

   dcerpc connect functions

   Copyright (C) Andrew Tridgell 2003
   Copyright (C) Jelmer Vernooij 2004
   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2005
   Copyright (C) Rafal Szczesniak  2005
   
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
#include "libcli/composite/composite.h"
#include "libcli/smb_composite/smb_composite.h"
#include "lib/events/events.h"
#include "libcli/smb2/smb2.h"
#include "libcli/smb2/smb2_calls.h"
#include "librpc/rpc/dcerpc.h"
#include "auth/credentials/credentials.h"


struct pipe_np_smb_state {
	struct smb_composite_connect conn;
	struct smbcli_tree *tree;
	struct dcerpc_pipe_connect io;
};


/*
  Stage 3 of ncacn_np_smb: Named pipe opened (or not)
*/
static void continue_pipe_open_smb(struct composite_context *ctx)
{
	struct composite_context *c = talloc_get_type(ctx->async.private_data,
						      struct composite_context);

	/* receive result of named pipe open request on smb */
	c->status = dcerpc_pipe_open_smb_recv(ctx);
	if (!composite_is_ok(c)) return;

	composite_done(c);
}


/*
  Stage 2 of ncacn_np_smb: Open a named pipe after successful smb connection
*/
static void continue_smb_connect(struct composite_context *ctx)
{
	struct composite_context *open_ctx;
	struct composite_context *c = talloc_get_type(ctx->async.private_data,
						      struct composite_context);
	struct pipe_np_smb_state *s = talloc_get_type(c->private_data,
						      struct pipe_np_smb_state);
	
	/* receive result of smb connect request */
	c->status = smb_composite_connect_recv(ctx, c);
	if (!composite_is_ok(c)) return;

	/* prepare named pipe open parameters */
	s->tree         = s->conn.out.tree;
	s->io.pipe_name = s->io.binding->endpoint;

	/* send named pipe open request */
	open_ctx = dcerpc_pipe_open_smb_send(s->io.pipe->conn, s->tree, s->io.pipe_name);
	if (composite_nomem(open_ctx, c)) return;

	composite_continue(c, open_ctx, continue_pipe_open_smb, c);
}


/*
  Initiate async open of a rpc connection to a rpc pipe on SMB using
  the binding structure to determine the endpoint and options
*/
struct composite_context *dcerpc_pipe_connect_ncacn_np_smb_send(TALLOC_CTX *mem_ctx, 
								struct dcerpc_pipe_connect *io)
{
	struct composite_context *c;
	struct pipe_np_smb_state *s;
	struct composite_context *conn_req;
	struct smb_composite_connect *conn;

	/* composite context allocation and setup */
	c = composite_create(mem_ctx, io->pipe->conn->event_ctx);
	if (c == NULL) return NULL;

	s = talloc_zero(c, struct pipe_np_smb_state);
	if (composite_nomem(s, c)) return c;
	c->private_data = s;

	s->io  = *io;
	conn   = &s->conn;

	/* prepare smb connection parameters: we're connecting to IPC$ share on
	   remote rpc server */
	conn->in.dest_host              = s->io.binding->host;
	conn->in.port                   = 0;
	conn->in.called_name            = s->io.binding->target_hostname;
	conn->in.service                = "IPC$";
	conn->in.service_type           = NULL;
	conn->in.workgroup              = lp_workgroup();

	/*
	 * provide proper credentials - user supplied, but allow a
	 * fallback to anonymous if this is an schannel connection
	 * (might be NT4 not allowing machine logins at session
	 * setup).
	 */
	s->conn.in.credentials = s->io.creds;
	if (s->io.binding->flags & DCERPC_SCHANNEL) {
		conn->in.fallback_to_anonymous  = True;
	} else {
		conn->in.fallback_to_anonymous  = False;
	}

	/* send smb connect request */
	conn_req = smb_composite_connect_send(conn, s->io.pipe->conn, s->io.pipe->conn->event_ctx);
	if (composite_nomem(conn_req, c)) return c;

	composite_continue(c, conn_req, continue_smb_connect, c);
	return c;
}


/*
  Receive result of a rpc connection to a rpc pipe on SMB
*/
NTSTATUS dcerpc_pipe_connect_ncacn_np_smb_recv(struct composite_context *c)
{
	NTSTATUS status = composite_wait(c);

	talloc_free(c);
	return status;
}


/*
  Sync version of a rpc connection to a rpc pipe on SMB
*/
NTSTATUS dcerpc_pipe_connect_ncacn_np_smb(TALLOC_CTX *mem_ctx,
					  struct dcerpc_pipe_connect *io)
{
	struct composite_context *c;
	c = dcerpc_pipe_connect_ncacn_np_smb_send(mem_ctx, io);
	return dcerpc_pipe_connect_ncacn_np_smb_recv(c);
}


struct pipe_np_smb2_state {
	struct smb2_tree *tree;
	struct dcerpc_pipe_connect io;
};


/*
  Stage 3 of ncacn_np_smb: Named pipe opened (or not)
*/
static void continue_pipe_open_smb2(struct composite_context *ctx)
{
	struct composite_context *c = talloc_get_type(ctx->async.private_data,
						      struct composite_context);

	/* receive result of named pipe open request on smb2 */
	c->status = dcerpc_pipe_open_smb2_recv(ctx);
	if (!composite_is_ok(c)) return;

	composite_done(c);
}


/*
  Stage 2 of ncacn_np_smb2: Open a named pipe after successful smb2 connection
*/
static void continue_smb2_connect(struct composite_context *ctx)
{
	struct composite_context *open_req;
	struct composite_context *c = talloc_get_type(ctx->async.private_data,
						      struct composite_context);
	struct pipe_np_smb2_state *s = talloc_get_type(c->private_data,
						       struct pipe_np_smb2_state);

	/* receive result of smb2 connect request */
	c->status = smb2_connect_recv(ctx, c, &s->tree);
	if (!composite_is_ok(c)) return;

	/* prepare named pipe open parameters */
	s->io.pipe_name = s->io.binding->endpoint;

	/* send named pipe open request */
	open_req = dcerpc_pipe_open_smb2_send(s->io.pipe->conn, s->tree, s->io.pipe_name);
	if (composite_nomem(open_req, c)) return;

	composite_continue(c, open_req, continue_pipe_open_smb2, c);
}


/* 
   Initiate async open of a rpc connection request on SMB2 using
   the binding structure to determine the endpoint and options
*/
struct composite_context *dcerpc_pipe_connect_ncacn_np_smb2_send(TALLOC_CTX *mem_ctx,
								 struct dcerpc_pipe_connect *io)
{
	struct composite_context *c;
	struct pipe_np_smb2_state *s;
	struct composite_context *conn_req;

	/* composite context allocation and setup */
	c = composite_create(mem_ctx, io->pipe->conn->event_ctx);
	if (c == NULL) return NULL;

	s = talloc_zero(c, struct pipe_np_smb2_state);
	if (composite_nomem(s, c)) return c;
	c->private_data = s;

	s->io = *io;

	/*
	 * provide proper credentials - user supplied or anonymous in case this is
	 * schannel connection
	 */
	if (s->io.binding->flags & DCERPC_SCHANNEL) {
		s->io.creds = cli_credentials_init(mem_ctx);
		if (composite_nomem(s->io.creds, c)) return c;

		cli_credentials_set_anonymous(s->io.creds);
		cli_credentials_guess(s->io.creds);
	}

	/* send smb2 connect request */
	conn_req = smb2_connect_send(mem_ctx, s->io.binding->host, "IPC$", s->io.creds,
				     c->event_ctx);
	composite_continue(c, conn_req, continue_smb2_connect, c);
	return c;
}


/*
  Receive result of a rpc connection to a rpc pipe on SMB2
*/
NTSTATUS dcerpc_pipe_connect_ncacn_np_smb2_recv(struct composite_context *c)
{
	NTSTATUS status = composite_wait(c);
	
	talloc_free(c);
	return status;
}


/*
  Sync version of a rpc connection to a rpc pipe on SMB2
*/
NTSTATUS dcerpc_pipe_connect_ncacn_np_smb2(TALLOC_CTX *mem_ctx,
					   struct dcerpc_pipe_connect *io)
{
	struct composite_context *c;
	c = dcerpc_pipe_connect_ncacn_np_smb2_send(mem_ctx, io);
	return dcerpc_pipe_connect_ncacn_np_smb2_recv(c);
}


struct pipe_ip_tcp_state {
	struct dcerpc_pipe_connect io;
	const char *host;
	const char *target_hostname;
	uint32_t port;
};


/*
  Stage 2 of ncacn_ip_tcp: rpc pipe opened (or not)
*/
static void continue_pipe_open_ncacn_ip_tcp(struct composite_context *ctx)
{
	struct composite_context *c = talloc_get_type(ctx->async.private_data,
						      struct composite_context);

	/* receive result of named pipe open request on tcp/ip */
	c->status = dcerpc_pipe_open_tcp_recv(ctx);
	if (!composite_is_ok(c)) return;

	composite_done(c);
}


/*
  Initiate async open of a rpc connection to a rpc pipe on TCP/IP using
  the binding structure to determine the endpoint and options
*/
struct composite_context* dcerpc_pipe_connect_ncacn_ip_tcp_send(TALLOC_CTX *mem_ctx,
								struct dcerpc_pipe_connect *io)
{
	struct composite_context *c;
	struct pipe_ip_tcp_state *s;
	struct composite_context *pipe_req;

	/* composite context allocation and setup */
	c = composite_create(mem_ctx, io->pipe->conn->event_ctx);
	if (c == NULL) return NULL;

	s = talloc_zero(c, struct pipe_ip_tcp_state);
	if (composite_nomem(s, c)) return c;
	c->private_data = s;

	/* store input parameters in state structure */
	s->io               = *io;
	s->host             = talloc_reference(c, io->binding->host);
	s->target_hostname  = talloc_reference(c, io->binding->target_hostname);
                             /* port number is a binding endpoint here */
	s->port             = atoi(io->binding->endpoint);   

	/* send pipe open request on tcp/ip */
	pipe_req = dcerpc_pipe_open_tcp_send(s->io.pipe->conn, s->host, s->target_hostname, 
					     s->port);
	composite_continue(c, pipe_req, continue_pipe_open_ncacn_ip_tcp, c);
	return c;
}


/*
  Receive result of a rpc connection to a rpc pipe on TCP/IP
*/
NTSTATUS dcerpc_pipe_connect_ncacn_ip_tcp_recv(struct composite_context *c)
{
	NTSTATUS status = composite_wait(c);
	
	talloc_free(c);
	return status;
}


/*
  Sync version of rpc connection to a rpc pipe on TCP/IP
*/
NTSTATUS dcerpc_pipe_connect_ncacn_ip_tcp(TALLOC_CTX *mem_ctx,
					  struct dcerpc_pipe_connect *io)
{
	struct composite_context *c;
	c = dcerpc_pipe_connect_ncacn_ip_tcp_send(mem_ctx, io);
	return dcerpc_pipe_connect_ncacn_ip_tcp_recv(c);
}


struct pipe_unix_state {
	struct dcerpc_pipe_connect io;
	const char *path;
};


/*
  Stage 2 of ncacn_unix: rpc pipe opened (or not)
*/
static void continue_pipe_open_ncacn_unix_stream(struct composite_context *ctx)
{
	struct composite_context *c = talloc_get_type(ctx->async.private_data,
						      struct composite_context);

	/* receive result of pipe open request on unix socket */
	c->status = dcerpc_pipe_open_unix_stream_recv(ctx);
	if (!composite_is_ok(c)) return;

	composite_done(c);
}


/*
  Initiate async open of a rpc connection to a rpc pipe on unix socket using
  the binding structure to determine the endpoint and options
*/
struct composite_context* dcerpc_pipe_connect_ncacn_unix_stream_send(TALLOC_CTX *mem_ctx,
								     struct dcerpc_pipe_connect *io)
{
	struct composite_context *c;
	struct pipe_unix_state *s;
	struct composite_context *pipe_req;

	/* composite context allocation and setup */
	c = composite_create(mem_ctx, io->pipe->conn->event_ctx);
	if (c == NULL) return NULL;

	s = talloc_zero(c, struct pipe_unix_state);
	if (composite_nomem(s, c)) return c;
	c->private_data = s;

	/* prepare pipe open parameters and store them in state structure
	   also, verify whether biding endpoint is not null */
	s->io = *io;
	
	if (!io->binding->endpoint) {
		DEBUG(0, ("Path to unix socket not specified\n"));
		composite_error(c, NT_STATUS_INVALID_PARAMETER);
		return c;
	}

	s->path  = talloc_strdup(c, io->binding->endpoint);  /* path is a binding endpoint here */
	if (composite_nomem(s->path, c)) return c;

	/* send pipe open request on unix socket */
	pipe_req = dcerpc_pipe_open_unix_stream_send(s->io.pipe->conn, s->path);
	composite_continue(c, pipe_req, continue_pipe_open_ncacn_unix_stream, c);
	return c;
}


/*
  Receive result of a rpc connection to a pipe on unix socket
*/
NTSTATUS dcerpc_pipe_connect_ncacn_unix_stream_recv(struct composite_context *c)
{
	NTSTATUS status = composite_wait(c);

	talloc_free(c);
	return status;
}


/*
  Sync version of a rpc connection to a rpc pipe on unix socket
*/
NTSTATUS dcerpc_pipe_connect_ncacn_unix_stream(TALLOC_CTX *mem_ctx,
					       struct dcerpc_pipe_connect *io)
{
	struct composite_context *c;
	c = dcerpc_pipe_connect_ncacn_unix_stream_send(mem_ctx, io);
	return dcerpc_pipe_connect_ncacn_unix_stream_recv(c);	
}


struct pipe_ncalrpc_state {
	struct dcerpc_pipe_connect io;
};


/*
  Stage 2 of ncalrpc: rpc pipe opened (or not)
*/
static void continue_pipe_open_ncalrpc(struct composite_context *ctx)
{
	struct composite_context *c = talloc_get_type(ctx->async.private_data,
						      struct composite_context);

	/* receive result of pipe open request on ncalrpc */
	c->status = dcerpc_pipe_connect_ncalrpc_recv(ctx);
	if (!composite_is_ok(c)) return;

	composite_done(c);
}


/* 
   Initiate async open of a rpc connection request on NCALRPC using
   the binding structure to determine the endpoint and options
*/
struct composite_context* dcerpc_pipe_connect_ncalrpc_send(TALLOC_CTX *mem_ctx,
							   struct dcerpc_pipe_connect *io)
{
	struct composite_context *c;
	struct pipe_ncalrpc_state *s;
	struct composite_context *pipe_req;

	/* composite context allocation and setup */
	c = composite_create(mem_ctx, io->pipe->conn->event_ctx);
	if (c == NULL) return NULL;

	s = talloc_zero(c, struct pipe_ncalrpc_state);
	if (composite_nomem(s, c)) return c;
	c->private_data = s;
	
	/* store input parameters in state structure */
	s->io  = *io;

	/* send pipe open request */
	pipe_req = dcerpc_pipe_open_pipe_send(s->io.pipe->conn, s->io.binding->endpoint);
	composite_continue(c, pipe_req, continue_pipe_open_ncalrpc, c);
	return c;
}


/*
  Receive result of a rpc connection to a rpc pipe on NCALRPC
*/
NTSTATUS dcerpc_pipe_connect_ncalrpc_recv(struct composite_context *c)
{
	NTSTATUS status = composite_wait(c);
	
	talloc_free(c);
	return status;
}


/*
  Sync version of a rpc connection to a rpc pipe on NCALRPC
*/
NTSTATUS dcerpc_pipe_connect_ncalrpc(TALLOC_CTX *mem_ctx,
				     struct dcerpc_pipe_connect *io)
{
	struct composite_context *c = dcerpc_pipe_connect_ncalrpc_send(mem_ctx, io);
	return dcerpc_pipe_connect_ncalrpc_recv(c);
}


struct pipe_connect_state {
	struct dcerpc_pipe *pipe;
	struct dcerpc_binding *binding;
	const struct dcerpc_interface_table *table;
	struct cli_credentials *credentials;
};


static void continue_map_binding(struct composite_context *ctx);
static void continue_connect(struct composite_context *c, struct pipe_connect_state *s);
static void continue_pipe_connect_ncacn_np_smb2(struct composite_context *ctx);
static void continue_pipe_connect_ncacn_np_smb(struct composite_context *ctx);
static void continue_pipe_connect_ncacn_ip_tcp(struct composite_context *ctx);
static void continue_pipe_connect_ncacn_unix(struct composite_context *ctx);
static void continue_pipe_connect_ncalrpc(struct composite_context *ctx);
static void continue_pipe_connect(struct composite_context *c, struct pipe_connect_state *s);
static void continue_pipe_auth(struct composite_context *ctx);


/*
  Stage 2 of pipe_connect_b: Receive result of endpoint mapping
*/
static void continue_map_binding(struct composite_context *ctx)
{
	struct composite_context *c = talloc_get_type(ctx->async.private_data,
						      struct composite_context);
	struct pipe_connect_state *s = talloc_get_type(c->private_data,
						       struct pipe_connect_state);
	
	c->status = dcerpc_epm_map_binding_recv(ctx);
	if (!composite_is_ok(c)) return;

	DEBUG(2,("Mapped to DCERPC endpoint %s\n", s->binding->endpoint));
	
	continue_connect(c, s);
}


/*
  Stage 2 of pipe_connect_b: Continue connection after endpoint is known
*/
static void continue_connect(struct composite_context *c, struct pipe_connect_state *s)
{
	struct dcerpc_pipe_connect pc;

	/* potential exits to another stage by sending an async request */
	struct composite_context *ncacn_np_smb2_req;
	struct composite_context *ncacn_np_smb_req;
	struct composite_context *ncacn_ip_tcp_req;
	struct composite_context *ncacn_unix_req;
	struct composite_context *ncalrpc_req;

	/* dcerpc pipe connect input parameters */
	pc.pipe         = s->pipe;
	pc.binding      = s->binding;
	pc.interface    = s->table;
	pc.creds        = s->credentials;
	
	/* connect dcerpc pipe depending on required transport */
	switch (s->binding->transport) {
	case NCACN_NP:
		if (pc.binding->flags & DCERPC_SMB2) {
			/* new varient of SMB a.k.a. SMB2 */
			ncacn_np_smb2_req = dcerpc_pipe_connect_ncacn_np_smb2_send(c, &pc);
			composite_continue(c, ncacn_np_smb2_req, continue_pipe_connect_ncacn_np_smb2, c);
			return;

		} else {
			/* good old ordinary SMB */
			ncacn_np_smb_req = dcerpc_pipe_connect_ncacn_np_smb_send(c, &pc);
			composite_continue(c, ncacn_np_smb_req, continue_pipe_connect_ncacn_np_smb, c);
			return;
		}
		break;

	case NCACN_IP_TCP:
		ncacn_ip_tcp_req = dcerpc_pipe_connect_ncacn_ip_tcp_send(c, &pc);
		composite_continue(c, ncacn_ip_tcp_req, continue_pipe_connect_ncacn_ip_tcp, c);
		return;

	case NCACN_UNIX_STREAM:
		ncacn_unix_req = dcerpc_pipe_connect_ncacn_unix_stream_send(c, &pc);
		composite_continue(c, ncacn_unix_req, continue_pipe_connect_ncacn_unix, c);
		return;

	case NCALRPC:
		ncalrpc_req = dcerpc_pipe_connect_ncalrpc_send(c, &pc);
		composite_continue(c, ncalrpc_req, continue_pipe_connect_ncalrpc, c);
		return;

	default:
		/* looks like a transport we don't support now */
		composite_error(c, NT_STATUS_NOT_SUPPORTED);
	}
}


/*
  Stage 3 of pipe_connect_b: Receive result of pipe connect request on
  named pipe on smb2
*/
static void continue_pipe_connect_ncacn_np_smb2(struct composite_context *ctx)
{
	struct composite_context *c = talloc_get_type(ctx->async.private_data,
						      struct composite_context);
	struct pipe_connect_state *s = talloc_get_type(c->private_data,
						       struct pipe_connect_state);

	c->status = dcerpc_pipe_connect_ncacn_np_smb2_recv(ctx);
	if (!composite_is_ok(c)) return;

	continue_pipe_connect(c, s);
}


/*
  Stage 3 of pipe_connect_b: Receive result of pipe connect request on
  named pipe on smb
*/
static void continue_pipe_connect_ncacn_np_smb(struct composite_context *ctx)
{
	struct composite_context *c = talloc_get_type(ctx->async.private_data,
						      struct composite_context);
	struct pipe_connect_state *s = talloc_get_type(c->private_data,
						       struct pipe_connect_state);

	c->status = dcerpc_pipe_connect_ncacn_np_smb_recv(ctx);
	if (!composite_is_ok(c)) return;
	
	continue_pipe_connect(c, s);
}


/*
  Stage 3 of pipe_connect_b: Receive result of pipe connect request on tcp/ip
*/
static void continue_pipe_connect_ncacn_ip_tcp(struct composite_context *ctx)
{
	struct composite_context *c = talloc_get_type(ctx->async.private_data,
						      struct composite_context);
	struct pipe_connect_state *s = talloc_get_type(c->private_data,
						       struct pipe_connect_state);

	c->status = dcerpc_pipe_connect_ncacn_ip_tcp_recv(ctx);
	if (!composite_is_ok(c)) return;

	continue_pipe_connect(c, s);
}


/*
  Stage 3 of pipe_connect_b: Receive result of pipe connect request on unix socket
*/
static void continue_pipe_connect_ncacn_unix(struct composite_context *ctx)
{
	struct composite_context *c = talloc_get_type(ctx->async.private_data,
						      struct composite_context);
	struct pipe_connect_state *s = talloc_get_type(c->private_data,
						       struct pipe_connect_state);
	
	c->status = dcerpc_pipe_connect_ncacn_unix_stream_recv(ctx);
	if (!composite_is_ok(c)) return;
	
	continue_pipe_connect(c, s);
}


/*
  Stage 3 of pipe_connect_b: Receive result of pipe connect request on local rpc
*/
static void continue_pipe_connect_ncalrpc(struct composite_context *ctx)
{
	struct composite_context *c = talloc_get_type(ctx->async.private_data,
						      struct composite_context);
	struct pipe_connect_state *s = talloc_get_type(c->private_data,
						       struct pipe_connect_state);
	
	c->status = dcerpc_pipe_connect_ncalrpc_recv(ctx);
	if (!composite_is_ok(c)) return;

	continue_pipe_connect(c, s);
}


/*
  Stage 4 of pipe_connect_b: Start an authentication on connected dcerpc pipe
  depending on credentials and binding flags passed.
*/
static void continue_pipe_connect(struct composite_context *c, struct pipe_connect_state *s)
{
	struct composite_context *auth_bind_req;

	s->pipe->binding = s->binding;
	if (!talloc_reference(s->pipe, s->binding)) {
		composite_error(c, NT_STATUS_NO_MEMORY);
		return;
	}

	auth_bind_req = dcerpc_pipe_auth_send(s->pipe, s->binding, s->table,
					      s->credentials);
	composite_continue(c, auth_bind_req, continue_pipe_auth, c);
}


/*
  Stage 5 of pipe_connect_b: Receive result of pipe authentication request
  and say if all went ok
*/
static void continue_pipe_auth(struct composite_context *ctx)
{
	struct composite_context *c = talloc_get_type(ctx->async.private_data,
						      struct composite_context);
	struct pipe_connect_state *s = talloc_get_type(c->private_data, struct pipe_connect_state);

	c->status = dcerpc_pipe_auth_recv(ctx, s, &s->pipe);
	if (!composite_is_ok(c)) return;

	composite_done(c);
}


/*
  handle timeouts of a dcerpc connect
*/
static void dcerpc_connect_timeout_handler(struct event_context *ev, struct timed_event *te, 
					   struct timeval t, void *private)
{
	struct composite_context *c = talloc_get_type(private, struct composite_context);
	composite_error(c, NT_STATUS_IO_TIMEOUT);
}

/*
  start a request to open a rpc connection to a rpc pipe, using
  specified binding structure to determine the endpoint and options
*/
struct composite_context* dcerpc_pipe_connect_b_send(TALLOC_CTX *parent_ctx,
						     struct dcerpc_binding *binding,
						     const struct dcerpc_interface_table *table,
						     struct cli_credentials *credentials,
						     struct event_context *ev)
{
	struct composite_context *c;
	struct pipe_connect_state *s;
	struct event_context *new_ev = NULL;

	if (ev == NULL) {
		new_ev = event_context_init(parent_ctx);
		if (new_ev == NULL) return NULL;
		ev = new_ev;
	}

	/* composite context allocation and setup */
	c = composite_create(parent_ctx, ev);
	if (c == NULL) {
		talloc_free(new_ev);
		return NULL;
	}
	talloc_steal(c, new_ev);

	s = talloc_zero(c, struct pipe_connect_state);
	if (composite_nomem(s, c)) return c;
	c->private_data = s;

	/* initialise dcerpc pipe structure */
	s->pipe = dcerpc_pipe_init(c, ev);
	if (composite_nomem(s->pipe, c)) return c;

	/* store parameters in state structure */
	s->binding      = binding;
	s->table        = table;
	s->credentials  = credentials;

	event_add_timed(c->event_ctx, c,
			timeval_current_ofs(DCERPC_REQUEST_TIMEOUT, 0),
			dcerpc_connect_timeout_handler, c);
	
	switch (s->binding->transport) {
	case NCACN_NP:
	case NCACN_IP_TCP:
	case NCALRPC:
		if (!s->binding->endpoint) {
			struct composite_context *binding_req;
			binding_req = dcerpc_epm_map_binding_send(c, s->binding, s->table,
								  s->pipe->conn->event_ctx);
			composite_continue(c, binding_req, continue_map_binding, c);
			return c;
		}

	default:
		break;
	}

	continue_connect(c, s);
	return c;
}


/*
  receive result of a request to open a rpc connection to a rpc pipe
*/
NTSTATUS dcerpc_pipe_connect_b_recv(struct composite_context *c, TALLOC_CTX *mem_ctx,
				    struct dcerpc_pipe **p)
{
	NTSTATUS status;
	struct pipe_connect_state *s;
	
	status = composite_wait(c);
	
	if (NT_STATUS_IS_OK(status)) {
		s = talloc_get_type(c->private_data, struct pipe_connect_state);
		talloc_steal(mem_ctx, s->pipe);
		*p = s->pipe;
	}
	talloc_free(c);
	return status;
}


/*
  open a rpc connection to a rpc pipe, using the specified 
  binding structure to determine the endpoint and options - sync version
*/
NTSTATUS dcerpc_pipe_connect_b(TALLOC_CTX *parent_ctx,
			       struct dcerpc_pipe **pp,
			       struct dcerpc_binding *binding,
			       const struct dcerpc_interface_table *table,
			       struct cli_credentials *credentials,
			       struct event_context *ev)
{
	struct composite_context *c;
	
	c = dcerpc_pipe_connect_b_send(parent_ctx, binding, table,
				       credentials, ev);
	return dcerpc_pipe_connect_b_recv(c, parent_ctx, pp);
}


struct pipe_conn_state {
	struct dcerpc_pipe *pipe;
};


static void continue_pipe_connect_b(struct composite_context *ctx);


/*
  Initiate rpc connection to a rpc pipe, using the specified string
  binding to determine the endpoint and options.
  The string is to be parsed to a binding structure first.
*/
struct composite_context* dcerpc_pipe_connect_send(TALLOC_CTX *parent_ctx,
						   const char *binding,
						   const struct dcerpc_interface_table *table,
						   struct cli_credentials *credentials,
						   struct event_context *ev)
{
	struct composite_context *c;
	struct pipe_conn_state *s;
	struct dcerpc_binding *b;
	struct composite_context *pipe_conn_req;
	struct event_context *new_ev = NULL;

	if (ev == NULL) {
		new_ev = event_context_init(parent_ctx);
		if (new_ev == NULL) return NULL;
		ev = new_ev;
	}

	/* composite context allocation and setup */
	c = composite_create(parent_ctx, ev);
	if (c == NULL) {
		talloc_free(new_ev);
		return NULL;
	}
	talloc_steal(c, new_ev);

	s = talloc_zero(c, struct pipe_conn_state);
	if (composite_nomem(s, c)) return c;
	c->private_data = s;

	/* parse binding string to the structure */
	c->status = dcerpc_parse_binding(c, binding, &b);
	if (!NT_STATUS_IS_OK(c->status)) {
		DEBUG(0, ("Failed to parse dcerpc binding '%s'\n", binding));
		composite_error(c, c->status);
		return c;
	}

	DEBUG(3, ("Using binding %s\n", dcerpc_binding_string(c, b)));

	/* 
	   start connecting to a rpc pipe after binding structure
	   is established
	 */
	pipe_conn_req = dcerpc_pipe_connect_b_send(c, b, table,
						   credentials, ev);
	composite_continue(c, pipe_conn_req, continue_pipe_connect_b, c);
	return c;
}


/*
  Stage 2 of pipe_connect: Receive result of actual pipe connect request
  and say if we're done ok
*/
static void continue_pipe_connect_b(struct composite_context *ctx)
{
	struct composite_context *c = talloc_get_type(ctx->async.private_data,
						      struct composite_context);
	struct pipe_conn_state *s = talloc_get_type(c->private_data,
						    struct pipe_conn_state);

	c->status = dcerpc_pipe_connect_b_recv(ctx, c, &s->pipe);
	talloc_steal(s, s->pipe);
	if (!composite_is_ok(c)) return;

	composite_done(c);
}


/*
  Receive result of pipe connect (using binding string) request
  and return connected pipe structure.
*/
NTSTATUS dcerpc_pipe_connect_recv(struct composite_context *c,
				  TALLOC_CTX *mem_ctx,
				  struct dcerpc_pipe **pp)
{
	NTSTATUS status;
	struct pipe_conn_state *s;

	status = composite_wait(c);
	s = talloc_get_type(c->private_data, struct pipe_conn_state);
	*pp = talloc_steal(mem_ctx, s->pipe);

	talloc_free(c);
	return status;
}


/*
  Open a rpc connection to a rpc pipe, using the specified string
  binding to determine the endpoint and options - sync version
*/
NTSTATUS dcerpc_pipe_connect(TALLOC_CTX *parent_ctx, 
			     struct dcerpc_pipe **pp, 
			     const char *binding,
			     const struct dcerpc_interface_table *table,
			     struct cli_credentials *credentials,
			     struct event_context *ev)
{
	struct composite_context *c;
	c = dcerpc_pipe_connect_send(parent_ctx, binding, 
				     table,
				     credentials, ev);
	return dcerpc_pipe_connect_recv(c, parent_ctx, pp);
}


struct sec_conn_state {
	struct dcerpc_pipe *pipe;
	struct dcerpc_pipe *pipe2;
	struct dcerpc_binding *binding;
	struct smbcli_tree *tree;
};


static void continue_open_smb(struct composite_context *ctx);
static void continue_open_tcp(struct composite_context *ctx);
static void continue_open_pipe(struct composite_context *ctx);
static void continue_pipe_open(struct composite_context *c);


/*
  Send request to create a secondary dcerpc connection from a primary
  connection
*/
struct composite_context* dcerpc_secondary_connection_send(struct dcerpc_pipe *p,
							   struct dcerpc_binding *b)
{
	struct composite_context *c;
	struct sec_conn_state *s;
	struct composite_context *pipe_smb_req;
	struct composite_context *pipe_tcp_req;
	struct composite_context *pipe_ncalrpc_req;
	
	/* composite context allocation and setup */
	c = composite_create(p, p->conn->event_ctx);
	if (c == NULL) return NULL;

	s = talloc_zero(c, struct sec_conn_state);
	if (composite_nomem(s, c)) return c;
	c->private_data = s;

	s->pipe     = p;
	s->binding  = b;

	/* initialise second dcerpc pipe based on primary pipe's event context */
	s->pipe2 = dcerpc_pipe_init(c, s->pipe->conn->event_ctx);
	if (composite_nomem(s->pipe2, c)) return c;

	/* open second dcerpc pipe using the same transport as for primary pipe */
	switch (s->pipe->conn->transport.transport) {
	case NCACN_NP:
		/* get smb tree of primary dcerpc pipe opened on smb */
		s->tree = dcerpc_smb_tree(s->pipe->conn);
		if (!s->tree) {
			composite_error(c, NT_STATUS_INVALID_PARAMETER);
			return c;
		}

		pipe_smb_req = dcerpc_pipe_open_smb_send(s->pipe2->conn, s->tree,
							 s->binding->endpoint);
		composite_continue(c, pipe_smb_req, continue_open_smb, c);
		return c;

	case NCACN_IP_TCP:
		pipe_tcp_req = dcerpc_pipe_open_tcp_send(s->pipe2->conn,
							 s->binding->host,
							 s->binding->target_hostname,
							 atoi(s->binding->endpoint));
		composite_continue(c, pipe_tcp_req, continue_open_tcp, c);
		return c;

	case NCALRPC:
		pipe_ncalrpc_req = dcerpc_pipe_open_pipe_send(s->pipe2->conn,
							      s->binding->endpoint);
		composite_continue(c, pipe_ncalrpc_req, continue_open_pipe, c);
		return c;

	default:
		/* looks like a transport we don't support */
		composite_error(c, NT_STATUS_NOT_SUPPORTED);
	}

	return c;
}


/*
  Stage 2 of secondary_connection: Receive result of pipe open request on smb
*/
static void continue_open_smb(struct composite_context *ctx)
{
	struct composite_context *c = talloc_get_type(ctx->async.private_data,
						      struct composite_context);
	
	c->status = dcerpc_pipe_open_smb_recv(ctx);
	if (!composite_is_ok(c)) return;

	continue_pipe_open(c);
}


/*
  Stage 2 of secondary_connection: Receive result of pipe open request on tcp/ip
*/
static void continue_open_tcp(struct composite_context *ctx)
{
	struct composite_context *c = talloc_get_type(ctx->async.private_data,
						      struct composite_context);
	
	c->status = dcerpc_pipe_open_tcp_recv(ctx);
	if (!composite_is_ok(c)) return;

	continue_pipe_open(c);
}


/*
  Stage 2 of secondary_connection: Receive result of pipe open request on ncalrpc
*/
static void continue_open_pipe(struct composite_context *ctx)
{
	struct composite_context *c = talloc_get_type(ctx->async.private_data,
						      struct composite_context);

	c->status = dcerpc_pipe_open_pipe_recv(ctx);
	if (!composite_is_ok(c)) return;

	continue_pipe_open(c);
}


/*
  Stage 3 of secondary_connection: Get binding data and flags from primary pipe
  and say if we're done ok.
*/
static void continue_pipe_open(struct composite_context *c)
{
	struct sec_conn_state *s;

	s = talloc_get_type(c->private_data, struct sec_conn_state);

	s->pipe2->conn->flags = s->pipe->conn->flags;
	s->pipe2->binding     = s->binding;
	if (!talloc_reference(s->pipe2, s->binding)) {
		composite_error(c, NT_STATUS_NO_MEMORY);
		return;
	}

	composite_done(c);
}


/*
  Receive result of secondary rpc connection request and return
  second dcerpc pipe.
*/
NTSTATUS dcerpc_secondary_connection_recv(struct composite_context *c,
					  struct dcerpc_pipe **p2)
{
	NTSTATUS status = composite_wait(c);
	struct sec_conn_state *s;

	s = talloc_get_type(c->private_data, struct sec_conn_state);

	if (NT_STATUS_IS_OK(status)) {
		*p2 = talloc_steal(s->pipe, s->pipe2);
	}

	talloc_free(c);
	return status;
}

/*
  Create a secondary dcerpc connection from a primary connection
  - sync version

  If the primary is a SMB connection then the secondary connection
  will be on the same SMB connection, but using a new fnum
*/
NTSTATUS dcerpc_secondary_connection(struct dcerpc_pipe *p,
				     struct dcerpc_pipe **p2,
				     struct dcerpc_binding *b)
{
	struct composite_context *c;
	
	c = dcerpc_secondary_connection_send(p, b);
	return dcerpc_secondary_connection_recv(c, p2);
}
