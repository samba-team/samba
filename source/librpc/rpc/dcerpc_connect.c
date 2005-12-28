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
#include "system/network.h"
#include "librpc/gen_ndr/ndr_epmapper.h"
#include "librpc/gen_ndr/ndr_dcerpc.h"
#include "librpc/gen_ndr/ndr_misc.h"
#include "libcli/raw/libcliraw.h"
#include "libcli/composite/composite.h"
#include "libcli/smb_composite/smb_composite.h"
#include "libcli/smb2/smb2.h"


struct dcerpc_pipe_connect;

struct pipe_np_smb_state {
	struct smb_composite_connect conn;
	struct smbcli_tree *tree;
	struct dcerpc_pipe_connect io;
};


/*
  Stage 3 of ncacn_np_smb: Named pipe opened (or not)
*/
void continue_pipe_open_smb(struct composite_context *ctx)
{
	struct composite_context *c = talloc_get_type(ctx->async.private_data,
						      struct composite_context);
	struct pipe_np_smb_state *s = talloc_get_type(c->private_data,
						      struct pipe_np_smb_state);

	/* receive result of named pipe open request on smb */
	c->status = dcerpc_pipe_open_smb_recv(ctx);
	if (!NT_STATUS_IS_OK(c->status)) {
		DEBUG(0,("Failed to open pipe %s - %s\n", s->io.pipe_name, nt_errstr(c->status)));
		composite_error(c, c->status);
		return;
	}

	composite_done(c);
}

/*
  Stage 2 of ncacn_np_smb: Open a named pipe after successful smb connection
*/
void continue_smb_connect(struct composite_context *ctx)
{
	struct composite_context *open_ctx;
	struct composite_context *c = talloc_get_type(ctx->async.private_data,
						      struct composite_context);
	struct pipe_np_smb_state *s = talloc_get_type(c->private_data,
						      struct pipe_np_smb_state);
	
	/* receive result of smb connect request */
	c->status = smb_composite_connect_recv(ctx, c);
	if (!NT_STATUS_IS_OK(c->status)) {
		DEBUG(0,("Failed to connect to %s - %s\n", s->io.binding->host, nt_errstr(c->status)));
		composite_error(c, c->status);
		return;
	}

	/* prepare named pipe open parameters */
	s->tree         = s->conn.out.tree;
	s->io.pipe_name = s->io.binding->endpoint;

	/* send named pipe open request */
	open_ctx = dcerpc_pipe_open_smb_send(s->io.pipe->conn, s->tree, s->io.pipe_name);
	if (open_ctx == NULL) {
		composite_error(c, NT_STATUS_NO_MEMORY);
		return;
	}

	composite_continue(c, open_ctx, continue_pipe_open_smb, c);
}


/*
  Initiate async open of a rpc connection to a rpc pipe on SMB using
  the binding structure to determine the endpoint and options
*/
struct composite_context *dcerpc_pipe_connect_ncacn_np_smb_send(TALLOC_CTX *tmp_ctx, 
								struct dcerpc_pipe_connect *io)
{
	struct composite_context *c;
	struct pipe_np_smb_state *s;
	struct composite_context *conn_req;
	struct smb_composite_connect *conn;

	/* composite context allocation and setup */
	c = talloc_zero(tmp_ctx, struct composite_context);
	if (c == NULL) return NULL;

	s = talloc_zero(c, struct pipe_np_smb_state);
	if (s == NULL) {
		composite_error(c, NT_STATUS_NO_MEMORY);
		goto done;
	}

	c->state = COMPOSITE_STATE_IN_PROGRESS;
	c->private_data = s;
	c->event_ctx = io->pipe->conn->event_ctx;

	s->io  = *io;
	conn   = &s->conn;

	/* prepare smb connection parameters: we're connecting to IPC$ share on
	   remote rpc server */
	conn->in.dest_host              = s->io.binding->host;
	conn->in.port                   = 0;
	conn->in.called_name            = strupper_talloc(tmp_ctx, s->io.binding->host);
	conn->in.service                = "IPC$";
	conn->in.service_type           = NULL;
	conn->in.fallback_to_anonymous  = False;
	conn->in.workgroup              = lp_workgroup();

	/*
	 * provide proper credentials - user supplied or anonymous in case this is
	 * schannel connection
	 */
	if (s->io.binding->flags & DCERPC_SCHANNEL) {
		struct cli_credentials *anon_creds;

		anon_creds = cli_credentials_init(tmp_ctx);
		if (!anon_creds) {
			composite_error(c, NT_STATUS_NO_MEMORY);
			goto done;
		}

		cli_credentials_set_anonymous(anon_creds);
		cli_credentials_guess(anon_creds);

		s->conn.in.credentials = anon_creds;

	} else {
		s->conn.in.credentials = s->io.creds;
	}

	/* send smb connect request */
	conn_req = smb_composite_connect_send(conn, s->io.pipe->conn, s->io.pipe->conn->event_ctx);
	if (!conn_req) {
		composite_error(c, NT_STATUS_NO_MEMORY);
		goto done;
	}

	composite_continue(c, conn_req, continue_smb_connect, c);

done:
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
NTSTATUS dcerpc_pipe_connect_ncacn_np_smb(TALLOC_CTX *tmp_ctx,
					  struct dcerpc_pipe_connect *io)
{
	struct composite_context *c;
	c = dcerpc_pipe_connect_ncacn_np_smb_send(tmp_ctx, io);
	return dcerpc_pipe_connect_ncacn_np_smb_recv(c);
}


struct pipe_np_smb2_state {
	struct smb2_tree *tree;
	struct dcerpc_pipe_connect io;
};


/*
  Stage 3 of ncacn_np_smb: Named pipe opened (or not)
*/
void continue_pipe_open_smb2(struct composite_context *ctx)
{
	struct composite_context *c = talloc_get_type(ctx->async.private_data,
						      struct composite_context);
	struct pipe_np_smb2_state *s = talloc_get_type(c->private_data,
						       struct pipe_np_smb2_state);

	/* receive result of named pipe open request on smb2 */
	c->status = dcerpc_pipe_open_smb2_recv(ctx);
	if (!NT_STATUS_IS_OK(c->status)) {
		DEBUG(0,("Failed to open pipe %s - %s\n", s->io.pipe_name, nt_errstr(c->status)));
		composite_error(c, c->status);
		return;
	}

	composite_done(c);
}


/*
  Stage 2 of ncacn_np_smb2: Open a named pipe after successful smb2 connection
*/
void continue_smb2_connect(struct composite_context *ctx)
{
	struct composite_context *open_req;
	struct composite_context *c = talloc_get_type(ctx->async.private_data,
						      struct composite_context);
	struct pipe_np_smb2_state *s = talloc_get_type(c->private_data,
						       struct pipe_np_smb2_state);

	/* receive result of smb2 connect request */
	c->status = smb2_connect_recv(ctx, c, &s->tree);
	if (!NT_STATUS_IS_OK(c->status)) {
		DEBUG(0,("Failed to connect to %s - %s\n", s->io.binding->host, nt_errstr(c->status)));
		composite_error(c, c->status);
		return;
	}

	/* prepare named pipe open parameters */
	s->io.pipe_name = s->io.binding->endpoint;

	/* send named pipe open request */
	open_req = dcerpc_pipe_open_smb2_send(s->io.pipe->conn, s->tree, s->io.pipe_name);
	if (open_req == NULL) {
		composite_error(c, NT_STATUS_NO_MEMORY);
		return;
	}

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
	c = talloc_zero(mem_ctx, struct composite_context);
	if (c == NULL) return NULL;

	s = talloc_zero(c, struct pipe_np_smb2_state);
	if (s == NULL) {
		composite_error(c, NT_STATUS_NO_MEMORY);
		goto done;
	}
	
	c->state = COMPOSITE_STATE_IN_PROGRESS;
	c->private_data = s;
	c->event_ctx = io->pipe->conn->event_ctx;

	s->io = *io;

	/*
	 * provide proper credentials - user supplied or anonymous in case this is
	 * schannel connection
	 */
	if (s->io.binding->flags & DCERPC_SCHANNEL) {
		s->io.creds = cli_credentials_init(mem_ctx);
		if (s->io.creds) {
			composite_error(c, NT_STATUS_NO_MEMORY);
			goto done;
		}

		cli_credentials_set_anonymous(s->io.creds);
		cli_credentials_guess(s->io.creds);
	}

	/* send smb2 connect request */
	conn_req = smb2_connect_send(mem_ctx, s->io.binding->host, "IPC$", s->io.creds,
				     c->event_ctx);
	if (conn_req == NULL) {
		composite_error(c, NT_STATUS_NO_MEMORY);
		goto done;
	}

	composite_continue(c, conn_req, continue_smb2_connect, c);

done:
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
