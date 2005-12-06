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


struct dcerpc_pipe_connect;

struct pipe_np_smb_state {
	struct smb_composite_connect conn;
	struct smbcli_tree *tree;
	struct dcerpc_pipe_connect io;
};


void continue_pipe_open_smb(struct composite_context *ctx)
{
	struct composite_context *c = talloc_get_type(ctx->async.private_data,
						      struct composite_context);
	struct pipe_np_smb_state *s = talloc_get_type(c->private_data,
						      struct pipe_np_smb_state);

	c->status = dcerpc_pipe_open_smb_recv(ctx);
	if (!NT_STATUS_IS_OK(c->status)) {

		DEBUG(0,("Failed to open pipe %s - %s\n", s->io.pipe_name, nt_errstr(c->status)));
		composite_trigger_error(c);
		return;
	}

	composite_done(c);
}


void continue_smb_connect(struct composite_context *ctx)
{
	struct composite_context *open_ctx;
	struct composite_context *c = talloc_get_type(ctx->async.private_data,
						      struct composite_context);
	struct pipe_np_smb_state *s = talloc_get_type(c->private_data,
						      struct pipe_np_smb_state);
	
	c->status = smb_composite_connect_recv(ctx, c);
	if (!NT_STATUS_IS_OK(c->status)) {

		DEBUG(0,("Failed to connect to %s - %s\n", s->io.binding->host, nt_errstr(c->status)));
		composite_trigger_error(c);
		return;
	}

	s->tree         = s->conn.out.tree;
	s->io.pipe_name = s->io.binding->endpoint;

	open_ctx = dcerpc_pipe_open_smb_send(s->io.pipe->conn, s->tree, s->io.pipe_name);

	composite_continue(c, open_ctx, continue_pipe_open_smb, c);
}


/* open a rpc connection to a rpc pipe on SMB using the binding
   structure to determine the endpoint and options */
struct composite_context *dcerpc_pipe_connect_ncacn_np_smb_send(TALLOC_CTX *tmp_ctx, 
								struct dcerpc_pipe_connect *io)
{
	struct composite_context *c;
	struct pipe_np_smb_state *s;
	struct composite_context *conn_req;
	struct smb_composite_connect *conn;

	c = talloc_zero(tmp_ctx, struct composite_context);
	if (c == NULL) return NULL;

	s = talloc_zero(c, struct pipe_np_smb_state);
	if (s == NULL) {
		c->status = NT_STATUS_NO_MEMORY;
		goto failed;
	}

	c->state = COMPOSITE_STATE_IN_PROGRESS;
	c->private_data = s;
	c->event_ctx = io->pipe->conn->event_ctx;

	s->io  = *io;
	conn   = &s->conn;

	conn->in.dest_host              = s->io.binding->host;
	conn->in.port                   = 0;
	conn->in.called_name            = strupper_talloc(tmp_ctx, s->io.binding->host);
	conn->in.service                = "IPC$";
	conn->in.service_type           = NULL;
	conn->in.fallback_to_anonymous  = False;
	conn->in.workgroup              = lp_workgroup();

	if (s->io.binding->flags & DCERPC_SCHANNEL) {
		struct cli_credentials *anon_creds
			= cli_credentials_init(tmp_ctx);
		if (composite_nomem(anon_creds, c)) return NULL;

		cli_credentials_set_anonymous(anon_creds);
		cli_credentials_guess(anon_creds);

		s->conn.in.credentials = anon_creds;

	} else {
		s->conn.in.credentials = s->io.creds;
	}

	conn_req = smb_composite_connect_send(conn, s->io.pipe->conn, s->io.pipe->conn->event_ctx);

	composite_continue(c, conn_req, continue_smb_connect, c);
	
	return c;

failed:
	composite_trigger_error(c);
	return NULL;
}


NTSTATUS dcerpc_pipe_connect_ncacn_np_smb_recv(struct composite_context *c)
{
	NTSTATUS status = composite_wait(c);

	talloc_free(c);
	return status;
}


NTSTATUS dcerpc_pipe_connect_ncacn_np_smb(TALLOC_CTX *tmp_ctx,
					  struct dcerpc_pipe_connect *io)
{
	struct composite_context *c;
	c = dcerpc_pipe_connect_ncacn_np_smb_send(tmp_ctx, io);
	return dcerpc_pipe_connect_ncacn_np_smb_recv(c);
}
