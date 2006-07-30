/* 
   Unix SMB/CIFS implementation.

   SMB2 composite connection setup

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
#include "libcli/raw/libcliraw.h"
#include "libcli/smb2/smb2.h"
#include "libcli/smb2/smb2_calls.h"
#include "libcli/composite/composite.h"
#include "libcli/resolve/resolve.h"

struct smb2_connect_state {
	struct cli_credentials *credentials;
	const char *host;
	const char *share;
	struct smb2_negprot negprot;
	struct smb2_tree_connect tcon;
	struct smb2_session *session;
	struct smb2_tree *tree;
};

/*
  continue after tcon reply
*/
static void continue_tcon(struct smb2_request *req)
{
	struct composite_context *c = talloc_get_type(req->async.private, 
						      struct composite_context);
	struct smb2_connect_state *state = talloc_get_type(c->private_data, 
							   struct smb2_connect_state);

	c->status = smb2_tree_connect_recv(req, &state->tcon);
	if (!composite_is_ok(c)) return;
	
	state->tree->tid = state->tcon.out.tid;

	composite_done(c);
}

/*
  continue after a session setup
*/
static void continue_session(struct composite_context *creq)
{
	struct composite_context *c = talloc_get_type(creq->async.private_data, 
						      struct composite_context);
	struct smb2_connect_state *state = talloc_get_type(c->private_data, 
							   struct smb2_connect_state);
	struct smb2_request *req;

	c->status = smb2_session_setup_spnego_recv(creq);
	if (!composite_is_ok(c)) return;

	state->tree = smb2_tree_init(state->session, state, True);
	if (composite_nomem(state->tree, c)) return;

	state->tcon.in.unknown1 = 0x09;
	state->tcon.in.path     = talloc_asprintf(state, "\\\\%s\\%s", 
						  state->host, state->share);
	if (composite_nomem(state->tcon.in.path, c)) return;
	
	req = smb2_tree_connect_send(state->tree, &state->tcon);
	if (composite_nomem(req, c)) return;

	req->async.fn = continue_tcon;
	req->async.private = c;	
}

/*
  continue after negprot reply
*/
static void continue_negprot(struct smb2_request *req)
{
	struct composite_context *c = talloc_get_type(req->async.private, 
						      struct composite_context);
	struct smb2_connect_state *state = talloc_get_type(c->private_data, 
							   struct smb2_connect_state);
	struct smb2_transport *transport = req->transport;
	struct composite_context *creq;

	c->status = smb2_negprot_recv(req, c, &state->negprot);
	if (!composite_is_ok(c)) return;

	state->session = smb2_session_init(transport, state, True);
	if (composite_nomem(state->session, c)) return;

	creq = smb2_session_setup_spnego_send(state->session, state->credentials);

	composite_continue(c, creq, continue_session, c);
}

/*
  continue after a socket connect completes
*/
static void continue_socket(struct composite_context *creq)
{
	struct composite_context *c = talloc_get_type(creq->async.private_data, 
						      struct composite_context);
	struct smb2_connect_state *state = talloc_get_type(c->private_data, 
							   struct smb2_connect_state);
	struct smbcli_socket *sock;
	struct smb2_transport *transport;
	struct smb2_request *req;

	c->status = smbcli_sock_connect_recv(creq, state, &sock);
	if (!composite_is_ok(c)) return;

	transport = smb2_transport_init(sock, state);
	if (composite_nomem(transport, c)) return;

	ZERO_STRUCT(state->negprot);
	state->negprot.in.unknown1 = 0x0001;

	req = smb2_negprot_send(transport, &state->negprot);
	if (composite_nomem(req, c)) return;

	req->async.fn = continue_negprot;
	req->async.private = c;
}


/*
  continue after a resolve finishes
*/
static void continue_resolve(struct composite_context *creq)
{
	struct composite_context *c = talloc_get_type(creq->async.private_data, 
						      struct composite_context);
	struct smb2_connect_state *state = talloc_get_type(c->private_data, 
							   struct smb2_connect_state);
	const char *addr;
	
	c->status = resolve_name_recv(creq, state, &addr);
	if (!composite_is_ok(c)) return;

	creq = smbcli_sock_connect_send(state, addr, 445, state->host, c->event_ctx);

	composite_continue(c, creq, continue_socket, c);
}

/*
  a composite function that does a full negprot/sesssetup/tcon, returning
  a connected smb2_tree
 */
struct composite_context *smb2_connect_send(TALLOC_CTX *mem_ctx,
					    const char *host,
					    const char *share,
					    struct cli_credentials *credentials,
					    struct event_context *ev)
{
	struct composite_context *c;
	struct smb2_connect_state *state;
	struct nbt_name name;
	struct composite_context *creq;

	c = composite_create(mem_ctx, ev);
	if (c == NULL) return NULL;

	state = talloc(c, struct smb2_connect_state);
	if (composite_nomem(state, c)) return c;
	c->private_data = state;

	state->credentials = credentials;
	state->host = talloc_strdup(c, host);
	if (composite_nomem(state->host, c)) return c;
	state->share = talloc_strdup(c, share);
	if (composite_nomem(state->share, c)) return c;

	ZERO_STRUCT(name);
	name.name = host;

	creq = resolve_name_send(&name, c->event_ctx, lp_name_resolve_order());
	composite_continue(c, creq, continue_resolve, c);
	return c;
}

/*
  receive a connect reply
*/
NTSTATUS smb2_connect_recv(struct composite_context *c, TALLOC_CTX *mem_ctx,
			   struct smb2_tree **tree)
{
	NTSTATUS status;
	struct smb2_connect_state *state = talloc_get_type(c->private_data, 
							   struct smb2_connect_state);
	status = composite_wait(c);
	if (NT_STATUS_IS_OK(status)) {
		*tree = talloc_steal(mem_ctx, state->tree);
	}
	talloc_free(c);
	return status;
}

/*
  sync version of smb2_connect
*/
NTSTATUS smb2_connect(TALLOC_CTX *mem_ctx, 
		      const char *host, const char *share,
		      struct cli_credentials *credentials,
		      struct smb2_tree **tree,
		      struct event_context *ev)
{
	struct composite_context *c = smb2_connect_send(mem_ctx, host, share, 
							credentials, ev);
	return smb2_connect_recv(c, mem_ctx, tree);
}
