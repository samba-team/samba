/* 
   Unix SMB/CIFS implementation.

   dcerpc over SMB transport

   Copyright (C) Tim Potter 2003
   Copyright (C) Andrew Tridgell 2003
   
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
#include <tevent.h>
#include "lib/tsocket/tsocket.h"
#include "libcli/smb/smb_constants.h"
#include "libcli/smb/smbXcli_base.h"
#include "libcli/smb/tstream_smbXcli_np.h"
#include "libcli/raw/libcliraw.h"
#include "libcli/smb2/smb2.h"
#include "librpc/rpc/dcerpc.h"
#include "librpc/rpc/dcerpc_proto.h"
#include "libcli/composite/composite.h"

/* transport private information used by SMB pipe transport */
struct smb_private {
	DATA_BLOB session_key;

	/*
	 * these are needed to open a secondary connection
	 */
	struct smbXcli_conn *conn;
	struct smbXcli_session *session;
	struct smbXcli_tcon *tcon;
	uint32_t timeout_msec;
};

/*
  fetch the user session key 
*/
static NTSTATUS smb_session_key(struct dcecli_connection *c, DATA_BLOB *session_key)
{
	struct smb_private *smb = talloc_get_type_abort(
		c->transport.private_data, struct smb_private);

	if (smb == NULL) return NT_STATUS_CONNECTION_DISCONNECTED;

	if (smb->session_key.length == 0) {
		return NT_STATUS_NO_USER_SESSION_KEY;
	}

	*session_key = smb->session_key;
	return NT_STATUS_OK;
}

struct dcerpc_pipe_open_smb_state {
	struct dcecli_connection *c;
	struct composite_context *ctx;

	const char *fname;

	struct smb_private *smb;
};

static void dcerpc_pipe_open_smb_done(struct tevent_req *subreq);

struct composite_context *dcerpc_pipe_open_smb_send(struct dcecli_connection *c,
						struct smbXcli_conn *conn,
						struct smbXcli_session *session,
						struct smbXcli_tcon *tcon,
						uint32_t timeout_msec,
						const char *pipe_name)
{
	struct composite_context *ctx;
	struct dcerpc_pipe_open_smb_state *state;
	uint16_t pid = 0;
	struct tevent_req *subreq;

	ctx = composite_create(c, c->event_ctx);
	if (ctx == NULL) return NULL;

	state = talloc(ctx, struct dcerpc_pipe_open_smb_state);
	if (composite_nomem(state, ctx)) return ctx;
	ctx->private_data = state;

	state->c = c;
	state->ctx = ctx;

	if ((strncasecmp(pipe_name, "/pipe/", 6) == 0) || 
	    (strncasecmp(pipe_name, "\\pipe\\", 6) == 0)) {
		pipe_name += 6;
	}
	if ((strncasecmp(pipe_name, "/", 1) == 0) ||
	    (strncasecmp(pipe_name, "\\", 1) == 0)) {
		pipe_name += 1;
	}
	state->fname = talloc_strdup(state, pipe_name);
	if (composite_nomem(state->fname, ctx)) return ctx;

	state->smb = talloc_zero(state, struct smb_private);
	if (composite_nomem(state->smb, ctx)) return ctx;

	state->smb->conn = conn;
	state->smb->session = session;
	state->smb->tcon = tcon;
	state->smb->timeout_msec = timeout_msec;

	state->c->server_name = strupper_talloc(state->c,
		smbXcli_conn_remote_name(conn));
	if (composite_nomem(state->c->server_name, ctx)) return ctx;

	ctx->status = smbXcli_session_application_key(session,
						      state->smb,
						      &state->smb->session_key);
	if (NT_STATUS_EQUAL(ctx->status, NT_STATUS_NO_USER_SESSION_KEY)) {
		state->smb->session_key = data_blob_null;
		ctx->status = NT_STATUS_OK;
	}
	if (!composite_is_ok(ctx)) return ctx;

	subreq = tstream_smbXcli_np_open_send(state, c->event_ctx,
					      conn, session, tcon, pid,
					      timeout_msec, state->fname);
	if (composite_nomem(subreq, ctx)) return ctx;
	tevent_req_set_callback(subreq, dcerpc_pipe_open_smb_done, state);

	return ctx;
}

static void dcerpc_pipe_open_smb_done(struct tevent_req *subreq)
{
	struct dcerpc_pipe_open_smb_state *state =
		tevent_req_callback_data(subreq,
		struct dcerpc_pipe_open_smb_state);
	struct composite_context *ctx = state->ctx;
	struct dcecli_connection *c = state->c;

	ctx->status = tstream_smbXcli_np_open_recv(subreq,
						   state->smb,
						   &state->c->transport.stream);
	TALLOC_FREE(subreq);
	if (!composite_is_ok(ctx)) return;

	state->c->transport.write_queue =
		tevent_queue_create(state->c, "dcerpc_smb write queue");
	if (composite_nomem(state->c->transport.write_queue, ctx)) return;

	/*
	  fill in the transport methods
	*/
	c->transport.transport       = NCACN_NP;
	c->transport.private_data    = NULL;

	/*
	 * Windows uses 4280 for ncacn_np,
	 * so we also use it, this is what our
	 * tstream_smbXcli_np code relies on.
	 */
	c->srv_max_xmit_frag = 4280;
	c->srv_max_recv_frag = 4280;

	/* Over-ride the default session key with the SMB session key */
	c->security_state.session_key = smb_session_key;

	c->transport.private_data = talloc_move(c, &state->smb);

	composite_done(ctx);
}

NTSTATUS dcerpc_pipe_open_smb_recv(struct composite_context *c)
{
	NTSTATUS status = composite_wait(c);
	talloc_free(c);
	return status;
}

_PUBLIC_ NTSTATUS dcerpc_pipe_open_smb(struct dcerpc_pipe *p,
			      struct smbcli_tree *t,
			      const char *pipe_name)
{
	struct smbXcli_conn *conn;
	struct smbXcli_session *session;
	struct smbXcli_tcon *tcon;
	struct composite_context *ctx;

	conn = t->session->transport->conn;
	session = t->session->smbXcli;
	tcon = t->smbXcli;
	smb1cli_tcon_set_id(tcon, t->tid);

	/* if we don't have a binding on this pipe yet, then create one */
	if (p->binding == NULL) {
		struct dcerpc_binding *b;
		NTSTATUS status;
		const char *r = smbXcli_conn_remote_name(conn);
		char *str;
		SMB_ASSERT(r != NULL);
		str = talloc_asprintf(p, "ncacn_np:%s", r);
		if (str == NULL) {
			return NT_STATUS_NO_MEMORY;
		}
		status = dcerpc_parse_binding(p, str, &b);
		talloc_free(str);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}
		p->binding = b;
	}

	ctx = dcerpc_pipe_open_smb_send(p->conn,
					conn, session, tcon,
					DCERPC_REQUEST_TIMEOUT * 1000,
					pipe_name);
	if (ctx == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	return dcerpc_pipe_open_smb_recv(ctx);
}

_PUBLIC_ NTSTATUS dcerpc_pipe_open_smb2(struct dcerpc_pipe *p,
			      struct smb2_tree *t,
			      const char *pipe_name)
{
	struct smbXcli_conn *conn;
	struct smbXcli_session *session;
	struct smbXcli_tcon *tcon;
	struct composite_context *ctx;

	conn = t->session->transport->conn;
	session = t->session->smbXcli;
	tcon = t->smbXcli;

	/* if we don't have a binding on this pipe yet, then create one */
	if (p->binding == NULL) {
		struct dcerpc_binding *b;
		NTSTATUS status;
		const char *r = smbXcli_conn_remote_name(conn);
		char *str;
		SMB_ASSERT(r != NULL);
		str = talloc_asprintf(p, "ncacn_np:%s", r);
		if (str == NULL) {
			return NT_STATUS_NO_MEMORY;
		}
		status = dcerpc_parse_binding(p, str, &b);
		talloc_free(str);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}
		p->binding = b;
	}

	ctx = dcerpc_pipe_open_smb_send(p->conn,
					conn, session, tcon,
					DCERPC_REQUEST_TIMEOUT * 1000,
					pipe_name);
	if (ctx == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	return dcerpc_pipe_open_smb_recv(ctx);
}

struct composite_context *dcerpc_secondary_smb_send(struct dcecli_connection *c1,
						    struct dcecli_connection *c2,
						    const char *pipe_name)
{
	struct smb_private *smb;

	if (c1->transport.transport != NCACN_NP) return NULL;

	smb = talloc_get_type(c1->transport.private_data, struct smb_private);
	if (!smb) return NULL;

	return dcerpc_pipe_open_smb_send(c2,
					 smb->conn,
					 smb->session,
					 smb->tcon,
					 smb->timeout_msec,
					 pipe_name);
}

NTSTATUS dcerpc_secondary_smb_recv(struct composite_context *c)
{
	return dcerpc_pipe_open_smb_recv(c);
}
