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
#include "librpc/rpc/dcerpc.h"
#include "librpc/rpc/dcerpc_proto.h"
#include "libcli/composite/composite.h"

/* transport private information used by SMB pipe transport */
struct smb_private {
	DATA_BLOB session_key;
	const char *server_name;

	struct tstream_context *stream;
	struct tevent_queue *write_queue;
	struct tevent_req *read_subreq;
	uint32_t pending_reads;

	/*
	 * these are needed to open a secondary connection
	 */
	struct smbXcli_conn *conn;
	struct smbXcli_session *session;
	struct smbXcli_tcon *tcon;
	uint32_t timeout_msec;
};


/*
  tell the dcerpc layer that the transport is dead
*/
static void pipe_dead(struct dcecli_connection *c, NTSTATUS status)
{
	struct smb_private *smb = talloc_get_type_abort(
		c->transport.private_data, struct smb_private);

	if (smb->stream == NULL) {
		return;
	}

	tevent_queue_stop(smb->write_queue);
	TALLOC_FREE(smb->read_subreq);
	TALLOC_FREE(smb->stream);

	if (NT_STATUS_EQUAL(NT_STATUS_UNSUCCESSFUL, status)) {
		status = NT_STATUS_UNEXPECTED_NETWORK_ERROR;
	}

	if (NT_STATUS_EQUAL(NT_STATUS_OK, status)) {
		status = NT_STATUS_END_OF_FILE;
	}

	if (c->transport.recv_data) {
		c->transport.recv_data(c, NULL, status);
	}
}

struct smb_send_read_state {
	struct dcecli_connection *p;
};

static int smb_send_read_state_destructor(struct smb_send_read_state *state)
{
	struct dcecli_connection *p = state->p;
	struct smb_private *sock = talloc_get_type_abort(
		p->transport.private_data, struct smb_private);

	sock->read_subreq = NULL;

	return 0;
}

static void smb_send_read_done(struct tevent_req *subreq);

static NTSTATUS smb_send_read(struct dcecli_connection *p)
{
	struct smb_private *sock = talloc_get_type_abort(
		p->transport.private_data, struct smb_private);
	struct smb_send_read_state *state;

	if (sock->read_subreq != NULL) {
		sock->pending_reads++;
		return NT_STATUS_OK;
	}

	state = talloc_zero(sock, struct smb_send_read_state);
	if (state == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	state->p = p;

	talloc_set_destructor(state, smb_send_read_state_destructor);

	sock->read_subreq = dcerpc_read_ncacn_packet_send(state,
							  p->event_ctx,
							  sock->stream);
	if (sock->read_subreq == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	tevent_req_set_callback(sock->read_subreq, smb_send_read_done, state);

	return NT_STATUS_OK;
}

static void smb_send_read_done(struct tevent_req *subreq)
{
	struct smb_send_read_state *state =
		tevent_req_callback_data(subreq,
					 struct smb_send_read_state);
	struct dcecli_connection *p = state->p;
	struct smb_private *sock = talloc_get_type_abort(
		p->transport.private_data, struct smb_private);
	NTSTATUS status;
	struct ncacn_packet *pkt;
	DATA_BLOB blob;

	status = dcerpc_read_ncacn_packet_recv(subreq, state,
					       &pkt, &blob);
	TALLOC_FREE(subreq);
	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(state);
		pipe_dead(p, status);
		return;
	}

	/*
	 * here we steal into thet connection context,
	 * but p->transport.recv_data() will steal or free it again
	 */
	talloc_steal(p, blob.data);
	TALLOC_FREE(state);

	if (sock->pending_reads > 0) {
		sock->pending_reads--;

		status = smb_send_read(p);
		if (!NT_STATUS_IS_OK(status)) {
			pipe_dead(p, status);
			return;
		}
	}

	if (p->transport.recv_data) {
		p->transport.recv_data(p, &blob, NT_STATUS_OK);
	}
}

/*
   send an initial pdu in a multi-pdu sequence
*/

struct smb_send_request_state {
	struct dcecli_connection *p;
	DATA_BLOB blob;
	struct iovec iov;
};

static int smb_send_request_state_destructor(struct smb_send_request_state *state)
{
	struct dcecli_connection *p = state->p;
	struct smb_private *sock = talloc_get_type_abort(
		p->transport.private_data, struct smb_private);

	sock->read_subreq = NULL;

	return 0;
}

static void smb_send_request_wait_done(struct tevent_req *subreq);
static void smb_send_request_done(struct tevent_req *subreq);

static NTSTATUS smb_send_request(struct dcecli_connection *p, DATA_BLOB *data,
				  bool trigger_read)
{
	struct smb_private *sock = talloc_get_type_abort(
		p->transport.private_data, struct smb_private);
	struct smb_send_request_state *state;
	struct tevent_req *subreq;
	bool use_trans = trigger_read;

	if (sock->stream == NULL) {
		return NT_STATUS_CONNECTION_DISCONNECTED;
	}

	state = talloc_zero(sock, struct smb_send_request_state);
	if (state == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	state->p = p;

	state->blob = data_blob_talloc(state, data->data, data->length);
	if (state->blob.data == NULL) {
		TALLOC_FREE(state);
		return NT_STATUS_NO_MEMORY;
	}
	state->iov.iov_base = (void *)state->blob.data;
	state->iov.iov_len = state->blob.length;

	if (sock->read_subreq != NULL) {
		use_trans = false;
	}

	if (use_trans) {
		/*
		 * we need to block reads until our write is
		 * the next in the write queue.
		 */
		sock->read_subreq = tevent_queue_wait_send(state, p->event_ctx,
							   sock->write_queue);
		if (sock->read_subreq == NULL) {
			TALLOC_FREE(state);
			return NT_STATUS_NO_MEMORY;
		}
		tevent_req_set_callback(sock->read_subreq,
					smb_send_request_wait_done,
					state);

		talloc_set_destructor(state, smb_send_request_state_destructor);

		trigger_read = false;
	}

	subreq = tstream_writev_queue_send(state, p->event_ctx,
					   sock->stream,
					   sock->write_queue,
					   &state->iov, 1);
	if (subreq == NULL) {
		TALLOC_FREE(state);
		return NT_STATUS_NO_MEMORY;
	}
	tevent_req_set_callback(subreq, smb_send_request_done, state);

	if (trigger_read) {
		smb_send_read(p);
	}

	return NT_STATUS_OK;
}

static void smb_send_request_wait_done(struct tevent_req *subreq)
{
	struct smb_send_request_state *state =
		tevent_req_callback_data(subreq,
		struct smb_send_request_state);
	struct dcecli_connection *p = state->p;
	struct smb_private *sock = talloc_get_type_abort(
		p->transport.private_data, struct smb_private);
	NTSTATUS status;
	bool ok;

	sock->read_subreq = NULL;
	talloc_set_destructor(state, NULL);

	ok = tevent_queue_wait_recv(subreq);
	if (!ok) {
		TALLOC_FREE(state);
		pipe_dead(p, NT_STATUS_NO_MEMORY);
		return;
	}

	if (tevent_queue_length(sock->write_queue) <= 2) {
		status = tstream_smbXcli_np_use_trans(sock->stream);
		if (!NT_STATUS_IS_OK(status)) {
			TALLOC_FREE(state);
			pipe_dead(p, status);
			return;
		}
	}

	/* we free subreq after tstream_smbXcli_np_use_trans */
	TALLOC_FREE(subreq);

	smb_send_read(p);
}

static void smb_send_request_done(struct tevent_req *subreq)
{
	struct smb_send_request_state *state =
		tevent_req_callback_data(subreq,
		struct smb_send_request_state);
	int ret;
	int error;

	ret = tstream_writev_queue_recv(subreq, &error);
	TALLOC_FREE(subreq);
	if (ret == -1) {
		struct dcecli_connection *p = state->p;
		NTSTATUS status = map_nt_error_from_unix_common(error);

		TALLOC_FREE(state);
		pipe_dead(p, status);
		return;
	}

	TALLOC_FREE(state);
}

/* 
   shutdown SMB pipe connection
*/
struct smb_shutdown_pipe_state {
	struct dcecli_connection *c;
	NTSTATUS status;
};

static void smb_shutdown_pipe_done(struct tevent_req *subreq);

static NTSTATUS smb_shutdown_pipe(struct dcecli_connection *c, NTSTATUS status)
{
	struct smb_private *smb = talloc_get_type_abort(
		c->transport.private_data, struct smb_private);
	struct smb_shutdown_pipe_state *state;
	struct tevent_req *subreq;

	if (smb->stream == NULL) {
		return NT_STATUS_OK;
	}

	state = talloc_zero(smb, struct smb_shutdown_pipe_state);
	if (state == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	state->c = c;
	state->status = status;

	subreq = tstream_disconnect_send(state, c->event_ctx, smb->stream);
	if (subreq == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	tevent_req_set_callback(subreq, smb_shutdown_pipe_done, state);

	return status;
}

static void smb_shutdown_pipe_done(struct tevent_req *subreq)
{
	struct smb_shutdown_pipe_state *state =
		tevent_req_callback_data(subreq, struct smb_shutdown_pipe_state);
	struct dcecli_connection *c = state->c;
	NTSTATUS status = state->status;
	int error;

	/*
	 * here we ignore the return values...
	 */
	tstream_disconnect_recv(subreq, &error);
	TALLOC_FREE(subreq);

	TALLOC_FREE(state);

	pipe_dead(c, status);
}

/*
  return SMB server name (called name)
*/
static const char *smb_peer_name(struct dcecli_connection *c)
{
	struct smb_private *smb = talloc_get_type_abort(
		c->transport.private_data, struct smb_private);
	if (smb == NULL) return "";
	return smb->server_name;
}

/*
  return remote name we make the actual connection (good for kerberos) 
*/
static const char *smb_target_hostname(struct dcecli_connection *c)
{
	struct smb_private *smb = talloc_get_type_abort(
		c->transport.private_data, struct smb_private);
	if (smb == NULL) return "";
	return smb->server_name;
}

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

	state->smb->server_name = strupper_talloc(state->smb,
		smbXcli_conn_remote_name(conn));
	if (composite_nomem(state->smb->server_name, ctx)) return ctx;

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
						   &state->smb->stream);
	TALLOC_FREE(subreq);
	if (!composite_is_ok(ctx)) return;

	state->smb->write_queue = tevent_queue_create(state->smb,
					"dcerpc_smb write queue");
	if (composite_nomem(state->smb->write_queue, ctx)) return;

	/*
	  fill in the transport methods
	*/
	c->transport.transport       = NCACN_NP;
	c->transport.private_data    = NULL;
	c->transport.shutdown_pipe   = smb_shutdown_pipe;
	c->transport.peer_name       = smb_peer_name;
	c->transport.target_hostname = smb_target_hostname;

	c->transport.send_request    = smb_send_request;
	c->transport.send_read       = smb_send_read;
	c->transport.recv_data       = NULL;

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
	uint32_t timeout_msec;
	struct composite_context *ctx;

	conn = t->session->transport->conn;
	session = t->session->smbXcli;
	tcon = t->smbXcli;
	smb1cli_tcon_set_id(tcon, t->tid);
	timeout_msec = t->session->transport->options.request_timeout * 1000;

	/* if we don't have a binding on this pipe yet, then create one */
	if (p->binding == NULL) {
		NTSTATUS status;
		const char *r = smbXcli_conn_remote_name(conn);
		char *str;
		SMB_ASSERT(r != NULL);
		str = talloc_asprintf(p, "ncacn_np:%s", r);
		if (str == NULL) {
			return NT_STATUS_NO_MEMORY;
		}
		status = dcerpc_parse_binding(p, str,
					      &p->binding);
		talloc_free(str);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}
	}

	ctx = dcerpc_pipe_open_smb_send(p->conn,
					conn, session,
					tcon, timeout_msec,
					pipe_name);
	if (ctx == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	return dcerpc_pipe_open_smb_recv(ctx);
}

struct composite_context *dcerpc_secondary_smb_send(struct dcecli_connection *c1,
						    struct dcerpc_pipe *p2,
						    const char *pipe_name)
{
	struct smb_private *smb;

	if (c1->transport.transport != NCACN_NP) return NULL;

	smb = talloc_get_type(c1->transport.private_data, struct smb_private);
	if (!smb) return NULL;

	return dcerpc_pipe_open_smb_send(p2->conn,
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
