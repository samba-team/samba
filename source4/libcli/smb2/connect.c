/* 
   Unix SMB/CIFS implementation.

   SMB2 composite connection setup

   Copyright (C) Andrew Tridgell 2005
   
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
#include <tevent.h>
#include "lib/util/tevent_ntstatus.h"
#include "libcli/raw/libcliraw.h"
#include "libcli/raw/raw_proto.h"
#include "libcli/smb2/smb2.h"
#include "libcli/smb2/smb2_calls.h"
#include "libcli/composite/composite.h"
#include "libcli/resolve/resolve.h"
#include "param/param.h"
#include "auth/credentials/credentials.h"
#include "../libcli/smb/smbXcli_base.h"

struct smb2_connect_state {
	struct tevent_context *ev;
	struct cli_credentials *credentials;
	uint64_t previous_session_id;
	struct resolve_context *resolve_ctx;
	const char *host;
	const char *share;
	const char *unc;
	const char **ports;
	const char *socket_options;
	struct nbt_name calling, called;
	struct gensec_settings *gensec_settings;
	struct smbcli_options options;
	struct smb2_transport *transport;
	struct smb2_session *session;
	struct smb2_tree *tree;
};

static void smb2_connect_socket_done(struct composite_context *creq);

/*
  a composite function that does a full negprot/sesssetup/tcon, returning
  a connected smb2_tree
 */
struct tevent_req *smb2_connect_send(TALLOC_CTX *mem_ctx,
				     struct tevent_context *ev,
				     const char *host,
				     const char **ports,
				     const char *share,
				     struct resolve_context *resolve_ctx,
				     struct cli_credentials *credentials,
				     uint64_t previous_session_id,
				     const struct smbcli_options *options,
				     const char *socket_options,
				     struct gensec_settings *gensec_settings)
{
	struct tevent_req *req;
	struct smb2_connect_state *state;
	struct composite_context *creq;
	static const char *default_ports[] = { "445", "139", NULL };

	req = tevent_req_create(mem_ctx, &state,
				struct smb2_connect_state);
	if (req == NULL) {
		return NULL;
	}

	state->ev = ev;
	state->credentials = credentials;
	state->previous_session_id = previous_session_id;
	state->options = *options;
	state->host = host;
	state->ports = ports;
	state->share = share;
	state->resolve_ctx = resolve_ctx;
	state->socket_options = socket_options;
	state->gensec_settings = gensec_settings;

	if (state->ports == NULL) {
		state->ports = default_ports;
	}

	make_nbt_name_client(&state->calling,
			     cli_credentials_get_workstation(credentials));

	nbt_choose_called_name(state, &state->called,
			       host, NBT_NAME_SERVER);

	state->unc = talloc_asprintf(state, "\\\\%s\\%s",
				    state->host, state->share);
	if (tevent_req_nomem(state->unc, req)) {
		return tevent_req_post(req, ev);
	}

	creq = smbcli_sock_connect_send(state, NULL, state->ports,
					state->host, state->resolve_ctx,
					state->ev, state->socket_options,
					&state->calling,
					&state->called);
	if (tevent_req_nomem(creq, req)) {
		return tevent_req_post(req, ev);
	}
	creq->async.fn = smb2_connect_socket_done;
	creq->async.private_data = req;

	return req;
}

static void smb2_connect_negprot_done(struct tevent_req *subreq);

static void smb2_connect_socket_done(struct composite_context *creq)
{
	struct tevent_req *req =
		talloc_get_type_abort(creq->async.private_data,
		struct tevent_req);
	struct smb2_connect_state *state =
		tevent_req_data(req,
		struct smb2_connect_state);
	struct smbcli_socket *sock;
	struct tevent_req *subreq;
	NTSTATUS status;
	uint32_t timeout_msec;

	status = smbcli_sock_connect_recv(creq, state, &sock);
	if (tevent_req_nterror(req, status)) {
		return;
	}

	state->transport = smb2_transport_init(sock, state, &state->options);
	if (tevent_req_nomem(state->transport, req)) {
		return;
	}

	timeout_msec = state->transport->options.request_timeout * 1000;

	subreq = smbXcli_negprot_send(state, state->ev,
				      state->transport->conn, timeout_msec,
				      PROTOCOL_SMB2_02,
				      state->transport->options.max_protocol);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, smb2_connect_negprot_done, req);
}

static void smb2_connect_session_done(struct tevent_req *subreq);

static void smb2_connect_negprot_done(struct tevent_req *subreq)
{
	struct tevent_req *req =
		tevent_req_callback_data(subreq,
		struct tevent_req);
	struct smb2_connect_state *state =
		tevent_req_data(req,
		struct smb2_connect_state);
	struct smb2_transport *transport = state->transport;
	NTSTATUS status;

	status = smbXcli_negprot_recv(subreq);
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		return;
	}

	/* This is a hack... */
	smb2cli_conn_set_max_credits(transport->conn, 30);

	state->session = smb2_session_init(transport, state->gensec_settings, state);
	if (tevent_req_nomem(state->session, req)) {
		return;
	}

	subreq = smb2_session_setup_spnego_send(state, state->ev,
						state->session,
						state->credentials,
						state->previous_session_id);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, smb2_connect_session_done, req);
}

static void smb2_connect_tcon_done(struct tevent_req *subreq);

static void smb2_connect_session_done(struct tevent_req *subreq)
{
	struct tevent_req *req =
		tevent_req_callback_data(subreq,
		struct tevent_req);
	struct smb2_connect_state *state =
		tevent_req_data(req,
		struct smb2_connect_state);
	NTSTATUS status;
	uint32_t timeout_msec;

	status = smb2_session_setup_spnego_recv(subreq);
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		return;
	}

	state->tree = smb2_tree_init(state->session, state, true);
	if (tevent_req_nomem(state->tree, req)) {
		return;
	}

	timeout_msec = state->transport->options.request_timeout * 1000;

	subreq = smb2cli_tcon_send(state, state->ev,
				   state->transport->conn,
				   timeout_msec,
				   state->session->smbXcli,
				   state->tree->smbXcli,
				   0, /* flags */
				   state->unc);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, smb2_connect_tcon_done, req);
}

static void smb2_connect_tcon_done(struct tevent_req *subreq)
{
	struct tevent_req *req =
		tevent_req_callback_data(subreq,
		struct tevent_req);
	NTSTATUS status;

	status = smb2cli_tcon_recv(subreq);
	if (tevent_req_nterror(req, status)) {
		return;
	}

	tevent_req_done(req);
}

NTSTATUS smb2_connect_recv(struct tevent_req *req,
			   TALLOC_CTX *mem_ctx,
			   struct smb2_tree **tree)
{
	struct smb2_connect_state *state =
		tevent_req_data(req,
		struct smb2_connect_state);
	NTSTATUS status;

	if (tevent_req_is_nterror(req, &status)) {
		tevent_req_received(req);
		return status;
	}

	*tree = talloc_move(mem_ctx, &state->tree);

	tevent_req_received(req);
	return NT_STATUS_OK;
}

/*
  sync version of smb2_connect
*/
NTSTATUS smb2_connect_ext(TALLOC_CTX *mem_ctx,
			  const char *host,
			  const char **ports,
			  const char *share,
			  struct resolve_context *resolve_ctx,
			  struct cli_credentials *credentials,
			  uint64_t previous_session_id,
			  struct smb2_tree **tree,
			  struct tevent_context *ev,
			  const struct smbcli_options *options,
			  const char *socket_options,
			  struct gensec_settings *gensec_settings)
{
	struct tevent_req *subreq;
	NTSTATUS status;
	bool ok;
	TALLOC_CTX *frame = talloc_stackframe();

	if (frame == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	subreq = smb2_connect_send(frame,
				   ev,
				   host,
				   ports,
				   share,
				   resolve_ctx,
				   credentials,
				   previous_session_id,
				   options,
				   socket_options,
				   gensec_settings);
	if (subreq == NULL) {
		TALLOC_FREE(frame);
		return NT_STATUS_NO_MEMORY;
	}

	ok = tevent_req_poll(subreq, ev);
	if (!ok) {
		status = map_nt_error_from_unix_common(errno);
		TALLOC_FREE(frame);
		return status;
	}

	status = smb2_connect_recv(subreq, mem_ctx, tree);
	TALLOC_FREE(subreq);
	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(frame);
		return status;
	}

	TALLOC_FREE(frame);
	return NT_STATUS_OK;
}

NTSTATUS smb2_connect(TALLOC_CTX *mem_ctx,
		      const char *host,
		      const char **ports,
		      const char *share,
		      struct resolve_context *resolve_ctx,
		      struct cli_credentials *credentials,
		      struct smb2_tree **tree,
		      struct tevent_context *ev,
		      struct smbcli_options *options,
		      const char *socket_options,
		      struct gensec_settings *gensec_settings)
{
	NTSTATUS status;

	status = smb2_connect_ext(mem_ctx, host, ports, share, resolve_ctx,
				  credentials,
				  0, /* previous_session_id */
				  tree, ev, options, socket_options,
				  gensec_settings);

	return status;
}
