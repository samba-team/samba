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

struct smb2_connect_state {
	struct tevent_context *ev;
	struct cli_credentials *credentials;
	struct resolve_context *resolve_ctx;
	const char *host;
	const char *share;
	const char **ports;
	const char *socket_options;
	struct gensec_settings *gensec_settings;
	struct smbcli_options options;
	struct smb2_negprot negprot;
	struct smb2_tree_connect tcon;
	struct smb2_session *session;
	struct smb2_tree *tree;
};

static void smb2_connect_resolve_done(struct composite_context *creq);

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
				     struct smbcli_options *options,
				     const char *socket_options,
				     struct gensec_settings *gensec_settings)
{
	struct tevent_req *req;
	struct smb2_connect_state *state;
	struct nbt_name name;
	struct composite_context *creq;

	req = tevent_req_create(mem_ctx, &state,
				struct smb2_connect_state);
	if (req == NULL) {
		return NULL;
	}

	state->ev = ev;
	state->credentials = credentials;
	state->options = *options;
	state->host = host;
	state->ports = ports;
	state->share = share;
	state->resolve_ctx = resolve_ctx;
	state->socket_options = socket_options;
	state->gensec_settings = gensec_settings;

	ZERO_STRUCT(name);
	name.name = host;

	creq = resolve_name_send(resolve_ctx, state, &name, ev);
	if (tevent_req_nomem(creq, req)) {
		return tevent_req_post(req, ev);
	}
	creq->async.fn = smb2_connect_resolve_done;
	creq->async.private_data = req;
	return req;
}

static void smb2_connect_socket_done(struct composite_context *creq);

static void smb2_connect_resolve_done(struct composite_context *creq)
{
	struct tevent_req *req =
		talloc_get_type_abort(creq->async.private_data,
		struct tevent_req);
	struct smb2_connect_state *state =
		tevent_req_data(req,
		struct smb2_connect_state);
	NTSTATUS status;
	const char *addr;
	const char **ports;
	const char *default_ports[] = { "445", NULL };

	status = resolve_name_recv(creq, state, &addr);
	if (tevent_req_nterror(req, status)) {
		return;
	}

	if (state->ports == NULL) {
		ports = default_ports;
	} else {
		ports = state->ports;
	}

	creq = smbcli_sock_connect_send(state, addr, ports,
					state->host, state->resolve_ctx,
					state->ev, state->socket_options);
	if (tevent_req_nomem(creq, req)) {
		return;
	}
	creq->async.fn = smb2_connect_socket_done;
	creq->async.private_data = req;
}

static void smb2_connect_negprot_done(struct smb2_request *smb2req);

static void smb2_connect_socket_done(struct composite_context *creq)
{
	struct tevent_req *req =
		talloc_get_type_abort(creq->async.private_data,
		struct tevent_req);
	struct smb2_connect_state *state =
		tevent_req_data(req,
		struct smb2_connect_state);
	struct smbcli_socket *sock;
	struct smb2_transport *transport;
	struct smb2_request *smb2req;
	NTSTATUS status;
	uint16_t dialects[3] = {
		SMB2_DIALECT_REVISION_000,
		SMB2_DIALECT_REVISION_202,
		SMB2_DIALECT_REVISION_210
	};

	status = smbcli_sock_connect_recv(creq, state, &sock);
	if (tevent_req_nterror(req, status)) {
		return;
	}

	transport = smb2_transport_init(sock, state, &state->options);
	if (tevent_req_nomem(transport, req)) {
		return;
	}

	ZERO_STRUCT(state->negprot);
	state->negprot.in.dialect_count = ARRAY_SIZE(dialects);
	switch (transport->options.signing) {
	case SMB_SIGNING_OFF:
		state->negprot.in.security_mode = 0;
		break;
	case SMB_SIGNING_SUPPORTED:
	case SMB_SIGNING_AUTO:
		state->negprot.in.security_mode = SMB2_NEGOTIATE_SIGNING_ENABLED;
		break;
	case SMB_SIGNING_REQUIRED:
		state->negprot.in.security_mode =
			SMB2_NEGOTIATE_SIGNING_ENABLED | SMB2_NEGOTIATE_SIGNING_REQUIRED;
		break;
	}
	state->negprot.in.capabilities  = 0;
	unix_to_nt_time(&state->negprot.in.start_time, time(NULL));
	state->negprot.in.dialects = dialects;

	smb2req = smb2_negprot_send(transport, &state->negprot);
	if (tevent_req_nomem(smb2req, req)) {
		return;
	}
	smb2req->async.fn = smb2_connect_negprot_done;
	smb2req->async.private_data = req;
}

static void smb2_connect_session_done(struct tevent_req *subreq);

static void smb2_connect_negprot_done(struct smb2_request *smb2req)
{
	struct tevent_req *req =
		talloc_get_type_abort(smb2req->async.private_data,
		struct tevent_req);
	struct smb2_connect_state *state =
		tevent_req_data(req,
		struct smb2_connect_state);
	struct smb2_transport *transport = smb2req->transport;
	struct tevent_req *subreq;
	NTSTATUS status;

	status = smb2_negprot_recv(smb2req, state, &state->negprot);
	if (tevent_req_nterror(req, status)) {
		return;
	}

	transport->negotiate.secblob = state->negprot.out.secblob;
	talloc_steal(transport, transport->negotiate.secblob.data);
	transport->negotiate.system_time = state->negprot.out.system_time;
	transport->negotiate.server_start_time = state->negprot.out.server_start_time;
	transport->negotiate.security_mode = state->negprot.out.security_mode;
	transport->negotiate.dialect_revision = state->negprot.out.dialect_revision;

	switch (transport->options.signing) {
	case SMB_SIGNING_OFF:
		if (transport->negotiate.security_mode & SMB2_NEGOTIATE_SIGNING_REQUIRED) {
			tevent_req_nterror(req, NT_STATUS_ACCESS_DENIED);
			return;
		}
		transport->signing_required = false;
		break;
	case SMB_SIGNING_SUPPORTED:
		if (transport->negotiate.security_mode & SMB2_NEGOTIATE_SIGNING_REQUIRED) {
			transport->signing_required = true;
		} else {
			transport->signing_required = false;
		}
		break;
	case SMB_SIGNING_AUTO:
		if (transport->negotiate.security_mode & SMB2_NEGOTIATE_SIGNING_ENABLED) {
			transport->signing_required = true;
		} else {
			transport->signing_required = false;
		}
		break;
	case SMB_SIGNING_REQUIRED:
		if (transport->negotiate.security_mode & SMB2_NEGOTIATE_SIGNING_ENABLED) {
			transport->signing_required = true;
		} else {
			tevent_req_nterror(req, NT_STATUS_ACCESS_DENIED);
			return;
		}
		break;
	}

	state->session = smb2_session_init(transport, state->gensec_settings, state, true);
	if (tevent_req_nomem(state->session, req)) {
		return;
	}

	subreq = smb2_session_setup_spnego_send(state, state->ev,
						state->session,
						state->credentials);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, smb2_connect_session_done, req);
}

static void smb2_connect_tcon_done(struct smb2_request *smb2req);

static void smb2_connect_session_done(struct tevent_req *subreq)
{
	struct tevent_req *req =
		tevent_req_callback_data(subreq,
		struct tevent_req);
	struct smb2_connect_state *state =
		tevent_req_data(req,
		struct smb2_connect_state);
	struct smb2_request *smb2req;
	NTSTATUS status;

	status = smb2_session_setup_spnego_recv(subreq);
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		return;
	}

	state->tree = smb2_tree_init(state->session, state, true);
	if (tevent_req_nomem(state->tree, req)) {
		return;
	}

	state->tcon.in.reserved = 0;
	state->tcon.in.path     = talloc_asprintf(state, "\\\\%s\\%s",
						  state->host, state->share);
	if (tevent_req_nomem(state->tcon.in.path, req)) {
		return;
	}

	smb2req = smb2_tree_connect_send(state->tree, &state->tcon);
	if (tevent_req_nomem(smb2req, req)) {
		return;
	}
	smb2req->async.fn = smb2_connect_tcon_done;
	smb2req->async.private_data = req;
}

static void smb2_connect_tcon_done(struct smb2_request *smb2req)
{
	struct tevent_req *req =
		talloc_get_type_abort(smb2req->async.private_data,
		struct tevent_req);
	struct smb2_connect_state *state =
		tevent_req_data(req,
		struct smb2_connect_state);
	NTSTATUS status;

	status = smb2_tree_connect_recv(smb2req, &state->tcon);
	if (tevent_req_nterror(req, status)) {
		return;
	}

	state->tree->tid = state->tcon.out.tid;

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
				   options,
				   socket_options,
				   gensec_settings);
	if (subreq == NULL) {
		TALLOC_FREE(frame);
		return NT_STATUS_NO_MEMORY;
	}

	ok = tevent_req_poll(subreq, ev);
	if (!ok) {
		status = map_nt_error_from_unix(errno);
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
