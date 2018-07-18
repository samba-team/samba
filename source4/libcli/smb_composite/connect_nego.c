/*
   Unix SMB/CIFS implementation.

   Copyright (C) Stefan Metzmacher 2018

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
#include "lib/util/tevent_ntstatus.h"
#include "libcli/composite/composite.h"
#include "libcli/raw/libcliraw.h"
#include "libcli/raw/raw_proto.h"
#include "libcli/smb_composite/smb_composite.h"
#include "lib/socket/socket.h"
#include "libcli/resolve/resolve.h"
#include "librpc/gen_ndr/ndr_nbt.h"
#include "libcli/smb/smbXcli_base.h"

struct smb_connect_nego_state {
	struct tevent_context *ev;
	struct resolve_context *resolve_ctx;
	const char *socket_options;
	struct smbcli_options options;
	const char *dest_hostname;
	const char *dest_address;
	const char **dest_ports;
	const char *target_hostname;
	struct nbt_name calling, called;
	struct smbXcli_conn *conn;
};

static void smb_connect_nego_connect_done(struct composite_context *creq);
static void smb_connect_nego_nego_done(struct tevent_req *subreq);

struct tevent_req *smb_connect_nego_send(TALLOC_CTX *mem_ctx,
					 struct tevent_context *ev,
					 struct resolve_context *resolve_ctx,
					 const struct smbcli_options *options,
					 const char *socket_options,
					 const char *dest_hostname,
					 const char *dest_address, /* optional */
					 const char **dest_ports,
					 const char *target_hostname,
					 const char *called_name,
					 const char *calling_name)
{
	struct tevent_req *req = NULL;
	struct smb_connect_nego_state *state = NULL;
	struct composite_context *creq = NULL;

	req = tevent_req_create(mem_ctx, &state,
				struct smb_connect_nego_state);
	if (req == NULL) {
		return NULL;
	}
	state->ev = ev;
	state->resolve_ctx= resolve_ctx;
	state->options = *options;
	state->socket_options = socket_options;
	state->dest_hostname = dest_hostname;
	state->dest_address = dest_address;
	state->dest_ports = dest_ports;
	state->target_hostname = target_hostname;

	make_nbt_name_client(&state->calling, calling_name);

	nbt_choose_called_name(state, &state->called,
			       called_name, NBT_NAME_SERVER);
	if (tevent_req_nomem(state->called.name, req)) {
		return tevent_req_post(req, ev);
	}

	creq = smbcli_sock_connect_send(state,
					state->dest_address,
					state->dest_ports,
					state->dest_hostname,
					state->resolve_ctx,
					state->ev,
					state->socket_options,
					&state->calling,
					&state->called);
	if (tevent_req_nomem(creq, req)) {
		return tevent_req_post(req, ev);
	}
	creq->async.private_data = req;
	creq->async.fn = smb_connect_nego_connect_done;

	return req;
}

static void smb_connect_nego_connect_done(struct composite_context *creq)
{
	struct tevent_req *req =
		talloc_get_type_abort(creq->async.private_data,
		struct tevent_req);
	struct smb_connect_nego_state *state =
		tevent_req_data(req,
		struct smb_connect_nego_state);
	struct tevent_req *subreq = NULL;
	struct smbcli_socket *sock = NULL;
	uint32_t smb1_capabilities;
	uint32_t timeout_msec = state->options.request_timeout * 1000;
	NTSTATUS status;

	status = smbcli_sock_connect_recv(creq, state, &sock);
	creq = NULL;
	if (tevent_req_nterror(req, status)) {
		return;
	}

	TALLOC_FREE(sock->event.fde);
	TALLOC_FREE(sock->event.te);

	smb1_capabilities = 0;
	smb1_capabilities |= CAP_LARGE_FILES;
	smb1_capabilities |= CAP_NT_SMBS | CAP_RPC_REMOTE_APIS;
	smb1_capabilities |= CAP_LOCK_AND_READ | CAP_NT_FIND;
	smb1_capabilities |= CAP_DFS | CAP_W2K_SMBS;
	smb1_capabilities |= CAP_LARGE_READX|CAP_LARGE_WRITEX;
	smb1_capabilities |= CAP_LWIO;

	if (state->options.ntstatus_support) {
		smb1_capabilities |= CAP_STATUS32;
	}

	if (state->options.unicode) {
		smb1_capabilities |= CAP_UNICODE;
	}

	if (state->options.use_spnego) {
		smb1_capabilities |= CAP_EXTENDED_SECURITY;
	}

	if (state->options.use_level2_oplocks) {
		smb1_capabilities |= CAP_LEVEL_II_OPLOCKS;
	}

	state->conn = smbXcli_conn_create(state,
					  sock->sock->fd,
					  state->target_hostname,
					  state->options.signing,
					  smb1_capabilities,
					  &state->options.client_guid,
					  state->options.smb2_capabilities);
	if (tevent_req_nomem(state->conn, req)) {
		return;
	}
	sock->sock->fd = -1;
	TALLOC_FREE(sock);

	subreq = smbXcli_negprot_send(state,
				      state->ev,
				      state->conn,
				      timeout_msec,
				      state->options.min_protocol,
				      state->options.max_protocol,
				      state->options.max_credits);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, smb_connect_nego_nego_done, req);
}

static void smb_connect_nego_nego_done(struct tevent_req *subreq)
{
	struct tevent_req *req =
		tevent_req_callback_data(subreq,
		struct tevent_req);
	NTSTATUS status;

	status = smbXcli_negprot_recv(subreq);
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		return;
	}

	tevent_req_done(req);
}

NTSTATUS smb_connect_nego_recv(struct tevent_req *req,
			       TALLOC_CTX *mem_ctx,
			       struct smbXcli_conn **_conn)
{
	struct smb_connect_nego_state *state =
		tevent_req_data(req,
		struct smb_connect_nego_state);
	NTSTATUS status;

	if (tevent_req_is_nterror(req, &status)) {
		tevent_req_received(req);
		return status;
	}

	*_conn = talloc_move(mem_ctx, &state->conn);
	tevent_req_received(req);
	return NT_STATUS_OK;
}
