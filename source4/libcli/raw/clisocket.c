/*
   Unix SMB/CIFS implementation.

   SMB client socket context management functions

   Copyright (C) Andrew Tridgell 1994-2005
   Copyright (C) James Myers 2003 <myersjj@samba.org>

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
#include "system/network.h"
#include "../lib/async_req/async_sock.h"
#include "../lib/util/tevent_ntstatus.h"
#include "lib/events/events.h"
#include "libcli/raw/libcliraw.h"
#include "libcli/composite/composite.h"
#include "lib/socket/socket.h"
#include "libcli/resolve/resolve.h"
#include "param/param.h"
#include "libcli/raw/raw_proto.h"
#include "../libcli/smb/read_smb.h"
#include "lib/util/util_net.h"
#include "../source3/libsmb/smbsock_connect.h"

struct sock_connect_state {
	struct composite_context *ctx;
	struct loadparm_context *lp_ctx;
	const char *host_name;
	struct nbt_name nbt_host_name;
	struct sockaddr_storage _destaddr;
	struct sockaddr_storage *destaddrs;
	size_t num_destaddrs;
	struct smbcli_options options;
	const char *socket_options;
	struct smbcli_socket *result;
	struct nbt_name calling;
	struct nbt_name called;
};

static void smbcli_sock_connect_resolved(struct composite_context *ctx);
static bool smbcli_sock_connect_submit(struct sock_connect_state *state);
static void smbcli_sock_connect_recv_conn(struct tevent_req *subreq);

struct composite_context *smbcli_sock_connect_send(TALLOC_CTX *mem_ctx,
						   const char *host_addr,
						   const struct smbcli_options *options,
						   const char *host_name,
						   struct loadparm_context *lp_ctx,
						   struct resolve_context *resolve_ctx,
						   struct tevent_context *event_ctx,
						   const char *socket_options,
						   struct nbt_name *calling,
						   struct nbt_name *called)
{
	struct composite_context *result, *ctx;
	struct sock_connect_state *state;
	NTSTATUS status;
	bool ok;

	result = talloc_zero(mem_ctx, struct composite_context);
	if (result == NULL) goto failed;
	result->state = COMPOSITE_STATE_IN_PROGRESS;

	result->event_ctx = event_ctx;
	if (result->event_ctx == NULL) goto failed;

	state = talloc_zero(result, struct sock_connect_state);
	if (state == NULL) goto failed;
	state->ctx = result;
	state->lp_ctx = lp_ctx;
	result->private_data = state;

	state->host_name = talloc_strdup(state, host_name);
	if (state->host_name == NULL) goto failed;

	state->options = *options;
	state->socket_options = talloc_reference(state, socket_options);

	if (!host_addr) {
		host_addr = host_name;
	}

	make_nbt_name_server(&state->nbt_host_name, host_name);

	status = nbt_name_dup(state, calling, &state->calling);
	if (!NT_STATUS_IS_OK(status)) {
		goto failed;
	}
	status = nbt_name_dup(state, called, &state->called);
	if (!NT_STATUS_IS_OK(status)) {
		goto failed;
	}

	if (is_ipaddress(host_addr)) {
		ok = interpret_string_addr(&state->_destaddr,
					   host_addr,
					   AI_NUMERICHOST|AI_PASSIVE);
		if (!ok) {
			goto failed;
		}
		state->destaddrs = &state->_destaddr;
		state->num_destaddrs = 1;
	}

	if (state->num_destaddrs == 0) {
		ctx = resolve_name_send(resolve_ctx,
					state,
					&state->nbt_host_name,
					event_ctx);
		if (ctx == NULL) {
			goto failed;
		}
		ctx->async.fn = smbcli_sock_connect_resolved;
		ctx->async.private_data = state;
		return result;
	}

	ok = smbcli_sock_connect_submit(state);
	if (!ok) {
		goto failed;
	}
	return result;

failed:
	talloc_free(result);
	return NULL;
}

static int smbcli_socket_destructor(struct smbcli_socket *sock)
{
	if (sock->sockfd != -1) {
		close(sock->sockfd);
		sock->sockfd = -1;
	}

	return 0;
}

static void smbcli_sock_connect_resolved(struct composite_context *ctx)
{
	struct sock_connect_state *state =
		talloc_get_type(ctx->async.private_data,
				struct sock_connect_state);
	const char **addrs = NULL;
	size_t n;

	state->ctx->status = resolve_name_multiple_recv(ctx, state, &addrs);
	if (!composite_is_ok(state->ctx)) return;

	for (n = 0; addrs[n] != NULL; n++) { /* count */ }

	state->destaddrs = talloc_zero_array(state, struct sockaddr_storage, n);
	if (composite_nomem(state->destaddrs, state->ctx)) return;

	for (n = 0; addrs[n] != NULL; n++) {
		bool ok;

		ok = interpret_string_addr(&state->destaddrs[n],
					   addrs[n],
					   AI_NUMERICHOST|AI_PASSIVE);
		if (!ok) {
			composite_error(state->ctx,
					NT_STATUS_INVALID_NETWORK_RESPONSE);
			return;
		}
	}
	state->num_destaddrs = n;
	smbcli_sock_connect_submit(state);
}

static bool smbcli_sock_connect_submit(struct sock_connect_state *state)
{
	struct tevent_req *subreq = NULL;
	const char **called_names = NULL;
	int *called_types = NULL;
	const char **calling_names = NULL;
	int *calling_types = NULL;
	size_t ai;

	called_names = talloc_array(state, const char *, state->num_destaddrs);
	if (composite_nomem(called_names, state->ctx)) {
		return false;
	}
	called_types = talloc_array(state, int, state->num_destaddrs);
	if (composite_nomem(called_types, state->ctx)) {
		return false;
	}
	calling_names = talloc_array(state, const char *, state->num_destaddrs);
	if (composite_nomem(calling_names, state->ctx)) {
		return false;
	}
	calling_types = talloc_array(state, int, state->num_destaddrs);
	if (composite_nomem(calling_types, state->ctx)) {
		return false;
	}
	for (ai = 0; ai < state->num_destaddrs; ai++) {
		called_names[ai] = state->called.name;
		called_types[ai] = state->called.type;
		calling_names[ai] = state->calling.name;
		calling_types[ai] = state->calling.type;
	}

	subreq = smbsock_any_connect_send(state,
					  state->ctx->event_ctx,
					  state->lp_ctx,
					  state->destaddrs,
					  called_names,
					  called_types,
					  calling_names,
					  calling_types,
					  state->num_destaddrs,
					  &state->options.transports);
	if (composite_nomem(subreq, state->ctx)) {
		return false;
	}
	tevent_req_set_callback(subreq,
				smbcli_sock_connect_recv_conn,
				state);
	return true;
}

static void smbcli_sock_connect_recv_conn(struct tevent_req *subreq)
{
	struct sock_connect_state *state =
		tevent_req_callback_data(subreq,
		struct sock_connect_state);
	int sockfd = -1;

	state->ctx->status = smbsock_any_connect_recv(subreq,
						      &sockfd,
						      NULL,
						      NULL);
	if (!composite_is_ok(state->ctx)) return;

	set_socket_options(sockfd, state->socket_options);

	state->result = talloc_zero(state, struct smbcli_socket);
	if (composite_nomem(state->result, state->ctx)) {
		close(sockfd);
		return;
	}

	state->result->sockfd = sockfd;
	state->result->hostname = talloc_steal(state->result, state->host_name);

	talloc_set_destructor(state->result, smbcli_socket_destructor);

	state->result->event.ctx = state->ctx->event_ctx;
	if (composite_nomem(state->result->event.ctx, state->ctx)) return;

	composite_done(state->ctx);
}

/*
  finish a smbcli_sock_connect_send() operation
*/
NTSTATUS smbcli_sock_connect_recv(struct composite_context *c,
				  TALLOC_CTX *mem_ctx,
				  struct smbcli_socket **result)
{
	NTSTATUS status = composite_wait(c);
	if (NT_STATUS_IS_OK(status)) {
		struct sock_connect_state *state =
			talloc_get_type(c->private_data,
					struct sock_connect_state);
		*result = talloc_steal(mem_ctx, state->result);
	}
	talloc_free(c);
	return status;
}

/*
  connect a smbcli_socket context to an IP/port pair
  if port is 0 then choose the ports listed in smb.conf (normally 445 then 139)

  sync version of the function
*/
NTSTATUS smbcli_sock_connect(TALLOC_CTX *mem_ctx,
			     const char *host_addr,
			     const struct smbcli_options *options,
			     const char *host_name,
			     struct loadparm_context *lp_ctx,
			     struct resolve_context *resolve_ctx,
			     struct tevent_context *event_ctx,
			     const char *socket_options,
			     struct nbt_name *calling,
			     struct nbt_name *called,
			     struct smbcli_socket **result)
{
	struct composite_context *c =
		smbcli_sock_connect_send(mem_ctx, host_addr, options,
					 host_name, lp_ctx, resolve_ctx,
					 event_ctx, socket_options,
					 calling, called);
	return smbcli_sock_connect_recv(c, mem_ctx, result);
}
