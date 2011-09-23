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

struct smbcli_transport_connect_state {
	struct tevent_context *ev;
	struct socket_context *sock;
	uint8_t *request;
	struct iovec iov;
	uint8_t *response;
};

static void smbcli_transport_connect_writev_done(struct tevent_req *subreq);
static void smbcli_transport_connect_read_smb_done(struct tevent_req *subreq);

static struct tevent_req *smbcli_transport_connect_send(TALLOC_CTX *mem_ctx,
						 struct tevent_context *ev,
						 struct socket_context *sock,
						 uint16_t port,
						 uint32_t timeout_msec,
						 struct nbt_name *calling,
						 struct nbt_name *called)
{
	struct tevent_req *req;
	struct smbcli_transport_connect_state *state;
	struct tevent_req *subreq;
	DATA_BLOB calling_blob, called_blob;
	uint8_t *p;
	NTSTATUS status;

	req = tevent_req_create(mem_ctx, &state,
				struct smbcli_transport_connect_state);
	if (req == NULL) {
		return NULL;
	}
	state->ev = ev;
	state->sock = sock;

	if (port != 139) {
		tevent_req_done(req);
		return tevent_req_post(req, ev);
	}

	status = nbt_name_to_blob(state, &calling_blob, calling);
	if (tevent_req_nterror(req, status)) {
		return tevent_req_post(req, ev);
	}

	status = nbt_name_to_blob(state, &called_blob, called);
	if (tevent_req_nterror(req, status)) {
		return tevent_req_post(req, ev);
	}

	state->request = talloc_array(state, uint8_t,
				      NBT_HDR_SIZE +
				      called_blob.length +
				      calling_blob.length);
	if (tevent_req_nomem(state->request, req)) {
		return tevent_req_post(req, ev);
	}

	/* put in the destination name */
	p = state->request + NBT_HDR_SIZE;
	memcpy(p, called_blob.data, called_blob.length);
	p += called_blob.length;

	memcpy(p, calling_blob.data, calling_blob.length);
	p += calling_blob.length;

	_smb_setlen_nbt(state->request,
			PTR_DIFF(p, state->request) - NBT_HDR_SIZE);
	SCVAL(state->request, 0, NBSSrequest);

	state->iov.iov_len = talloc_array_length(state->request);
	state->iov.iov_base = (void *)state->request;

	subreq = writev_send(state, ev, NULL,
			     sock->fd,
			     true, /* err_on_readability */
			     &state->iov, 1);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq,
				smbcli_transport_connect_writev_done,
				req);

	if (timeout_msec > 0) {
		struct timeval endtime;

		endtime = timeval_current_ofs_msec(timeout_msec);
		if (!tevent_req_set_endtime(req, ev, endtime)) {
			return tevent_req_post(req, ev);
		}
	}

	return req;
}

static void smbcli_transport_connect_writev_done(struct tevent_req *subreq)
{
	struct tevent_req *req =
		tevent_req_callback_data(subreq,
		struct tevent_req);
	struct smbcli_transport_connect_state *state =
		tevent_req_data(req,
		struct smbcli_transport_connect_state);
	ssize_t ret;
	int err;

	ret = writev_recv(subreq, &err);
	TALLOC_FREE(subreq);
	if (ret == -1) {
		NTSTATUS status = map_nt_error_from_unix_common(err);

		close(state->sock->fd);
		state->sock->fd = -1;

		tevent_req_nterror(req, status);
		return;
	}

	subreq = read_smb_send(state, state->ev,
			       state->sock->fd);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq,
				smbcli_transport_connect_read_smb_done,
				req);
}

static void smbcli_transport_connect_read_smb_done(struct tevent_req *subreq)
{
	struct tevent_req *req =
		tevent_req_callback_data(subreq,
		struct tevent_req);
	struct smbcli_transport_connect_state *state =
		tevent_req_data(req,
		struct smbcli_transport_connect_state);
	ssize_t ret;
	int err;
	NTSTATUS status;
	uint8_t error;

	ret = read_smb_recv(subreq, state,
			    &state->response, &err);
	if (ret == -1) {
		status = map_nt_error_from_unix_common(err);

		close(state->sock->fd);
		state->sock->fd = -1;

		tevent_req_nterror(req, status);
		return;
	}

	if (ret < 4) {
		close(state->sock->fd);
		state->sock->fd = -1;

		tevent_req_nterror(req, NT_STATUS_INVALID_NETWORK_RESPONSE);
		return;
	}

	switch (CVAL(state->response, 0)) {
	case NBSSpositive:
		tevent_req_done(req);
		return;

	case NBSSnegative:
		if (ret < 5) {
			close(state->sock->fd);
			state->sock->fd = -1;

			tevent_req_nterror(req, NT_STATUS_INVALID_NETWORK_RESPONSE);
			return;
		}

		error = CVAL(state->response, 4);
		switch (error) {
		case 0x80:
		case 0x81:
			status = NT_STATUS_REMOTE_NOT_LISTENING;
			break;
		case 0x82:
			status = NT_STATUS_RESOURCE_NAME_NOT_FOUND;
			break;
		case 0x83:
			status = NT_STATUS_REMOTE_RESOURCES;
			break;
		default:
			status = NT_STATUS_INVALID_NETWORK_RESPONSE;
			break;
		}
		break;

	case NBSSretarget:
		DEBUG(1,("Warning: session retarget not supported\n"));
		status = NT_STATUS_NOT_SUPPORTED;
		break;

	default:
		status = NT_STATUS_INVALID_NETWORK_RESPONSE;
		break;
	}

	close(state->sock->fd);
	state->sock->fd = -1;

	tevent_req_nterror(req, status);
}

static NTSTATUS smbcli_transport_connect_recv(struct tevent_req *req)
{
	return tevent_req_simple_recv_ntstatus(req);
}

struct sock_connect_state {
	struct composite_context *ctx;
	const char *host_name;
	int num_ports;
	uint16_t *ports;
	const char *socket_options;
	struct smbcli_socket *result;
	struct socket_connect_multi_ex multi_ex;
	struct nbt_name calling;
	struct nbt_name called;
};

/*
  connect a smbcli_socket context to an IP/port pair
  if port is 0 then choose 445 then 139
*/

static struct tevent_req *smbcli_sock_establish_send(TALLOC_CTX *mem_ctx,
						     struct tevent_context *ev,
						     struct socket_context *sock,
						     struct socket_address *addr,
						     void *private_data)
{
	struct sock_connect_state *state =
		talloc_get_type_abort(private_data,
		struct sock_connect_state);
	uint32_t timeout_msec = 15 * 1000;

	return smbcli_transport_connect_send(state,
					     ev,
					     sock,
					     addr->port,
					     timeout_msec,
					     &state->calling,
					     &state->called);
}

static NTSTATUS smbcli_sock_establish_recv(struct tevent_req *req)
{
	return smbcli_transport_connect_recv(req);
}

static void smbcli_sock_connect_recv_conn(struct composite_context *ctx);

struct composite_context *smbcli_sock_connect_send(TALLOC_CTX *mem_ctx,
						   const char *host_addr,
						   const char **ports,
						   const char *host_name,
						   struct resolve_context *resolve_ctx,
						   struct tevent_context *event_ctx,
						   const char *socket_options,
						   struct nbt_name *calling,
						   struct nbt_name *called)
{
	struct composite_context *result, *ctx;
	struct sock_connect_state *state;
	NTSTATUS status;
	int i;

	result = talloc_zero(mem_ctx, struct composite_context);
	if (result == NULL) goto failed;
	result->state = COMPOSITE_STATE_IN_PROGRESS;

	result->event_ctx = event_ctx;
	if (result->event_ctx == NULL) goto failed;

	state = talloc(result, struct sock_connect_state);
	if (state == NULL) goto failed;
	state->ctx = result;
	result->private_data = state;

	state->host_name = talloc_strdup(state, host_name);
	if (state->host_name == NULL) goto failed;

	state->num_ports = str_list_length(ports);
	state->ports = talloc_array(state, uint16_t, state->num_ports);
	if (state->ports == NULL) goto failed;
	for (i=0;ports[i];i++) {
		state->ports[i] = atoi(ports[i]);
	}
	state->socket_options = talloc_reference(state, socket_options);

	if (!host_addr) {
		host_addr = host_name;
	}

	state->multi_ex.private_data = state;
	state->multi_ex.establish_send = smbcli_sock_establish_send;
	state->multi_ex.establish_recv = smbcli_sock_establish_recv;

	status = nbt_name_dup(state, calling, &state->calling);
	if (!NT_STATUS_IS_OK(status)) {
		goto failed;
	}
	status = nbt_name_dup(state, called, &state->called);
	if (!NT_STATUS_IS_OK(status)) {
		goto failed;
	}

	ctx = socket_connect_multi_ex_send(state, host_addr,
					   state->num_ports, state->ports,
					   resolve_ctx,
					   state->ctx->event_ctx,
					   &state->multi_ex);
	if (ctx == NULL) goto failed;
	ctx->async.fn = smbcli_sock_connect_recv_conn;
	ctx->async.private_data = state;
	return result;

failed:
	talloc_free(result);
	return NULL;
}

static void smbcli_sock_connect_recv_conn(struct composite_context *ctx)
{
	struct sock_connect_state *state =
		talloc_get_type(ctx->async.private_data,
				struct sock_connect_state);
	struct socket_context *sock;
	uint16_t port;

	state->ctx->status = socket_connect_multi_ex_recv(ctx, state, &sock,
							  &port);
	if (!composite_is_ok(state->ctx)) return;

	state->ctx->status =
		socket_set_option(sock, state->socket_options, NULL);
	if (!composite_is_ok(state->ctx)) return;


	state->result = talloc_zero(state, struct smbcli_socket);
	if (composite_nomem(state->result, state->ctx)) return;

	state->result->sock = talloc_steal(state->result, sock);
	state->result->port = port;
	state->result->hostname = talloc_steal(sock, state->host_name);

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
			     const char *host_addr, const char **ports,
			     const char *host_name,
			     struct resolve_context *resolve_ctx,
			     struct tevent_context *event_ctx,
			     const char *socket_options,
			     struct nbt_name *calling,
			     struct nbt_name *called,
			     struct smbcli_socket **result)
{
	struct composite_context *c =
		smbcli_sock_connect_send(mem_ctx, host_addr, ports, host_name,
					 resolve_ctx,
					 event_ctx, socket_options,
					 calling, called);
	return smbcli_sock_connect_recv(c, mem_ctx, result);
}
