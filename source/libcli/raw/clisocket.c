/* 
   Unix SMB/CIFS implementation.

   SMB client socket context management functions

   Copyright (C) Andrew Tridgell 1994-2005
   Copyright (C) James Myers 2003 <myersjj@samba.org>
   
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
#include "lib/events/events.h"
#include "libcli/raw/libcliraw.h"
#include "libcli/composite/composite.h"
#include "lib/socket/socket.h"
#include "libcli/resolve/resolve.h"

struct sock_connect_state {
	struct composite_context *ctx;
	const char *host_name;
	int num_ports;
	uint16_t *ports;
	struct smbcli_socket *result;
};

/*
  connect a smbcli_socket context to an IP/port pair
  if port is 0 then choose 445 then 139
*/

static void smbcli_sock_connect_recv_conn(struct composite_context *ctx);

struct composite_context *smbcli_sock_connect_send(TALLOC_CTX *mem_ctx,
						   const char *host_addr,
						   int port,
						   const char *host_name,
						   struct event_context *event_ctx)
{
	struct composite_context *result, *ctx;
	struct sock_connect_state *state;

	result = talloc_zero(mem_ctx, struct composite_context);
	if (result == NULL) goto failed;
	result->state = COMPOSITE_STATE_IN_PROGRESS;

	if (event_ctx != NULL) {
		result->event_ctx = talloc_reference(result, event_ctx);
	} else {
		result->event_ctx = event_context_init(result);
	}

	if (result->event_ctx == NULL) goto failed;

	state = talloc(result, struct sock_connect_state);
	if (state == NULL) goto failed;
	state->ctx = result;
	result->private_data = state;

	state->host_name = talloc_strdup(state, host_name);
	if (state->host_name == NULL) goto failed;

	if (port == 0) {
		const char **ports = lp_smb_ports();
		int i;

		for (i=0;ports[i];i++) /* noop */ ;
		if (i == 0) {
			DEBUG(3, ("no smb ports defined\n"));
			goto failed;
		}
		state->num_ports = i;
		state->ports = talloc_array(state, uint16_t, i);
		if (state->ports == NULL) goto failed;
		for (i=0;ports[i];i++) {
			state->ports[i] = atoi(ports[i]);
		}
	} else {
		state->ports = talloc_array(state, uint16_t, 1);
		if (state->ports == NULL) goto failed;
		state->num_ports = 1;
		state->ports[0] = port;
	}

	ctx = socket_connect_multi_send(state, host_addr,
					state->num_ports, state->ports,
					state->ctx->event_ctx);
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

	state->ctx->status = socket_connect_multi_recv(ctx, state, &sock,
						       &port);
	if (!composite_is_ok(state->ctx)) return;

	state->ctx->status =
		socket_set_option(sock, lp_socket_options(), NULL);
	if (!composite_is_ok(state->ctx)) return;


	state->result = talloc_zero(state, struct smbcli_socket);
	if (composite_nomem(state->result, state->ctx)) return;

	state->result->sock = talloc_steal(state->result, sock);
	state->result->port = port;
	state->result->hostname = talloc_steal(sock, state->host_name);

	state->result->event.ctx =
		talloc_reference(state->result, state->ctx->event_ctx);
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
			     const char *host_addr, int port,
			     const char *host_name,
			     struct event_context *event_ctx,
			     struct smbcli_socket **result)
{
	struct composite_context *c =
		smbcli_sock_connect_send(mem_ctx, host_addr, port, host_name,
					 event_ctx);
	return smbcli_sock_connect_recv(c, mem_ctx, result);
}


/****************************************************************************
 mark the socket as dead
****************************************************************************/
void smbcli_sock_dead(struct smbcli_socket *sock)
{
	talloc_free(sock->event.fde);
	sock->event.fde = NULL;
	talloc_free(sock->sock);
	sock->sock = NULL;
}

/****************************************************************************
 Set socket options on a open connection.
****************************************************************************/
void smbcli_sock_set_options(struct smbcli_socket *sock, const char *options)
{
	socket_set_option(sock->sock, options, NULL);
}

/****************************************************************************
resolve a hostname and connect 
****************************************************************************/
struct smbcli_socket *smbcli_sock_connect_byname(const char *host, int port,
						 TALLOC_CTX *mem_ctx,
						 struct event_context *event_ctx)
{
	int name_type = NBT_NAME_SERVER;
	const char *address;
	NTSTATUS status;
	struct nbt_name nbt_name;
	char *name, *p;
	TALLOC_CTX *tmp_ctx = talloc_new(mem_ctx);
	struct smbcli_socket *result;

	if (tmp_ctx == NULL) {
		DEBUG(0, ("talloc_new failed\n"));
		return NULL;
	}

	name = talloc_strdup(tmp_ctx, host);
	if (name == NULL) {
		DEBUG(0, ("talloc_strdup failed\n"));
		talloc_free(tmp_ctx);
		return NULL;
	}

	if (event_ctx == NULL) {
		event_ctx = event_context_init(mem_ctx);
	}

	if (event_ctx == NULL) {
		DEBUG(0, ("event_context_init failed\n"));
		talloc_free(tmp_ctx);
		return NULL;
	}

	/* allow hostnames of the form NAME#xx and do a netbios lookup */
	if ((p = strchr(name, '#'))) {
		name_type = strtol(p+1, NULL, 16);
		*p = 0;
	}

	make_nbt_name(&nbt_name, host, name_type);
	
	status = resolve_name(&nbt_name, tmp_ctx, &address, event_ctx);
	if (!NT_STATUS_IS_OK(status)) {
		talloc_free(tmp_ctx);
		return NULL;
	}

	status = smbcli_sock_connect(mem_ctx, address, port, name, event_ctx,
				     &result);

	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(9, ("smbcli_sock_connect failed: %s\n",
			  nt_errstr(status)));
		talloc_free(tmp_ctx);
		return NULL;
	}

	talloc_free(tmp_ctx);

	return result;
}
